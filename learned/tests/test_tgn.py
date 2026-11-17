"""
Tests for the learned service (ASTRA phase 10): the dataset schema, the simulator and its attack families, no leakage between training and testing, determinism, the network learning,
the evaluation gate, and what the service is able to send to the platform.

    docker build -f learned/Dockerfile -t astra-learned . && docker run --rm --entrypoint python astra-learned -m unittest learned.tests.test_tgn

The sizes are small so the whole file runs in about a minute; the numbers in a real evaluation (service evaluate) use the full simulator.
"""
import copy
import json
import os
import tempfile
import time
import unittest

from learned.tgn import evaluate as E
from learned.tgn import model as M
from learned.tgn import schema
from learned.tgn import service
from learned.tgn import simulate as S

SMALL = dict(train_minutes=40, val_minutes=15, test_minutes=15, episodes=6)


class SchemaTests(unittest.TestCase):
    def test_only_the_schema_fields_ever_enter_and_a_tampered_dataset_is_refused(self):
        raw = {"t": 5, "agent": "a", "kind": "tool_call", "target": "x", "dept": "D", "tier": 2, "prompt": "never read", "args": {"secret": 1}}
        self.assertEqual(set(schema.clean(raw)), set(schema.FIELDS))
        with self.assertRaises(ValueError):
            schema.clean({"t": 1, "agent": "a"})
        ds = schema.dataset([raw, {"t": 1, "agent": "a", "kind": "heartbeat", "target": "", "dept": "D", "tier": 1}])
        self.assertEqual(len(ds["events"]), 1, "heartbeats are not events")
        schema.check(ds)
        bad = copy.deepcopy(ds)
        bad["events"][0]["target"] = "other"
        with self.assertRaises(ValueError):
            schema.check(bad)
        bad = copy.deepcopy(ds)
        bad["schema"] = "tgn-events-v0"
        with self.assertRaises(ValueError):
            schema.check(bad)


class SimulatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ds = S.make_dataset(seed=3, **SMALL)

    def test_the_same_seed_gives_the_same_traffic_and_another_seed_does_not(self):
        again = S.make_dataset(seed=3, **SMALL)
        self.assertEqual(again["hash"], self.ds["hash"])
        self.assertEqual(again["attacks"]["metronome"]["victims"], self.ds["attacks"]["metronome"]["victims"])
        self.assertNotEqual(S.make_dataset(seed=4, **SMALL)["hash"], self.ds["hash"])

    def test_train_validation_and_test_are_disjoint_in_time_and_attacks_never_cross_families(self):
        ds = self.ds
        (a0, a1), (b0, b1), (c0, c1) = ds["spans"]["train"], ds["spans"]["val"], ds["spans"]["test"]
        self.assertTrue(all(a0 <= e["t"] < a1 for e in ds["train"]) and all(b0 <= e["t"] < b1 for e in ds["val"]) and all(c0 <= e["t"] < c1 for e in ds["test"]))
        self.assertTrue(set(S.DEV_FAMILIES).isdisjoint(S.TEST_FAMILIES))
        for fam, info in ds["attacks"].items():
            lo, hi = (b0, b1) if fam in S.DEV_FAMILIES else (c0, c1)
            self.assertEqual(info["role"], "dev" if fam in S.DEV_FAMILIES else "test")
            self.assertTrue(info["victims"], fam)
            self.assertTrue(all(lo <= w * S.WINDOW < hi for _, w in info["victims"]), f"{fam} attacks stay inside their own span")

    def test_an_attack_changes_only_its_victim_windows(self):
        normal = sorted(self.ds["train"] + self.ds["val"] + self.ds["test"], key=lambda e: (e["t"], e["agent"]))
        for fam, info in self.ds["attacks"].items():
            victims = {tuple(v) for v in info["victims"]}
            key = lambda e: (e["agent"], S.window_of(e["t"]))                                    # noqa: E731
            before = [e for e in normal if key(e) not in victims]
            after = [e for e in info["events"] if key(e) not in victims]
            self.assertEqual(before, after, f"{fam} touched a window it should not have")
            self.assertNotEqual([e for e in normal if key(e) in victims], [e for e in info["events"] if key(e) in victims])

    def test_no_attack_vocabulary_is_in_the_training_data(self):
        vocab = M.Vocab.of(self.ds["train"])
        for novel in ("shell.exec", "external_api", "pastebin"):
            self.assertNotIn(novel, vocab.nodes, "the network is trained on normal traffic only")
        self.assertNotIn("memory_write", vocab.kinds)


class ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ds = S.make_dataset(seed=3, **SMALL)
        cls.vocab = M.Vocab.of(cls.ds["train"])
        cls.model, cls.curve = M.train(cls.ds["train"], cls.vocab, seed=1, epochs=4)

    def test_training_is_deterministic_for_a_seed_and_differs_between_seeds(self):
        again, _ = M.train(self.ds["train"], self.vocab, seed=1, epochs=4)
        self.assertEqual(M.state_dict_checksum(again), M.state_dict_checksum(self.model))
        other, _ = M.train(self.ds["train"], self.vocab, seed=2, epochs=4)
        self.assertNotEqual(M.state_dict_checksum(other), M.state_dict_checksum(self.model))

    def test_it_learns_normal_traffic_and_is_more_surprised_by_what_it_never_saw(self):
        self.assertLess(self.curve[-1], self.curve[0] * 0.8, self.curve)
        val = M.surprises(self.model, self.vocab, sorted(self.ds["train"] + self.ds["val"], key=lambda e: e["t"]))
        n_train = len(self.ds["train"])
        normal_val = sum(val[n_train:]) / len(val[n_train:])
        info = self.ds["attacks"]["novel_target"]
        stream = info["events"]
        sp = M.surprises(self.model, self.vocab, stream)
        hit = [s for s, e in zip(sp, stream) if e["target"] in ("shell.exec", "external_api", "pastebin")]
        self.assertTrue(hit and sum(hit) / len(hit) > normal_val + 2, (sum(hit) / len(hit), normal_val))

    def test_an_unknown_node_or_kind_is_scored_not_crashed_on(self):
        ev = [{"t": 1.0, "agent": "support", "kind": "tool_call", "target": "never-seen-tool", "dept": "D", "tier": 2}, {"t": 2.0, "agent": "ghost", "kind": "new_kind", "target": "support", "dept": "D", "tier": 1}]
        sp = M.surprises(self.model, self.vocab, ev)
        self.assertEqual(len(sp), 2)
        self.assertTrue(all(s > 0 and s == s for s in sp))

    def test_weights_round_trip_through_a_file_with_their_checksum(self):
        with tempfile.TemporaryDirectory() as d:
            r = service.train_and_evaluate(seed=3, epochs=3, out=d, **SMALL)
            model, vocab = service.load(d, r["checksum"])
            self.assertEqual(M.state_dict_checksum(model), r["checksum"])
            with self.assertRaises(RuntimeError):
                service.load(d, "0" * 64)


class EvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = service.train_and_evaluate(seed=3, epochs=4, **SMALL)

    def test_the_metrics_have_everything_the_platform_needs_and_nothing_secret(self):
        m = self.r["metrics"]
        self.assertTrue(m["simulated"])
        self.assertEqual(set(m["tgn"]["tpr"]), set(S.DEV_FAMILIES + S.TEST_FAMILIES))
        self.assertEqual(m["families"], {"dev": list(S.DEV_FAMILIES), "test": list(S.TEST_FAMILIES)})
        self.assertTrue(m["normalisation"] and m["budget_fpr"] == E.BUDGET and m["margin"] == E.MARGIN)
        self.assertEqual(len(self.r["checksum"]), 64)
        json.dumps(self.r)                                                                   # all of it is plain JSON, so it can be sent

    def test_the_threshold_is_spent_on_validation_normal_traffic_at_the_stated_budget(self):
        scores = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9] * 2
        thr = E.threshold_for(scores, 0.05)
        self.assertLessEqual(sum(1 for s in scores if s >= thr) / len(scores), 0.05)
        self.assertGreater(thr, max(scores) - 1e-6 + 0.0 - 1e-6)
        self.assertEqual(E.threshold_for([1.0, 2.0], 0.0), 2.0 + 1e-9)

    def test_dev_families_choose_the_settings_and_the_test_families_are_only_judged_once(self):
        with tempfile.TemporaryDirectory():
            r = service.train_and_evaluate(seed=3, configs=((2, 16), (4, 16)), **SMALL)
        sel = r["metrics"]["selection"]
        self.assertEqual(sel["chosen_on"], "dev families only")
        self.assertTrue(all(set(c) == {"epochs", "d", "dev_detection", "fpr_val_budget"} for c in sel["candidates"]), "only dev numbers are kept for the settings that were not chosen")
        best = max(sel["candidates"], key=lambda c: (c["dev_detection"] or 0, -c["epochs"]))
        self.assertEqual(r["hyper"]["epochs"], best["epochs"])

    def test_the_rule_is_the_one_the_platform_applies(self):
        good = copy.deepcopy(self.r["metrics"])
        good["tgn"]["tpr"] = {f: 0.9 for f in S.DEV_FAMILIES + S.TEST_FAMILIES}
        good["baseline"]["tpr"] = {f: 0.3 for f in S.DEV_FAMILIES + S.TEST_FAMILIES}
        good["tgn"]["macro_test"], good["baseline"]["macro_test"], good["tgn"]["fpr_test"] = 0.9, 0.3, 0.03
        self.assertTrue(E.decide(good)["passed"])
        worse = copy.deepcopy(good)
        worse["tgn"]["macro_test"] = 0.32
        self.assertFalse(E.decide(worse)["passed"])
        leaky = copy.deepcopy(good)
        leaky["families"]["dev"] = ["metronome"]
        self.assertIn("overlap", " ".join(E.decide(leaky)["reasons"]))
        noisy = copy.deepcopy(good)
        noisy["tgn"]["fpr_test"] = 0.3
        self.assertIn("false-positive", " ".join(E.decide(noisy)["reasons"]))
        one = copy.deepcopy(good)
        one["families"]["test"] = ["metronome"]
        self.assertIn("fewer than", " ".join(E.decide(one)["reasons"]))


class ServiceTests(unittest.TestCase):
    def test_what_the_service_posts_for_a_window_is_a_number_never_a_control_or_a_level(self):
        """The platform decides what a flag may be. The service can only say which agent, which window, how many events and what score."""
        ds = S.make_dataset(seed=3, **SMALL)
        with tempfile.TemporaryDirectory() as d:
            r = service.train_and_evaluate(seed=3, epochs=3, out=d, **SMALL)
            now = time.time()
            shift = (int(now // S.WINDOW) - 20) * S.WINDOW - ds["spans"]["test"][0]                 # the simulated test span ends a few windows before now
            events = [dict(e, t=e["t"] + shift) for e in ds["test"]]
            norm = r["metrics"]["normalisation"]
            posts = []

            class Fake:
                def call(self, method, path, body=None):
                    if path.startswith("/api/astra/learned/tgn/active"):
                        return {"id": "m1", "checksum": r["checksum"], "normalisation": norm, "last_window_end": events[0]["t"] // S.WINDOW * S.WINDOW, "window_seconds": 60, "threshold": 3.0}
                    if path.startswith("/api/astra/learned/stream"):
                        return {"events": [dict(e, extra="never read") for e in events], "more": False}
                    posts.append((method, path, body))
                    return {"scored": len(body["windows"]), "flagged": 0}

            original = service.from_env
            service.from_env = lambda: Fake()
            try:
                import argparse
                self.assertEqual(service.cmd_score(argparse.Namespace(out=d)), 0)
            finally:
                service.from_env = original
            self.assertEqual(len(posts), 1)
            method, path, body = posts[0]
            self.assertEqual((method, path), ("POST", "/api/astra/learned/tgn/scores"))
            self.assertEqual(set(body), {"model_id", "windows"})
            self.assertTrue(body["windows"])
            for w in body["windows"]:
                self.assertEqual(set(w), {"agent", "window_start", "events", "score"})
                self.assertEqual(w["window_start"] % S.WINDOW, 0)
                self.assertGreaterEqual(w["events"], 1)

    def test_nothing_is_scored_when_no_model_is_adopted_and_a_missing_key_stops_the_service(self):
        class Fake:
            def call(self, method, path, body=None):
                return None
        original = service.from_env
        service.from_env = lambda: Fake()
        try:
            import argparse
            self.assertEqual(service.cmd_score(argparse.Namespace(out="/nonexistent")), 0)
        finally:
            service.from_env = original
        saved = {k: os.environ.pop(k, None) for k in ("ASTRA_URL", "ASTRA_KEY")}
        try:
            with self.assertRaises(SystemExit):
                service.from_env()
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v


if __name__ == "__main__":
    unittest.main()
