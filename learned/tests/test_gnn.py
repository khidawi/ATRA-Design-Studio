"""
Tests for the graph model of the learned service (ASTRA phase 11): the snapshots, the estate simulator and its permitted-only attacks, no leakage between training and testing, determinism, the
model learning, the two-question gate, and what the service can send.

    docker build -f learned/Dockerfile -t astra-learned . && docker run --rm --entrypoint python astra-learned -m unittest learned.tests.test_gnn

The sizes are small; a real evaluation (python -m learned gnn evaluate) uses the full simulator and takes minutes.
"""
import argparse
import copy
import json
import tempfile
import time
import unittest

from learned.gnn import evaluate as E
from learned.gnn import graph as G
from learned.gnn import model as M
from learned.gnn import service
from learned.gnn import simulate as S

SMALL = dict(train_minutes=30, val_minutes=12, test_minutes=12, episodes=6)


class SimulatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ds = S.make_dataset(seed=5, **SMALL)

    def test_deterministic_and_the_late_agents_have_no_history_before_validation(self):
        self.assertEqual(S.make_dataset(seed=5, **SMALL)["hash"], self.ds["hash"])
        self.assertNotEqual(S.make_dataset(seed=6, **SMALL)["hash"], self.ds["hash"])
        in_train = {e["agent"] for e in self.ds["train"]}
        self.assertTrue(set(S.COLD).isdisjoint(in_train), "an agent that joins late has no training events")
        self.assertTrue(set(S.COLD) <= {e["agent"] for e in self.ds["val"]} | {e["agent"] for e in self.ds["test"]})

    def test_every_attack_event_is_permitted_so_the_reachability_check_sees_nothing(self):
        for fam, info in self.ds["attacks"].items():
            victims = {tuple(v) for v in info["victims"]}
            self.assertTrue(victims, fam)
            added = [e for e in info["events"] if (e["agent"], S.window_of(e["t"])) in victims]
            self.assertTrue(added)
            self.assertEqual(S.violates(added), [], f"{fam} used something the estate does not permit")
        normal = self.ds["train"] + self.ds["val"] + self.ds["test"]
        self.assertEqual(S.violates(normal), [], "normal traffic never leaves the permissions either")

    def test_families_never_cross_spans_and_other_windows_are_untouched(self):
        (b0, b1), (c0, c1) = self.ds["spans"]["val"], self.ds["spans"]["test"]
        normal = sorted(self.ds["train"] + self.ds["val"] + self.ds["test"], key=lambda e: (e["t"], e["agent"]))
        self.assertTrue(set(S.DEV_FAMILIES).isdisjoint(S.TEST_FAMILIES))
        for fam, info in self.ds["attacks"].items():
            lo, hi = (b0, b1) if fam in S.DEV_FAMILIES else (c0, c1)
            victims = {tuple(v) for v in info["victims"]}
            self.assertTrue(all(lo <= w * S.WINDOW < hi for _, w in victims), fam)
            key = lambda e: (e["agent"], S.window_of(e["t"]))                                    # noqa: E731
            self.assertEqual([e for e in normal if key(e) not in victims], [e for e in info["events"] if key(e) not in victims])

    def test_training_never_sees_an_attack(self):
        lay = G.Layout.of(self.ds["train"], known_agents=sorted(S.AGENTS))
        train_keys = {(e["agent"], e["kind"], e["target"]) for e in self.ds["train"]}
        for fam, info in self.ds["attacks"].items():
            victims = {tuple(v) for v in info["victims"]}
            added = {(e["agent"], e["kind"], e["target"]) for e in info["events"] if (e["agent"], S.window_of(e["t"])) in victims}
            self.assertTrue(added - train_keys or fam in ("volume_shift", "mix_shift"), f"{fam} should show something training did not")
        self.assertEqual(lay.slots, len(lay.tools) + len(lay.resources) + len(lay.agents) + 1)


class GraphTests(unittest.TestCase):
    def test_a_snapshot_describes_what_happened_and_never_who_an_agent_is(self):
        ev = [{"t": 1.0, "agent": "support-1", "kind": "tool_call", "target": "search", "dept": "Customer", "tier": 2},
              {"t": 2.0, "agent": "support-1", "kind": "data_access", "target": "crm", "dept": "Customer", "tier": 2},
              {"t": 3.0, "agent": "support-1", "kind": "delegation", "target": "payments-1", "dept": "Customer", "tier": 2}]
        lay = G.Layout(["search", "notify"], ["crm"], ["support-1", "payments-1"], ["Customer"])
        s = G.build(ev, lay)
        self.assertEqual({n[0] for n in s.nodes}, {"agent", "tool", "resource", "dept"})
        self.assertEqual(sorted(n[1] for n in s.nodes if n[0] == "agent"), ["payments-1", "support-1"], "a delegation target becomes a node too")
        self.assertTrue(all(len(v) == lay.dim for v in s.x))
        renamed = [dict(e, agent="support-9") if e["agent"] == "support-1" else e for e in ev]
        s2 = G.build(renamed, G.Layout(["search", "notify"], ["crm"], ["support-9", "payments-1"], ["Customer"]))
        a1 = [v for (t, n), v in zip(s.nodes, s.x) if t == "agent" and n == "support-1"][0]
        a2 = [v for (t, n), v in zip(s2.nodes, s2.x) if t == "agent" and n == "support-9"][0]
        self.assertEqual(sum(1 for x in a1 if x), sum(1 for x in a2 if x))
        self.assertEqual(G.build(ev, lay).x, s.x, "a snapshot is deterministic")
        with_unknown = G.build(ev + [{"t": 4.0, "agent": "support-1", "kind": "tool_call", "target": "never-seen", "dept": "Customer", "tier": 2}], lay)
        self.assertTrue(with_unknown.x[0][-1] > 0 or any(v[-1] > 0 for v in with_unknown.x), "an unknown target lands in the other slot instead of crashing")
        self.assertEqual(G.build([], lay).nodes, [])


class ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ds = S.make_dataset(seed=5, **SMALL)
        cls.lay = G.Layout.of(cls.ds["train"], known_agents=sorted(S.AGENTS))
        cls.snaps = service.snapshots(cls.ds["train"], cls.lay, 0, cls.ds["spans"]["train"][1])
        cls.model, cls.curve = M.train(cls.snaps, cls.lay.dim, seed=1, epochs=12)

    def test_deterministic_for_a_seed_and_different_between_seeds(self):
        again, _ = M.train(self.snaps, self.lay.dim, seed=1, epochs=12)
        self.assertEqual(M.state_dict_checksum(again), M.state_dict_checksum(self.model))
        other, _ = M.train(self.snaps, self.lay.dim, seed=2, epochs=12)
        self.assertNotEqual(M.state_dict_checksum(other), M.state_dict_checksum(self.model))

    def test_it_learns_normal_traffic_and_scores_a_late_agent_it_never_saw(self):
        self.assertLess(self.curve[-1], self.curve[0] * 0.7, self.curve)
        late = [e for e in self.ds["val"] if e["agent"] in S.COLD]
        wins = G.by_window(late, S.WINDOW, 0, 1e9)
        self.assertTrue(wins)
        errs = [M.agent_errors(self.model, G.build(evs, self.lay)) for evs in wins.values()]
        self.assertTrue(all(v == v and v >= 0 for e in errs for v in e.values()))

    def test_the_robust_normalisation_ignores_an_outlier_and_has_a_floor(self):
        med, mad = M.robust_norm([1.0, 1.1, 0.9, 1.0, 1.05, 0.95, 40.0])
        self.assertAlmostEqual(med, 1.0, places=1)
        self.assertLess(mad, 1.0, "one wild value does not move the spread")
        self.assertGreater(M.robust_norm([2.0] * 8)[1], 0, "a perfectly steady node still has a positive scale")

    def test_weights_round_trip_with_their_checksum(self):
        with tempfile.TemporaryDirectory() as d:
            r = service.train_and_evaluate(seed=5, epochs=4, out=d, **SMALL)
            model, lay = service.load(d, r["checksum"])
            self.assertEqual(M.state_dict_checksum(model), r["checksum"])
            with self.assertRaises(RuntimeError):
                service.load(d, "0" * 64)


class EvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = service.train_and_evaluate(seed=5, epochs=8, **SMALL)

    def test_the_metrics_answer_both_questions_and_are_plain_json(self):
        m = self.r["metrics"]
        fams = set(S.DEV_FAMILIES + S.TEST_FAMILIES)
        self.assertTrue(m["simulated"])
        for key in (("gnn", "tpr"), ("baseline", "tpr"), ("reachability", "tpr"), ("gnn", "novel")):
            self.assertEqual(set(m[key[0]][key[1]]), fams, key)
        self.assertEqual(m["attack_events_not_permitted"], 0)
        self.assertTrue(all(v == 0 for v in m["reachability"]["tpr"].values()), "what the estate permits, the reachability check cannot flag")
        self.assertEqual(m["reachability"]["fpr_test"], 0)
        self.assertTrue(all(0 <= m["gnn"]["novel"][f] <= m["gnn"]["tpr"][f] + 1e-9 for f in fams), "what only the model catches cannot exceed what it catches")
        self.assertEqual(m["families"], {"dev": list(S.DEV_FAMILIES), "test": list(S.TEST_FAMILIES)})
        json.dumps(self.r)

    def test_the_baseline_cannot_judge_an_agent_with_no_history(self):
        m = self.r["metrics"]
        self.assertTrue(set(S.COLD).isdisjoint(m["baseline"]["agents_modelled"]))
        for f, v in m["baseline"]["tpr_late"].items():
            self.assertIn(v, (0.0, None), f)

    def test_the_decision_needs_both_questions(self):
        base = copy.deepcopy(self.r["metrics"])
        fams = list(S.TEST_FAMILIES)
        base["gnn"]["tpr"] = {f: 0.9 for f in S.DEV_FAMILIES + S.TEST_FAMILIES}
        base["baseline"]["tpr"] = {f: 0.4 for f in S.DEV_FAMILIES + S.TEST_FAMILIES}
        base["gnn"]["macro_test"], base["baseline"]["macro_test"], base["gnn"]["fpr_test"] = 0.9, 0.4, 0.03
        base["gnn"]["novel"] = {f: 0.0 for f in S.DEV_FAMILIES + S.TEST_FAMILIES}
        d = E.decide(base)
        self.assertFalse(d["passed"])
        self.assertTrue(any("does not add enough" in r for r in d["reasons"]), d)
        base["gnn"]["novel"][fams[0]], base["gnn"]["novel"][fams[1]] = 0.5, 0.3
        self.assertTrue(E.decide(base)["passed"], E.decide(base))
        base["gnn"]["novel"][fams[1]] = 0.24
        self.assertFalse(E.decide(base)["passed"], "a quarter is the floor")
        base["gnn"]["novel"][fams[1]] = 0.3
        weak = copy.deepcopy(base)
        weak["gnn"]["macro_test"] = 0.42
        self.assertTrue(any("not clearly better" in r for r in E.decide(weak)["reasons"]))
        noisy = copy.deepcopy(base)
        noisy["gnn"]["fpr_test"] = 0.3
        self.assertTrue(any("false-positive" in r for r in E.decide(noisy)["reasons"]))
        forbidden = copy.deepcopy(base)
        forbidden["attack_events_not_permitted"] = 2
        self.assertTrue(any("not permitted" in r for r in E.decide(forbidden)["reasons"]))
        leaky = copy.deepcopy(base)
        leaky["families"]["dev"] = [fams[0]]
        self.assertTrue(any("overlap" in r for r in E.decide(leaky)["reasons"]))

    def test_settings_are_chosen_on_dev_families_only(self):
        r = service.train_and_evaluate(seed=5, configs=((3, 4), (6, 4)), **SMALL)
        sel = r["metrics"]["selection"]
        self.assertEqual(sel["chosen_on"], "dev families only")
        self.assertTrue(all(set(c) == {"epochs", "emb", "dev_detection"} for c in sel["candidates"]))
        best = max(sel["candidates"], key=lambda c: (c["dev_detection"], -c["epochs"]))
        self.assertEqual((r["hyper"]["epochs"], r["hyper"]["emb"]), (best["epochs"], best["emb"]))


class ServiceTests(unittest.TestCase):
    def test_what_the_service_posts_is_a_number_never_a_control_or_a_level(self):
        ds = S.make_dataset(seed=5, **SMALL)
        with tempfile.TemporaryDirectory() as d:
            r = service.train_and_evaluate(seed=5, epochs=3, out=d, **SMALL)
            now = time.time()
            shift = (int(now // S.WINDOW) - 12) * S.WINDOW - ds["spans"]["test"][0]
            events = [dict(e, t=e["t"] + shift) for e in ds["test"]]
            posts = []

            class Fake:
                def call(self, method, path, body=None):
                    if path.startswith("/api/astra/learned/gnn/active"):
                        return {"id": "m1", "checksum": r["checksum"], "normalisation": r["metrics"]["normalisation"], "last_window_end": events[0]["t"] // S.WINDOW * S.WINDOW}
                    if path.startswith("/api/astra/learned/stream"):
                        return {"events": [dict(e, extra="never read") for e in events], "more": False}
                    posts.append((method, path, body))
                    return {"scored": len(body["windows"]), "flagged": 0}

            original = service.from_env
            service.from_env = lambda: Fake()
            try:
                self.assertEqual(service.cmd_score(argparse.Namespace(out=d)), 0)
            finally:
                service.from_env = original
            self.assertEqual(len(posts), 1)
            method, path, body = posts[0]
            self.assertEqual((method, path), ("POST", "/api/astra/learned/gnn/scores"))
            self.assertEqual(set(body), {"model_id", "windows"})
            self.assertTrue(body["windows"])
            for w in body["windows"]:
                self.assertEqual(set(w), {"agent", "window_start", "events", "score"})
                self.assertEqual(w["window_start"] % S.WINDOW, 0)

    def test_nothing_is_scored_when_no_graph_model_is_adopted(self):
        class Fake:
            def call(self, method, path, body=None):
                return None
        original = service.from_env
        service.from_env = lambda: Fake()
        try:
            self.assertEqual(service.cmd_score(argparse.Namespace(out="/nonexistent")), 0)
        finally:
            service.from_env = original


if __name__ == "__main__":
    unittest.main()
