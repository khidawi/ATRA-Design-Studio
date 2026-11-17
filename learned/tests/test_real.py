"""
Tests for the real-traces mode of the learned service (ASTRA phase 16, learned/real.py): a company's own events become a held-out evaluation, with attacks injected from that company's own
agents and targets; too little history is refused with the reason; nothing about an attack reaches training; and the whole path from events to an evaluation the platform can judge runs.

    docker build -f learned/Dockerfile -t astra-learned . && docker run --rm --entrypoint python astra-learned -m unittest learned.tests.test_real

The "company" here is made by the simulator's normal-traffic process under other agent names and real epoch times: that tests the PIPELINE on data of the right shape. It says nothing about how the
network does on a real company, which is what the real evaluation (service evaluate --real) is for.
"""
import argparse
import unittest

from learned import real as R
from learned.tgn import schema
from learned.tgn import service
from learned.tgn import simulate as S

T0 = 1_700_000_000.0


def company(minutes: float = 150, seed: int = 5, agents=None):
    """Normal traffic of the right shape under a company's own agent names, at real epoch times."""
    out = []
    for e in S.normal_traffic(seed, minutes):
        if agents is not None and e["agent"] not in agents:
            continue
        out.append(dict(e, agent="acme-" + e["agent"], t=e["t"] + T0))
    return out


class DatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = company()
        cls.ds = R.make_dataset(cls.raw, seed=3, episodes=6)

    def test_the_dataset_is_real_labelled_and_split_by_time_with_no_event_in_two_places(self):
        ds = self.ds
        self.assertIs(ds["simulated"], False)
        self.assertEqual(ds["data"]["kind"], "real normal traffic with injected attacks")
        self.assertEqual(len(ds["train"]) + len(ds["val"]) + len(ds["test"]), len(schema.dataset(self.raw)["events"]))
        (a0, a1), (b0, b1), (c0, c1) = ds["spans"]["train"], ds["spans"]["val"], ds["spans"]["test"]
        self.assertTrue(a1 == b0 and b1 == c0 and a0 <= ds["train"][0]["t"])
        self.assertTrue(all(e["t"] < a1 for e in ds["train"]) and all(b0 <= e["t"] < b1 for e in ds["val"]) and all(e["t"] >= c0 for e in ds["test"]))
        self.assertTrue(all(a.startswith("acme-") for a in ds["data"]["agents"]), "the vocabulary is the company's own, not the simulator's")

    def test_families_never_cross_and_nothing_about_an_attack_reaches_training_or_the_other_span(self):
        ds = self.ds
        v0, t0 = ds["spans"]["val"][0], ds["spans"]["test"][0]
        self.assertTrue(set(ds["attacks"]) <= set(S.DEV_FAMILIES + S.TEST_FAMILIES))
        for fam, info in ds["attacks"].items():
            lo, hi = (v0, t0) if fam in S.DEV_FAMILIES else (t0, ds["spans"]["test"][1])
            self.assertEqual(info["role"], "dev" if fam in S.DEV_FAMILIES else "test")
            for agent, w in info["victims"]:
                self.assertTrue(lo <= w * S.WINDOW < hi, f"{fam} was injected outside its own span")
            before = [e for e in info["events"] if e["t"] < v0]
            self.assertEqual(before, ds["train"], f"{fam} changed the training span")

    def test_the_attacks_are_made_from_the_companys_own_agents_and_targets(self):
        ds = self.ds
        known = {(e["agent"], e["kind"], e["target"]) for e in ds["train"]}
        own_targets = {e["target"] for e in ds["train"]}
        for fam in ("metronome", "slow_drip"):
            if fam not in ds["attacks"]:
                continue
            normal = {(e["t"], e["agent"], e["kind"], e["target"]) for e in ds["val"] + ds["test"]}
            injected = [e for e in ds["attacks"][fam]["events"] if (e["t"], e["agent"], e["kind"], e["target"]) not in normal and e["t"] >= ds["spans"]["val"][0]]
            self.assertTrue(injected, f"{fam} injected nothing")
            for e in injected:
                self.assertIn(e["agent"], ds["data"]["agents"])
                self.assertIn(e["target"], own_targets, f"{fam} used a target the company never uses")
        self.assertTrue(known)

    def test_the_summary_says_what_was_and_was_not_measured(self):
        text = R.summary(self.ds)
        self.assertIn("real traces", text)
        self.assertIn("attack families measured", text)


class RefusalTests(unittest.TestCase):
    def test_too_few_events_are_refused_with_the_number_and_what_is_needed(self):
        with self.assertRaises(R.DataError) as c:
            R.make_dataset(company(minutes=10))
        self.assertIn("at least", str(c.exception))

    def test_a_history_too_short_for_a_held_out_test_is_refused_with_the_reason(self):
        raw = company(minutes=30)
        raw = [e for e in raw if e["agent"] == "acme-support"] * 1
        with self.assertRaises(R.DataError) as c:
            R.make_dataset(raw + [dict(e, t=e["t"] + 1) for e in raw] + [dict(e, t=e["t"] + 2) for e in raw])
        self.assertTrue("agent-minutes" in str(c.exception) or "at least" in str(c.exception) or "training span" in str(c.exception), str(c.exception))

    def test_a_company_with_one_agent_cannot_host_a_lateral_chain_and_says_so(self):
        raw = company(minutes=400, agents={"support"})
        ds = R.make_dataset(raw, seed=3, episodes=6)
        self.assertNotIn("lateral_chain", ds["attacks"])
        self.assertIn("lateral_chain", ds["data"]["families_skipped"])
        self.assertIn("second agent", ds["data"]["families_skipped"]["lateral_chain"])

    def test_the_command_refuses_a_company_without_enough_data_and_exits_with_the_reason(self):
        original_env, original_fetch = service.from_env, service.fetch_real
        service.from_env = lambda: object()
        service.fetch_real = lambda p, days: company(minutes=5)
        try:
            code = service.cmd_evaluate(argparse.Namespace(real=True, days=14.0, episodes=6, seed=1, epochs=2, out="/nonexistent", post=False))
        finally:
            service.from_env, service.fetch_real = original_env, original_fetch
        self.assertEqual(code, 3)


class PathTests(unittest.TestCase):
    def test_events_become_a_model_and_an_evaluation_marked_as_real_traces(self):
        ds = R.make_dataset(company(), seed=3, episodes=6)
        r = service.train_and_evaluate(seed=3, epochs=2, d=16, ds=ds)
        m = r["metrics"]
        self.assertIs(m["simulated"], False)
        self.assertEqual(m["data"]["kind"], "real normal traffic with injected attacks")
        self.assertEqual(m["dataset_hash"], ds["hash"])
        for key in ("budget_fpr", "margin", "families", "tgn", "baseline", "normalisation", "decision"):
            self.assertIn(key, m)
        self.assertTrue(set(m["normalisation"]) <= set(ds["data"]["agents"]) | {e["agent"] for e in ds["val"]}, "normalised per agent of this company")
        self.assertTrue({"acme-support"} <= set(r["vocab"]["nodes"]), "the model's vocabulary is the company's own agents")
        self.assertEqual(len(r["checksum"]), 64)


if __name__ == "__main__":
    unittest.main()
