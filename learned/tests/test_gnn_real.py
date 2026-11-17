"""
Tests for the real-traces mode of the graph model (ASTRA phase 17, learned/gnn/real.py): a company's own events and the permissions of its active contracts become a held-out evaluation whose
attacks are permitted-but-unusual; an agent without a contract is left out and named; an estate that cannot host a family says so; the path from events to an evaluation the platform can judge runs.

    docker build -f learned/Dockerfile -t astra-learned . && docker run --rm --entrypoint python astra-learned -m unittest learned.tests.test_gnn_real

The "company" is the graph simulator's estate under real epoch times, with its own role permissions standing in for contracts: that tests the PIPELINE on data of the right shape. It says nothing
about how the graph model does on a real company, which is what the real evaluation (gnn evaluate --real) is for.
"""
import argparse
import unittest

from learned.gnn import evaluate as E
from learned.gnn import real as R
from learned.gnn import service
from learned.gnn import simulate as S

T0 = 1_700_000_000.0


def company(agents=None, minutes: float = 200):
    out = []
    for e in S.normal_traffic(5, minutes, cold_from=minutes * 0.6 * 60):
        if agents is None or e["agent"] in agents:
            out.append(dict(e, t=e["t"] + T0))
    return out


def contracts(agents):
    return {a: S.allowed(a) for a in agents}


class DatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = company()
        cls.ds = R.make_dataset(cls.raw, contracts(S.AGENTS), seed=3, episodes=6)

    def test_the_dataset_is_real_labelled_and_split_by_time(self):
        ds = self.ds
        self.assertIs(ds["simulated"], False)
        (a0, a1), (b0, b1), (c0, c1) = ds["spans"]["train"], ds["spans"]["val"], ds["spans"]["test"]
        self.assertTrue(a1 == b0 and b1 == c0)
        self.assertTrue(all(e["t"] < a1 for e in ds["train"]) and all(b0 <= e["t"] < b1 for e in ds["val"]) and all(e["t"] >= c0 for e in ds["test"]))
        self.assertEqual(ds["data"]["kind"], "real normal traffic with injected attacks")

    def test_every_attack_event_is_permitted_by_the_contract_so_the_reachability_check_sees_none(self):
        ds = self.ds
        self.assertTrue(len(ds["attacks"]) >= 4, ds["data"]["families_skipped"])
        for fam, info in ds["attacks"].items():
            for v in info["victims"]:
                evs = [e for e in info["events"] if (e["agent"], S.window_of(e["t"])) == tuple(v)]
                self.assertTrue(evs, fam)
                self.assertEqual(E.violations(ds, evs), [], f"{fam} used something the contract does not permit")

    def test_families_stay_in_their_own_span_and_never_touch_training(self):
        ds = self.ds
        v0, t0 = ds["spans"]["val"][0], ds["spans"]["test"][0]
        for fam, info in ds["attacks"].items():
            lo, hi = (v0, t0) if fam in R.DEV_FAMILIES else (t0, ds["spans"]["test"][1])
            self.assertEqual(info["role"], "dev" if fam in R.DEV_FAMILIES else "test")
            for agent, w in info["victims"]:
                self.assertTrue(lo <= w * S.WINDOW < hi)
            self.assertEqual([e for e in info["events"] if e["t"] < v0], ds["train"])
        self.assertFalse(set(R.DEV_FAMILIES) & set(R.TEST_FAMILIES))

    def test_peer_families_use_what_the_peers_never_do(self):
        ds = self.ds
        ctx = R.Context(ds["train"], {e["agent"]: e["dept"] for e in ds["train"] + ds["val"] + ds["test"]}, ds["permitted"])
        info = ds["attacks"]["rare_resource"]
        normal = {(e["t"], e["agent"], e["kind"], e["target"]) for e in ds["val"]}
        for agent, w in info["victims"]:
            added = [e for e in info["events"] if (e["agent"], S.window_of(e["t"])) == (agent, w) and (e["t"], e["agent"], e["kind"], e["target"]) not in normal]
            self.assertTrue(added)
            for e in added:
                self.assertEqual(e["kind"], "data_access")
                self.assertNotIn((e["kind"], e["target"]), ctx.peer_use(agent), "an attack on a peer-based family must use something no peer does")

    def test_late_agents_are_named_and_the_summary_says_what_was_measured(self):
        self.assertTrue(set(S.COLD) <= set(self.ds["cold"]))
        text = R.summary(self.ds)
        self.assertIn("real traces", text)
        self.assertIn("attack families measured", text)


class HonestyTests(unittest.TestCase):
    def test_an_agent_without_an_active_contract_is_left_out_and_named(self):
        ds = R.make_dataset(company(), contracts([a for a in S.AGENTS if a != "hr-1"]), seed=3, episodes=6)
        self.assertEqual(ds["data"]["agents_without_contract"], ["hr-1"])
        self.assertNotIn("hr-1", {e["agent"] for e in ds["train"] + ds["val"] + ds["test"]})
        self.assertIn("hr-1", R.summary(ds))

    def test_too_few_events_or_agents_are_refused_with_the_reason(self):
        with self.assertRaises(R.DataError) as c:
            R.make_dataset(company(minutes=5), contracts(S.AGENTS))
        self.assertIn("at least", str(c.exception))
        with self.assertRaises(R.DataError) as c:
            R.make_dataset(company(), contracts(["support-1"]))
        self.assertTrue("peers" in str(c.exception) or "events of agents" in str(c.exception))

    def test_an_estate_without_peers_is_refused_because_no_development_family_can_be_built(self):
        one_each = ["support-1", "payments-1", "hr-1"]            # one agent in each of three departments
        with self.assertRaises(R.DataError) as c:
            R.make_dataset(company(one_each, minutes=400), contracts(one_each), seed=3, episodes=6)
        self.assertIn("settings cannot be chosen", str(c.exception))
        self.assertIn("peer", str(c.exception))

    def test_a_missing_held_out_family_is_named_not_hidden(self):
        raw = [dict(e, dept=("Ops" if e["agent"] in ("payments-1", "payments-2") else e["dept"])) for e in company()]
        ds = R.make_dataset(raw, contracts(S.AGENTS), seed=3, episodes=6)
        self.assertEqual(set(ds["attacks"]) | set(ds["data"]["families_skipped"]), set(R.DEV_FAMILIES + R.TEST_FAMILIES))

    def test_an_agent_with_no_peer_in_an_unassigned_department_has_no_peers(self):
        ctx = R.Context([], {"a": R.UNASSIGNED, "b": R.UNASSIGNED}, {"a": set(), "b": set()})
        self.assertEqual(ctx.peers("a"), [])

    def test_the_contract_view_is_read_into_the_event_vocabulary(self):
        p = R.permitted_of({"tools": [{"name": "search", "write": False}], "data": ["crm"], "delegates_to": ["payments-1"], "mcp_servers": [{"name": "files", "signed": True}]})
        self.assertEqual(p, {("tool_call", "search"), ("data_access", "crm"), ("delegation", "payments-1"), ("mcp_connect", "files")})


class CommandTests(unittest.TestCase):
    def test_permissions_are_read_from_the_contract_view_and_an_agent_without_one_is_left_out(self):
        class P:
            def call(self, method, path, body=None):
                if path.endswith("/a"):
                    return {"state": "contract", "allowed": {"tools": [{"name": "t"}], "data": ["d"], "delegates_to": [], "mcp_servers": []}}
                return {"state": "no_contract", "allowed": None}
        got = service.fetch_permissions(P(), ["a", "b"])
        self.assertEqual(got, {"a": {("tool_call", "t"), ("data_access", "d")}})

    def test_the_command_refuses_a_company_without_enough_data_and_exits_with_the_reason(self):
        o = (service.from_env, service.fetch_real, service.fetch_permissions)
        service.from_env, service.fetch_real, service.fetch_permissions = lambda: object(), lambda p, d: company(minutes=5), lambda p, a: contracts(a)
        try:
            code = service.cmd_evaluate(argparse.Namespace(real=True, days=14.0, episodes=6, seed=1, epochs=2, out="/nonexistent", post=False))
        finally:
            service.from_env, service.fetch_real, service.fetch_permissions = o
        self.assertEqual(code, 3)


class PathTests(unittest.TestCase):
    def test_events_and_contracts_become_a_model_and_an_evaluation_marked_as_real_traces(self):
        ds = R.make_dataset(company(), contracts(S.AGENTS), seed=3, episodes=6)
        r = service.train_and_evaluate(seed=3, epochs=3, emb=4, ds=ds)
        m = r["metrics"]
        self.assertIs(m["simulated"], False)
        self.assertEqual(m["data"]["kind"], "real normal traffic with injected attacks")
        self.assertEqual(m["attack_events_not_permitted"], 0)
        self.assertEqual(m["families"], {"dev": list(R.DEV_FAMILIES), "test": list(R.TEST_FAMILIES)})
        for key in ("budget_fpr", "margin", "novel_min", "gnn", "baseline", "reachability", "normalisation", "decision"):
            self.assertIn(key, m)
        self.assertEqual(set(m["gnn"]["tpr"]), set(ds["attacks"]))
        self.assertEqual(r["vocab"]["agents"], sorted(set(S.AGENTS)))
        self.assertEqual(len(r["checksum"]), 64)


if __name__ == "__main__":
    unittest.main()
