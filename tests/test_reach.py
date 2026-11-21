"""Reach graph: who can reach what, directly or through another agent, and approvals that go stale indirectly."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from pathlib import Path

from scopewake import approvals as apv
from scopewake import reach
from scopewake.cli import main
from scopewake.diff import normalize

D0, D1 = date(2026, 11, 1), date(2026, 11, 20)


def agent(name, caps=(), calls=(), kind="copilot-studio", rel=None, creds=(), servers=()):
    return {"id": rel or name, "kind": kind, "name": name, "source_rel": rel or name, "score": 0, "trifecta": False,
            "credentials": [{"kind": k, "location": loc, "loc_rel": loc, "name": n, "mitigated": False} for k, loc, n in creds],
            "capabilities": [{"name": c, "via": "test"} for c in caps] + [{"name": f"agent:{c}", "via": "test"} for c in calls],
            "servers": [{"config": "test", "name": s, "transport": "http", "endpoint": f"https://{s}.example", "args_hash": "",
                         "fingerprint": s, "env_names": [], "header_names": []} for s in servers], "cloud": {}}


def rep(*agents, complete=True):
    return normalize({"tool": "scopewake", "coverage": {"complete": complete, "issues": []}, "agents": list(agents)})


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class GraphTests(unittest.TestCase):
    def test_chain_is_followed_with_shortest_path(self):
        g = reach.build(rep(agent("Front desk", ["tool:faq"], calls=["Invoice helper"]),
                            agent("Invoice helper", ["tool:invoices"], calls=["Payments bot"]),
                            agent("Payments bot", ["tool:payments"], servers=["stripe"])))
        fd = next(a for a in g["agents"] if a["agent"].startswith("copilot-studio/Front desk"))
        got = {(x["type"], x["target"]): x["path"] for x in fd["indirect"]}
        self.assertEqual(len(got[("capability", "tool:payments")]), 3)
        self.assertEqual(len(got[("capability", "tool:invoices")]), 2)
        self.assertIn(("server", "stripe (https://stripe.example)"), got)
        self.assertTrue(g["coverage"]["complete"])

    def test_direct_reach_is_not_reported_as_indirect(self):
        g = reach.build(rep(agent("A", ["tool:payments"], calls=["B"]), agent("B", ["tool:payments", "tool:mail"])))
        a = next(x for x in g["agents"] if x["agent"].startswith("copilot-studio/A"))
        self.assertEqual([x["target"] for x in a["indirect"]], ["tool:mail"])

    def test_cycle_terminates_and_self_link_is_ignored(self):
        g = reach.build(rep(agent("A", ["tool:a"], calls=["B", "A"]), agent("B", ["tool:b"], calls=["A"])))
        ind = reach.indirect_by_agent(g)
        self.assertEqual([x[1] for x in ind[[k for k in ind if "/A" in k][0]]], ["tool:b"])
        self.assertEqual([x[1] for x in ind[[k for k in ind if "/B" in k][0]]], ["tool:a"])

    def test_unresolved_and_ambiguous_links_make_the_graph_incomplete(self):
        g = reach.build(rep(agent("A", calls=["Ghost"])))
        self.assertFalse(g["coverage"]["complete"])
        self.assertEqual(g["coverage"]["unresolved_links"][0]["link"], "Ghost")
        g = reach.build(rep(agent("A", calls=["Twin"]), agent("Twin", ["tool:x"], rel="t1"), agent("Twin", ["tool:y"], rel="t2")))
        self.assertEqual(len(g["coverage"]["ambiguous_links"][0]["candidates"]), 2)
        self.assertEqual(next(a for a in g["agents"] if "/A" in a["agent"])["indirect"], [])

    def test_link_resolves_by_id_and_drops_fingerprint_suffix(self):
        g = reach.build(rep(agent("A", calls=["agent-0042#abcdef123456"]), agent("Payments bot", ["tool:payments"], rel="agent-0042")))
        self.assertEqual(next(a for a in g["agents"] if "/A" in a["agent"])["indirect"][0]["target"], "tool:payments")

    def test_hop_limit_is_reported_not_silent(self):
        chain = [agent(f"N{i}", [f"tool:t{i}"], calls=[f"N{i + 1}"] if i < 8 else []) for i in range(9)]
        g = reach.build(rep(*chain))
        self.assertTrue(g["coverage"]["truncated"])
        self.assertFalse(g["coverage"]["complete"])
        n0 = next(a for a in g["agents"] if a["agent"].startswith("copilot-studio/N0"))
        self.assertEqual(len(n0["indirect"]), reach.MAX_HOPS)

    def test_incomplete_scan_carries_through(self):
        self.assertFalse(reach.build(rep(agent("A"), complete=False))["coverage"]["complete"])

    def test_select_finds_every_agent_that_reaches_a_target(self):
        g = reach.select(reach.build(rep(agent("A", calls=["B"]), agent("B", ["tool:payments"]), agent("C", ["tool:mail"]))), "PAYMENTS")
        self.assertEqual(len(g["targets"]), 1)
        self.assertEqual([r["direct"] for r in g["targets"][0]["reached_by"]], [False, True])

    def test_mermaid_and_text_render(self):
        g = reach.build(rep(agent("A", calls=["B", "Ghost"]), agent("B", ["tool:payments"])))
        self.assertIn("-.->", reach.to_mermaid(g))
        self.assertIn("not in report", reach.to_mermaid(g))
        self.assertIn("via copilot-studio/B", reach.to_text(g))


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.before = rep(agent("Invoice helper", ["tool:invoices"], calls=["Payments bot"]), agent("Payments bot", ["tool:ledger-read"]))
        self.led = apv.approve(apv.empty_ledger(), self.before, "Invoice helper", ["Invoice helper"], "Head of Risk", D0)

    def test_unchanged_is_current(self):
        r = apv.review(self.led, self.before, D1)["approvals"][0]
        self.assertEqual(r["status"], "current")

    def test_change_in_called_agent_makes_caller_approval_stale(self):
        after = rep(agent("Invoice helper", ["tool:invoices"], calls=["Payments bot"]), agent("Payments bot", ["tool:ledger-read", "tool:payments"]))
        r = apv.review(self.led, after, D1)["approvals"][0]
        self.assertEqual(r["status"], "re-review required")
        self.assertEqual([x["type"] for x in r["reasons"]], ["indirect reach added"])
        self.assertIn("tool:payments", r["reasons"][0]["detail"])
        self.assertIn("Payments bot", r["reasons"][0]["detail"])

    def test_new_link_makes_approval_stale_twice_over(self):
        after = rep(agent("Invoice helper", ["tool:invoices"], calls=["Payments bot", "Mail bot"]), agent("Payments bot", ["tool:ledger-read"]),
                    agent("Mail bot", ["tool:send-mail"]))
        types = [x["type"] for x in apv.review(self.led, after, D1)["approvals"][0]["reasons"]]
        self.assertIn("capability added", types)        # the link itself
        self.assertIn("indirect reach added", types)    # what the link brings

    def test_removed_indirect_reach_does_not_require_review(self):
        after = rep(agent("Invoice helper", ["tool:invoices"], calls=["Payments bot"]), agent("Payments bot", []))
        r = apv.review(self.led, after, D1)["approvals"][0]
        self.assertEqual(r["status"], "current")
        self.assertEqual(r["reasons"][0]["type"], "indirect reach reduced")

    def test_ledger_from_before_this_version_is_not_flagged(self):
        old = json.loads(json.dumps(self.led))
        for s in old["approvals"][0]["snapshot"]["agents"]:
            s.pop("indirect")
        after = rep(agent("Invoice helper", ["tool:invoices"], calls=["Payments bot"]), agent("Payments bot", ["tool:ledger-read", "tool:payments"]))
        self.assertEqual(apv.review(old, after, D1)["approvals"][0]["status"], "current")

    def test_ledger_with_indirect_reach_verifies(self):
        self.assertEqual(apv.verify_ledger(self.led)["status"], "intact")


class CliTests(unittest.TestCase):
    def test_reach_from_merged_report(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "all.json"
            p.write_text(json.dumps({"tool": "scopewake", "coverage": {"complete": True, "issues": []},
                                     "agents": [agent("A", calls=["B"]), agent("B", ["tool:payments"])]}))
            code, out, _ = run(["reach", "--report", str(p), "--to", "payments"])
            self.assertEqual(code, 0)
            self.assertIn("via copilot-studio/B", out)
            code, out, _ = run(["reach", "--report", str(p), "--format", "json"])
            self.assertEqual(json.loads(out)["kind"], "reach-graph")
            self.assertEqual(run(["reach", "--report", str(p), "--fail-on-indirect"])[0], 1)
            self.assertEqual(run(["reach", "--report", str(p), "--to", " "])[0], 2)
            self.assertEqual(run(["reach", "--report", str(Path(t) / "missing.json")])[0], 2)


class ImportRegressionTests(unittest.TestCase):
    def test_each_imported_agent_keeps_its_own_name(self):
        """Up to 0.4.0 every imported agent was given the name of the last row in the export."""
        from scopewake.inventory import import_inventory
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "agents.csv"
            p.write_text("AgentId,AgentName,Platform,DeclaredTools,ConnectedAgents\n"
                         "a-1,Invoice helper,Copilot Studio,read-invoices,Payments bot\n"
                         "a-2,Payments bot,Copilot Studio,read-ledger;send-payment,\n")
            r = import_inventory(str(p))
            self.assertEqual([a["name"] for a in r["agents"]], ["Invoice helper", "Payments bot"])
            g = reach.build(normalize(r))
            helper = next(a for a in g["agents"] if "Invoice helper" in a["agent"])
            self.assertEqual({x["target"] for x in helper["indirect"]}, {"tool:read-ledger", "tool:send-payment"})


if __name__ == "__main__":
    unittest.main()
