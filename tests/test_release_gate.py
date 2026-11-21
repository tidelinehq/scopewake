"""Release gate: reach-graph soundness against an independent oracle, approval migration, and evidence integrity."""
import copy
import io
import json
import random
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from pathlib import Path

from scopewake import approvals as apv
from scopewake import reach
from scopewake.cli import main
from test_reach import agent, rep

D0, D1, D2 = date(2026, 11, 1), date(2026, 11, 10), date(2026, 11, 20)


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class ReachOracleTests(unittest.TestCase):
    """The oracle shares no code with reach.build: all-pairs shortest hops by repeated relaxation."""

    def oracle(self, names, tools, calls):
        INF = 10 ** 6
        d = {a: {b: (0 if a == b else INF) for b in names} for a in names}
        for a in names:
            for b in calls[a]:
                if b != a:
                    d[a][b] = 1
        for k in names:
            for i in names:
                for j in names:
                    if d[i][k] + d[k][j] < d[i][j]:
                        d[i][j] = d[i][k] + d[k][j]
        want, cut = {}, False
        for a in names:
            best = {}
            for b in names:
                if b == a or d[a][b] >= INF:
                    continue
                if d[a][b] > reach.MAX_HOPS:
                    cut = True
                    continue
                for t in tools[b]:
                    if t not in tools[a]:
                        best[t] = min(best.get(t, INF), d[a][b])
            want[a] = best
        return want, cut

    def test_random_graphs_match_the_oracle(self):
        rng = random.Random(20261121)
        for trial in range(400):
            n = rng.randint(1, 9)
            names = [f"Agent{i}" for i in range(n)]
            pool = [f"tool:t{i}" for i in range(rng.randint(1, 8))]
            tools = {a: set(rng.sample(pool, rng.randint(0, len(pool)))) for a in names}
            calls = {a: set(rng.sample(names, rng.randint(0, min(3, n)))) for a in names}
            g = reach.build(rep(*[agent(a, sorted(tools[a]), calls=sorted(calls[a])) for a in names]))
            want, cut = self.oracle(names, tools, calls)
            got = {a["agent"].split("/")[1].split(" (")[0]: a for a in g["agents"]}
            self.assertEqual(g["coverage"]["truncated"], cut, trial)
            for a in names:
                found = {x["target"]: x["path"] for x in got[a]["indirect"]}
                self.assertEqual(set(found), set(want[a]), (trial, a))
                for t, path in found.items():
                    self.assertEqual(len(path) - 1, want[a][t], (trial, a, t))          # a shortest path
                    hops = [p.split("/")[1].split(" (")[0] for p in path]
                    self.assertEqual(hops[0], a)
                    self.assertTrue(all(hops[i + 1] in calls[hops[i]] for i in range(len(hops) - 1)), (trial, path))
                    self.assertIn(t, tools[hops[-1]])                                    # the last agent really holds it

    def test_revoked_link_and_revoked_permission_remove_reach(self):
        before = rep(agent("A", calls=["B"]), agent("B", ["tool:payments"]))
        led = apv.approve(apv.empty_ledger(), before, "A", ["A"], "Risk", D0)
        no_link = rep(agent("A"), agent("B", ["tool:payments"]))
        no_perm = rep(agent("A", calls=["B"]), agent("B"))
        for after in (no_link, no_perm):
            self.assertEqual(reach.indirect_by_agent(reach.build(after))[[k for k in reach.indirect_by_agent(reach.build(after)) if "/A" in k][0]], [])
            self.assertNotEqual(apv.review(led, after, D1)["approvals"][0]["status"], "re-review required")
        # granted again after revocation: stale again
        self.assertEqual(apv.review(led, before, D1)["approvals"][0]["status"], "current")

    def test_every_edge_states_what_it_claims_and_where_it_came_from(self):
        g = reach.build(rep(agent("A", ["tool:x"], calls=["B"]), agent("B", ["tool:payments"])))
        self.assertEqual(g["semantics"]["state"], "configured")
        for t in g["targets"]:
            for r in t["reached_by"]:
                self.assertEqual(r["state"], "configured")
                self.assertTrue(r["evidence"])
        a = next(x for x in g["agents"] if "/A" in x["agent"])
        self.assertEqual((a["links"][0]["declared_as"], a["links"][0]["state"]), ("B", "configured"))
        self.assertTrue(a["links"][0]["evidence"])
        self.assertIn("does not show", reach.to_text(g))


class MigrationTests(unittest.TestCase):
    def old_import_ledger(self):
        """A ledger as 0.4.0 wrote it from a two-row import: both agents carry the last row's name, no indirect reach."""
        wrong = rep({**agent("Payments bot", rel="a-1"), "capabilities": [{"name": "tool:read-invoices", "via": "defender:DeclaredTools"}]},
                    {**agent("Payments bot", rel="a-2"), "capabilities": [{"name": "tool:read-ledger", "via": "defender:DeclaredTools"}]})
        led = apv.approve(apv.empty_ledger(), wrong, "Finance agents", ["copilot-studio"], "Risk", D0)
        for s in led["approvals"][0]["snapshot"]["agents"]:
            s.pop("indirect")
        return led

    def test_affected_approval_is_flagged_and_never_current(self):
        led = self.old_import_ledger()
        fixed = rep({**agent("Invoice helper", rel="a-1"), "capabilities": [{"name": "tool:read-invoices", "via": "defender:DeclaredTools"}]},
                    {**agent("Payments bot", rel="a-2"), "capabilities": [{"name": "tool:read-ledger", "via": "defender:DeclaredTools"}]})
        r = apv.review(led, fixed, D1)["approvals"][0]
        self.assertEqual(r["status"], "re-review required")
        self.assertIn("recorded before the import naming fix", [x["type"] for x in r["reasons"]])

    def test_scanned_agents_and_new_approvals_are_not_flagged(self):
        scanned = rep({**agent("Cursor", kind="cursor"), "capabilities": [{"name": "payments", "via": "mcp:stripe"}]})
        led = apv.approve(apv.empty_ledger(), scanned, "Dev", ["cursor"], "Risk", D0)
        old = copy.deepcopy(led)
        old["approvals"][0]["snapshot"]["agents"][0].pop("indirect")
        for l in (led, old):
            self.assertEqual(apv.review(l, scanned, D1)["approvals"][0]["status"], "current")
        imported = rep({**agent("Invoice helper", rel="a-1"), "capabilities": [{"name": "tool:x", "via": "generic:tools"}]})
        new = apv.approve(apv.empty_ledger(), imported, "Fin", ["Invoice helper"], "Risk", D0)
        self.assertEqual(apv.review(new, imported, D1)["approvals"][0]["status"], "current")


class LedgerIntegrityTests(unittest.TestCase):
    def setUp(self):
        r = rep(agent("A", ["tool:x"]), agent("B", ["tool:y"]))
        self.one = apv.approve(apv.empty_ledger(), r, "A", ["A"], "Risk", D0)
        self.two = apv.approve(copy.deepcopy(self.one), r, "B", ["B"], "Risk", D1)
        self.head1, self.head2 = apv.head_hash(self.one), apv.head_hash(self.two)

    def test_rollback_to_an_older_copy_passes_the_chain_but_fails_the_anchor(self):
        self.assertEqual(apv.verify_ledger(self.one)["status"], "intact")                     # the chain alone cannot see it
        res = apv.verify_ledger(self.one, expect_head=self.head2)
        self.assertEqual((res["status"], res["anchor"]), ("tampered", "not found"))

    def test_older_anchor_is_found_when_the_ledger_has_moved_on(self):
        res = apv.verify_ledger(self.two, expect_head=self.head1.upper())
        self.assertEqual(res["status"], "intact")
        self.assertIn("1 later event", res["anchor"])

    def test_cut_tail_replayed_event_reorder_and_foreign_anchor(self):
        cut = copy.deepcopy(self.two); cut["log"].pop()
        self.assertEqual(apv.verify_ledger(cut)["status"], "tampered")                        # approval B no longer logged
        replay = copy.deepcopy(self.two); replay["log"].append(copy.deepcopy(replay["log"][0]))
        self.assertEqual(apv.verify_ledger(replay)["status"], "tampered")
        swap = copy.deepcopy(self.two); swap["log"].reverse()
        self.assertEqual(apv.verify_ledger(swap)["status"], "tampered")
        self.assertEqual(apv.verify_ledger(self.two, expect_head="f" * 64)["status"], "tampered")
        self.assertEqual(apv.verify_ledger(apv.empty_ledger(), expect_head=self.head1)["status"], "tampered")

    def test_cli_expect_head(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "led.json"; p.write_text(json.dumps(self.one))
            self.assertEqual(run(["verify-ledger", str(p), "--expect-head", self.head1])[0], 0)
            code, out, _ = run(["verify-ledger", str(p), "--expect-head", self.head2])
            self.assertEqual(code, 1)
            self.assertIn("rolled back", out)


class PackIntegrityTests(unittest.TestCase):
    def pack(self):
        with tempfile.TemporaryDirectory() as t:
            led = Path(t) / "led.json"
            rp = Path(t) / "r.json"
            rp.write_text(json.dumps({"tool": "scopewake", "coverage": {"complete": True, "issues": []}, "agents": [agent("A", ["tool:x"])]}))
            code, out, _ = run(["approve", "--report", str(rp), "--system", "A", "--agent", "A", "--by", "Risk"])
            led.write_text(out)
            home = Path(t) / "home"; home.mkdir(); proj = Path(t) / "proj"; proj.mkdir()
            code, out, _ = run(["evidence", str(proj), "--home", str(home), "--include", str(rp), "--approvals", str(led), "--format", "json"])
            return json.loads(out)

    def test_untouched_pack_verifies_and_every_kind_of_edit_is_caught(self):
        pk = self.pack()
        self.assertEqual(apv.verify_pack(pk)["status"], "intact")
        edits = []
        a = copy.deepcopy(pk); a["files"]["review.md"] += "\nall clear"; edits.append(a)                     # file changed
        b = copy.deepcopy(pk); b["files"]["extra.md"] = "x"; edits.append(b)                                  # file added
        c = copy.deepcopy(pk); c["files"].pop("reach.json"); edits.append(c)                                  # file removed
        d = copy.deepcopy(pk); d["manifest"]["ledger_head"] = "0" * 64; edits.append(d)                       # head misreported
        e = copy.deepcopy(pk)                                                                                 # ledger edited, hash refreshed
        led = json.loads(e["files"]["ledger.json"]); led["approvals"][0]["approved_by"] = "Someone else"
        e["files"]["ledger.json"] = json.dumps(led, indent=2)
        import hashlib
        e["manifest"]["sha256"]["ledger.json"] = hashlib.sha256(e["files"]["ledger.json"].encode()).hexdigest()
        edits.append(e)
        for x in edits:
            self.assertEqual(apv.verify_pack(x)["status"], "tampered")

    def test_cli_and_honest_note(self):
        pk = self.pack()
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "pack.json"; p.write_text(json.dumps(pk))
            code, out, _ = run(["verify-evidence", str(p)])
            self.assertEqual(code, 0)
            self.assertIn("does not show who made it", out)
            pk["files"]["scan.md"] = "edited"; p.write_text(json.dumps(pk))
            self.assertEqual(run(["verify-evidence", str(p)])[0], 1)
            p.write_text("[]")
            self.assertEqual(run(["verify-evidence", str(p)])[0], 2)


if __name__ == "__main__":
    unittest.main()
