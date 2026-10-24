"""Tests for approval review: approvals frozen against reach, and flagged when a later change makes them stale."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import date
from pathlib import Path

from scopewake import approvals as apv
from scopewake import compliance as comp
from scopewake.cli import main
from scopewake.diff import normalize
from scopewake.report import to_json
from scopewake.scanner import scan
from scopewake.scoring import score_all
from test_scopewake import ALL_FAKES, build_fixture, snapshot

D0, D1 = date(2026, 10, 23), date(2026, 10, 24)


def run(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(argv)
    return code, buf.getvalue()


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.tmp = Path(self._t.name)
        self.home, self.proj = build_fixture(self.tmp)

    def tearDown(self):
        self._t.cleanup()

    def report(self):
        agents = score_all(scan(self.proj, self.home))
        return agents, normalize(json.loads(to_json(agents)))

    def ledger(self, **kw):
        _, rep = self.report()
        args = dict(owner="Ops", scope="read invoices", valid_days=365)
        args.update(kw)
        return apv.approve(apv.empty_ledger(), rep, "Invoice reader", ["cursor"], "Jane Tan", D0, **args)

    def add_payments_server(self):
        p = self.home / ".cursor" / "mcp.json"
        m = json.loads(p.read_text())
        m["mcpServers"]["payments"] = {"url": "https://pay.example.com/mcp", "headers": {"Authorization": "Bearer x"}}
        p.write_text(json.dumps(m))

    def test_unchanged_reach_is_current(self):
        led = self.ledger()
        res = apv.review(led, self.report()[1], D1)
        self.assertEqual(res["approvals"][0]["status"], "current")
        self.assertEqual(len(res["unapproved_agents"]), 2)
        self.assertTrue(apv.needs_action(res))  # unapproved agents still need action

    def test_new_authority_requires_re_review_with_reference(self):
        led = self.ledger()
        self.add_payments_server()
        r = apv.review(led, self.report()[1], D1)["approvals"][0]
        self.assertEqual(r["status"], "re-review required")
        types = {x["type"] for x in r["reasons"]}
        self.assertIn("MCP server added", types)
        self.assertTrue(all(x["ref"] == apv.REF_CHANGE for x in r["reasons"] if x.get("review")))

    def test_low_severity_addition_still_breaks_scope(self):
        # Scope test, not severity test: any added credential counts.
        led = self.ledger()
        p = self.home / ".cursor" / "mcp.json"
        m = json.loads(p.read_text())
        m["mcpServers"]["files"]["env"] = {"NEW_VAR": "1"}
        p.write_text(json.dumps(m))
        r = apv.review(led, self.report()[1], D1)["approvals"][0]
        self.assertEqual(r["status"], "re-review required")
        self.assertTrue(any(x["type"] == "MCP server changed" and "NEW_VAR" in x["detail"] for x in r["reasons"]))

    def test_removal_alone_does_not_require_review(self):
        led = self.ledger()
        p = self.home / ".cursor" / "mcp.json"
        m = json.loads(p.read_text())
        del m["mcpServers"]["pay"]
        p.write_text(json.dumps(m))
        r = apv.review(led, self.report()[1], D1)["approvals"][0]
        self.assertEqual(r["status"], "current")
        self.assertTrue(any(x["type"] == "MCP server removed" for x in r["reasons"]))

    def test_expiry_and_expiring_soon(self):
        led = self.ledger(valid_days=30)
        rep = self.report()[1]
        self.assertEqual(apv.review(led, rep, date(2026, 11, 1))["approvals"][0]["status"], "expiring soon")
        self.assertEqual(apv.review(led, rep, date(2026, 12, 1))["approvals"][0]["status"], "evidence expired")

    def test_missing_agent_is_verify_not_current(self):
        led = self.ledger()
        (self.home / ".cursor" / "mcp.json").unlink()
        r = apv.review(led, self.report()[1], D1)["approvals"][0]
        self.assertEqual(r["status"], "verify")

    def test_incomplete_scan_cannot_be_current(self):
        led = self.ledger()
        _, rep = self.report()
        rep["complete"] = False
        self.assertEqual(apv.review(led, rep, D1)["approvals"][0]["status"], "verify")

    def test_renewal_keeps_history(self):
        led = self.ledger()
        self.add_payments_server()
        led2 = apv.approve(led, self.report()[1], "invoice reader", ["cursor"], "CRO", D1)
        self.assertEqual(len(led2["approvals"]), 1)
        a = led2["approvals"][0]
        self.assertEqual(len(a["history"]), 1)
        self.assertEqual(a["history"][0]["approved_by"], "Jane Tan")
        self.assertEqual(a["scope"], "read invoices")
        self.assertEqual(apv.review(led2, self.report()[1], D1)["approvals"][0]["status"], "current")

    def test_no_secret_values_in_ledger_or_outputs(self):
        led = self.ledger()
        res = apv.review(led, self.report()[1], D1)
        text = json.dumps(led) + json.dumps(res) + apv.review_csv(res) + apv.review_text(res)
        for fake in ALL_FAKES:
            self.assertNotIn(fake, text)

    def test_markdown_reasons_are_list_items(self):
        led = self.ledger()
        self.add_payments_server()
        md = apv.review_text(apv.review(led, self.report()[1], D1), markdown=True)
        self.assertIn("\n- **MCP server added**", md)

    def test_unknown_agent_selector_is_an_error(self):
        with self.assertRaises(ValueError):
            apv.approve(apv.empty_ledger(), self.report()[1], "X", ["nope"], "A", D0)

    def test_ledger_validation(self):
        bad = self.tmp / "bad.json"
        for content in ("[]", json.dumps({"kind": "approvals", "approvals": [{"system": "x"}]}), "{not json"):
            bad.write_text(content)
            with self.assertRaises(ValueError):
                apv.load_ledger(str(bad))

    def test_compliance_change_review_control(self):
        agents, rep = self.report()
        def status(review):
            pack = comp.build_pack(agents, None, ["mas-airm"], None, review)
            return {c["ref"]: c["status"] for c in pack["frameworks"][0]["controls"]}["paras 5.24-5.25"]
        self.assertEqual(status(None), "gap")
        led = self.ledger()
        for sel, name in (("claude-code", "Coding"), ("github-action", "CI")):
            led = apv.approve(led, rep, name, [sel], "Jane Tan", D0)
        self.assertEqual(status(apv.review(led, rep, D1)), "evidenced")
        self.add_payments_server()
        self.assertEqual(status(apv.review(led, self.report()[1], D1)), "gap")

    def test_cli_round_trip_is_read_only_and_gates(self):
        before = snapshot(self.tmp)
        code, out = run(["approve", str(self.proj), "--home", str(self.home), "--system", "Invoice reader",
                         "--agent", "cursor", "--by", "Jane Tan", "--today", "2026-10-23"])
        self.assertEqual(code, 0)
        self.assertEqual(snapshot(self.tmp), before)  # approve prints; it writes nothing
        led = self.tmp / "approvals.json"
        led.write_text(out)
        code, _ = run(["review", str(self.proj), "--home", str(self.home), "--ledger", str(led), "--today", "2026-10-24"])
        self.assertEqual(code, 0)
        self.add_payments_server()
        code, out = run(["review", str(self.proj), "--home", str(self.home), "--ledger", str(led),
                         "--today", "2026-10-24", "--fail-on-review", "--format", "json"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["approvals"][0]["status"], "re-review required")
        code, out = run(["review", "--report", str(led), "--ledger", str(led)])
        self.assertEqual(code, 2)  # a ledger is not a scan report
        code, out = run(["review", str(self.proj), "--home", str(self.home), "--ledger", str(led), "--format", "csv"])
        self.assertTrue(out.startswith("system,status,owner"))

    def test_saved_report_works_like_live_scan(self):
        code, out = run(["scan", str(self.proj), "--home", str(self.home), "--format", "json"])
        rep = self.tmp / "scan.json"
        rep.write_text(out)
        code, out = run(["approve", "--report", str(rep), "--system", "S", "--agent", "Cursor", "--by", "A", "--today", "2026-10-23"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["approvals"][0]["agents"], ["Cursor"])


if __name__ == "__main__":
    unittest.main()
