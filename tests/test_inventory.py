"""Tests for importing agent inventories (Defender XDR AgentsInfo exports, generic CSV/JSON) and merging reports."""
import csv
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from datetime import date
from pathlib import Path

from scopewake import approvals as apv
from scopewake import inventory as inv
from scopewake.cli import main
from scopewake.diff import normalize
from test_scopewake import build_fixture

COLS = ["Timestamp", "AgentId", "AgentName", "Platform", "LifecycleStatus", "DeclaredTools", "DeclaredDataSources",
        "Permissions", "McpServers", "ConnectedAgents", "Availability", "Owners", "Instructions"]


def row(**kw):
    base = {"Timestamp": "2026-11-01T00:00:00Z", "AgentId": "a1", "AgentName": "Invoice helper", "Platform": "CopilotStudio",
            "LifecycleStatus": "Active", "DeclaredTools": json.dumps([{"name": "SendEmail"}]),
            "DeclaredDataSources": json.dumps([{"displayName": "Finance SharePoint"}]), "Permissions": "[]",
            "McpServers": "[]", "ConnectedAgents": "[]", "Availability": "SpecificGroups",
            "Owners": json.dumps([{"displayName": "Jane Tan"}]), "Instructions": "SECRET SYSTEM PROMPT"}
    base.update(kw)
    return base


def write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        w.writerows(rows)


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue()


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.tmp = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def test_defender_export_imports_latest_active_and_drops_prompts(self):
        p = self.tmp / "agents.csv"
        write_csv(p, [row(), row(Timestamp="2026-11-02T00:00:00Z", DeclaredTools=json.dumps([{"name": "SendEmail"}, {"name": "Pay"}])),
                      row(AgentId="a2", AgentName="Old bot", LifecycleStatus="Deleted")])
        rep = inv.import_inventory(str(p))
        self.assertEqual(len(rep["agents"]), 1)
        caps = {c["name"].split("#")[0] for c in rep["agents"][0]["capabilities"]}
        self.assertIn("tool:Pay", caps)
        self.assertIn("data:Finance SharePoint", caps)
        self.assertNotIn("SECRET", json.dumps(rep))
        self.assertEqual(rep["agents"][0]["kind"], "copilotstudio")
        normalize(rep)  # valid report

    def test_new_mcp_server_on_imported_agent_needs_re_review(self):
        p = self.tmp / "agents.csv"
        write_csv(p, [row()])
        before = normalize(inv.import_inventory(str(p)))
        led = apv.approve(apv.empty_ledger(), before, "Invoice helper", ["Invoice helper"], "Head of Risk", date(2026, 11, 3))
        write_csv(p, [row(McpServers=json.dumps([{"name": "payments", "url": "https://pay.example.com/mcp"}]))])
        after = normalize(inv.import_inventory(str(p)))
        r = apv.review(led, after, date(2026, 11, 4))["approvals"][0]
        self.assertEqual(r["status"], "re-review required")
        self.assertEqual(apv.verify_ledger(led)["status"], "intact")

    def test_wider_audience_needs_re_review(self):
        p = self.tmp / "agents.csv"
        write_csv(p, [row()])
        led = apv.approve(apv.empty_ledger(), normalize(inv.import_inventory(str(p))), "Invoice helper", ["Invoice helper"],
                          "Head of Risk", date(2026, 11, 3))
        write_csv(p, [row(Availability="AllUsers")])
        r = apv.review(led, normalize(inv.import_inventory(str(p))), date(2026, 11, 4))["approvals"][0]
        self.assertEqual(r["status"], "re-review required")

    def test_generic_csv_with_map_and_merge_with_scan(self):
        p = self.tmp / "custom.csv"
        p.write_text("Agent,Owner,Tools\nClaims triage,Ops,read_claims;approve_payout\n", encoding="utf-8")
        code, out = run(["import", str(p), "--source", "generic", "--map", "name=Agent", "--map", "owner=Owner",
                         "--map", "tools=Tools", "--platform", "in-house"])
        self.assertEqual(code, 0)
        imp = self.tmp / "imp.json"
        imp.write_text(out)
        home, proj = build_fixture(self.tmp / "fx")
        code, scan_out = run(["scan", str(proj), "--home", str(home), "--format", "json"])
        sc = self.tmp / "scan.json"
        sc.write_text(scan_out)
        code, merged = run(["merge", str(sc), str(imp)])
        self.assertEqual(code, 0)
        m = normalize(json.loads(merged))
        self.assertTrue(any(k[0] == "in-house" for k in m["agents"]))
        self.assertTrue(any(k[0] == "cursor" for k in m["agents"]))
        code, ev = run(["evidence", str(proj), "--home", str(home), "--framework", "none", "--include", str(imp)])
        self.assertEqual(code, 0)
        self.assertIn("imported.json", json.loads(ev)["files"])

    def test_bad_inputs(self):
        p = self.tmp / "x.csv"
        p.write_text("Foo\nbar\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            inv.import_inventory(str(p))
        with self.assertRaises(ValueError):
            inv.parse_map(["nonsense=Col"])
        with self.assertRaises(ValueError):
            inv.merge_reports([{"tool": "other"}])


if __name__ == "__main__":
    unittest.main()
