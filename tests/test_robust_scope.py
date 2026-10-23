"""Tests for MCP change detection, the evidence pack and managed-settings fixes."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from tideline import compliance as comp
from tideline.cli import main
from tideline.fix import fixes
from tideline.report import to_json
from tideline.scanner import scan, server_fingerprint
from tideline.scoring import score_all
from tideline.diff import diff_reports
from test_tideline import ALL_FAKES, FAKE_GH, build_fixture


def run(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(argv)
    return code, buf.getvalue()


class FingerprintTests(unittest.TestCase):
    def test_no_secret_values_in_fingerprint(self):
        fp = server_fingerprint("gh", {"command": "npx", "args": ["--token", FAKE_GH],
                                       "env": {"GITHUB_TOKEN": FAKE_GH}, "url": None})
        text = json.dumps(fp)
        self.assertNotIn(FAKE_GH, text)
        self.assertEqual(fp["env_names"], ["GITHUB_TOKEN"])
        self.assertEqual(fp["transport"], "local")

    def test_remote_endpoint_keeps_host_only(self):
        fp = server_fingerprint("r", {"url": "https://user:pw@api.example.com:8443/mcp?token=abc123"})
        self.assertEqual(fp["endpoint"], "https://api.example.com:8443")
        self.assertNotIn("abc123", json.dumps(fp))
        self.assertNotIn("pw", fp["endpoint"])

    def test_args_hash_ignores_secret_but_tracks_change(self):
        a = server_fingerprint("s", {"command": "npx", "args": ["pkg@1"]})
        b = server_fingerprint("s", {"command": "npx", "args": ["pkg@2"]})
        self.assertNotEqual(a["args_hash"], b["args_hash"])
        self.assertNotEqual(a["fingerprint"], b["fingerprint"])


class ChangeIntelligenceTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.tmp = Path(self._t.name)
        self.home, self.proj = build_fixture(self.tmp)

    def tearDown(self):
        self._t.cleanup()

    def report(self, name):
        p = self.tmp / name
        p.write_text(to_json(score_all(scan(self.proj, self.home))))
        return str(p)

    def edit_cursor(self, fn):
        cfg = self.home / ".cursor" / "mcp.json"
        data = json.loads(cfg.read_text())
        fn(data["mcpServers"])
        cfg.write_text(json.dumps(data))

    def test_endpoint_change_is_flagged_as_worse(self):
        self.edit_cursor(lambda s: s.update({"remote": {"url": "https://a.example.com/mcp"}}))
        old = self.report("old.json")
        self.edit_cursor(lambda s: s["remote"].update({"url": "https://b.evil.example/mcp"}))
        new = self.report("new.json")
        d = diff_reports(old, new)
        self.assertTrue(d["worse"])
        changed = [sv for c in d["changed"] for sv in c["servers_changed"]]
        self.assertTrue(any("endpoint" in w for sv in changed for w in sv["changes"]))

    def test_new_server_and_new_env_name_flagged(self):
        old = self.report("old.json")
        def change(s):
            s["files"]["env"] = {"EXTRA_KEY": "${X}"}
            s["new"] = {"command": "npx", "args": ["something"]}
        self.edit_cursor(change)
        d = diff_reports(old, self.report("new.json"))
        self.assertTrue(d["worse"])
        c = next(c for c in d["changed"] if c["servers_added"] or c["servers_changed"])
        self.assertEqual([s["server"] for s in c["servers_added"]], ["new"])
        self.assertTrue(any("new env var EXTRA_KEY" in w for sv in c["servers_changed"] for w in sv["changes"]))

    def test_old_reports_without_servers_still_load(self):
        old = self.report("old.json")
        data = json.loads(Path(old).read_text())
        for a in data["agents"]:
            a.pop("servers", None)
        Path(old).write_text(json.dumps(data))
        diff_reports(old, self.report("new.json"))


class EvidencePackTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.tmp = Path(self._t.name)
        self.home, self.proj = build_fixture(self.tmp)
        self.agents = score_all(scan(self.proj, self.home))

    def tearDown(self):
        self._t.cleanup()

    def test_without_inventory_inventory_is_a_gap(self):
        pack = comp.build_pack(self.agents, None, ["mas-airm"])
        status = {c["ref"]: c["status"] for c in pack["frameworks"][0]["controls"]}
        self.assertEqual(status["para 4.7"], "gap")
        self.assertEqual(status["para 4.8, fn 25"], "evidenced")
        self.assertEqual(status["para 4.2, fn 21"], "partial")  # SaaS AI not declared

    def test_complete_inventory_is_evidenced_and_declared_saas_counts(self):
        def row(**k):
            r = {f: "x" for f in comp.INVENTORY_FIELDS}
            r.update(k)
            return r
        rows = [row(match=a.id, materiality="high") for a in self.agents]
        rows.append(row(name="CRM AI assistant", materiality="low"))
        inv = {"organisation": "Test", "systems": rows, "approved_tools": []}
        pack = comp.build_pack(self.agents, inv, ["mas-airm"])
        status = {c["ref"]: c["status"] for c in pack["frameworks"][0]["controls"]}
        self.assertEqual(status["para 4.7"], "evidenced")
        self.assertEqual(status["para 4.2, fn 21"], "evidenced")
        self.assertEqual(status["section 4"], "evidenced")
        self.assertEqual(status["paras 2.3-2.5"], "gap")  # empty approved list

    def test_bypass_agent_is_oversight_gap_and_no_secrets_in_pack(self):
        pack = comp.build_pack(self.agents, None, list(comp.FRAMEWORKS))
        eu = next(f for f in pack["frameworks"] if f["framework"] == "eu-ai-act")
        self.assertEqual(eu["controls"][0]["status"], "gap")
        self.assertTrue(eu["review"].startswith("DRAFT"))
        text = json.dumps(pack) + comp.pack_markdown(pack)
        for s in ALL_FAKES:
            self.assertNotIn(s, text)

    def test_empty_scan_is_never_evidenced(self):
        pack = comp.build_pack([], None, ["nydfs"])
        self.assertTrue(all(c["status"] != "evidenced" for c in pack["frameworks"][0]["controls"]))

    def test_cli_template_round_trip(self):
        code, out = run(["compliance", str(self.proj), "--home", str(self.home), "--inventory-template"])
        self.assertEqual(code, 0)
        inv_path = self.tmp / "inv.json"
        inv_path.write_text(out)
        code, md = run(["compliance", str(self.proj), "--home", str(self.home), "--inventory", str(inv_path), "--framework", "all"])
        self.assertEqual(code, 0)
        self.assertIn("MAS Guidelines on AI Risk Management", md)
        self.assertLess(md.index("MAS Guidelines"), md.index("EU AI Act"))

    def test_bad_inventory_fails_cleanly(self):
        bad = self.tmp / "bad.json"
        bad.write_text("[1,2]")
        self.assertEqual(run(["compliance", str(self.proj), "--home", str(self.home), "--inventory", str(bad)])[0], 2)


class OidcContextTests(unittest.TestCase):
    def _agent(self, on, perms):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "p"
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "a.yml").write_text(
                f"on:\n  {on}:\npermissions:\n  {perms}\njobs:\n  a:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n")
            agents = score_all(scan(root, Path(d) / "h"))
        return next(a for a in agents if a.kind == "github-action")

    def test_id_token_alone_is_not_elevated_write(self):
        a = self._agent("push", "id-token: write")
        names = {c.name: c.severity for c in a.capabilities}
        self.assertNotIn("elevated-token-permissions", names)
        self.assertEqual(names["oidc-token-request"], 4)

    def test_id_token_with_untrusted_trigger_is_high(self):
        a = self._agent("issue_comment", "id-token: write")
        self.assertEqual({c.name: c.severity for c in a.capabilities}["oidc-token-request"], 7)
        self.assertTrue(any("trust policy" in f for f in a.fixes))


class FixTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.tmp = Path(self._t.name)
        self.home, self.proj = build_fixture(self.tmp)

    def tearDown(self):
        self._t.cleanup()

    def test_fix_denies_credential_dirs_and_bypass(self):
        out = fixes(score_all(scan(self.proj, self.home)))
        perms = out["claude_code_managed_settings"]["permissions"]
        self.assertIn("Read(~/.aws/**)", perms["deny"])
        self.assertIn("Read(~/.ssh/**)", perms["deny"])
        self.assertIn("Read(./.env)", perms["deny"])
        self.assertEqual(perms["disableBypassPermissionsMode"], "disable")
        self.assertNotIn(FAKE_GH, json.dumps(out))

    def test_cli_fix_is_json(self):
        code, out = run(["fix", str(self.proj), "--home", str(self.home)])
        self.assertEqual(code, 0)
        self.assertIn("claude_code_managed_settings", json.loads(out))


if __name__ == "__main__":
    unittest.main()
