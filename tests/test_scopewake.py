import json
import os
import socket
import tempfile
import unittest
from pathlib import Path

from scopewake.report import to_json, to_markdown, to_mermaid, to_sarif, to_text
from scopewake.scanner import scan
from scopewake.scoring import score_all

# Fake secrets are assembled at runtime so no real-looking secret sits in the repo.
FAKE_GH = "ghp_" + "A1b2C3d4E5" * 3 + "F6g7H8"
FAKE_AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
FAKE_STRIPE = "sk_live_" + "x9y8z7w6v5u4t3s2r1"
FAKE_DB = "postgres://admin:" + "hunter2hunter2" + "@db.internal/app"
ALL_FAKES = [FAKE_GH, FAKE_AWS, FAKE_STRIPE, "hunter2hunter2"]


def build_fixture(tmp: Path):
    home, proj = tmp / "home", tmp / "proj"
    (home / ".aws").mkdir(parents=True)
    (home / ".aws" / "credentials").write_text(f"[default]\naws_access_key_id = {FAKE_AWS}\naws_secret_access_key = abc\n")
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_ed25519").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n")
    (home / ".claude").mkdir()
    (home / ".claude" / "settings.json").write_text(json.dumps({"permissions": {"defaultMode": "bypassPermissions"}}))
    (home / ".cursor").mkdir()
    (home / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {
        "github": {"command": "npx", "args": ["@modelcontextprotocol/server-github"], "env": {"GITHUB_TOKEN": FAKE_GH}},
        "files": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/"]},
        "pay": {"command": "node", "args": ["stripe-mcp"], "env": {"STRIPE_API_KEY": FAKE_STRIPE}},
    }}))
    (proj / ".github" / "workflows").mkdir(parents=True)
    (proj / ".github" / "workflows" / "agent.yml").write_text(
        "on:\n  issue_comment:\n    types: [created]\npermissions:\n  contents: write\njobs:\n  a:\n    steps:\n"
        "      - uses: anthropics/claude-code-action@v1\n        env:\n          K: ${{ secrets.PROD_DEPLOY_KEY }}\n")
    (proj / ".env").write_text(f"DATABASE_URL={FAKE_DB}\nNAME=demo\n")
    return home, proj


def snapshot(root: Path):
    return sorted((str(p), p.stat().st_mtime_ns, p.stat().st_size) for p in root.rglob("*") if p.is_file())


class ScopewakeTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.tmp = Path(self._t.name)
        self.home, self.proj = build_fixture(self.tmp)

    def tearDown(self):
        self._t.cleanup()

    def run_scan(self):
        return score_all(scan(self.proj, self.home))

    def test_finds_and_ranks_agents(self):
        agents = self.run_scan()
        names = {a.name for a in agents}
        self.assertIn("Claude Code", names)
        self.assertIn("Cursor", names)
        self.assertTrue(any(a.kind == "github-action" for a in agents))
        self.assertEqual([a.score for a in agents], sorted((a.score for a in agents), reverse=True))
        self.assertTrue(all(0 <= a.score <= 100 for a in agents))

    def test_bypass_mode_scores_high_autonomy(self):
        cc = next(a for a in self.run_scan() if a.kind == "claude-code")
        self.assertEqual(cc.autonomy, 1.0)

    def test_detects_literal_secret_kinds_and_ambient(self):
        cur = next(a for a in self.run_scan() if a.kind == "cursor")
        kinds = {c.kind for c in cur.credentials}
        self.assertIn("github-token", kinds)
        self.assertIn("stripe-live-key", kinds)
        self.assertIn("aws-credentials-file", kinds)
        self.assertIn("db-url-with-password", kinds)

    def test_workflow_untrusted_trigger_and_secret_reference(self):
        wf = next(a for a in self.run_scan() if a.kind == "github-action")
        self.assertTrue(any(c.name == "untrusted-trigger" for c in wf.capabilities))
        self.assertTrue(any(c.how == "secrets-reference" and c.name == "PROD_DEPLOY_KEY" for c in wf.credentials))
        self.assertEqual(wf.exposure, 1.0)

    def test_deny_rule_mitigates(self):
        (self.home / ".claude" / "settings.json").write_text(json.dumps({"permissions": {"defaultMode": "default", "deny": ["Read(**/.env*)", "Read(~/.aws/**)"]}}))
        cc = next(a for a in self.run_scan() if a.kind == "claude-code")
        aws = [c for c in cc.credentials if c.kind == "aws-credentials-file"]
        env = [c for c in cc.credentials if c.kind == "db-url-with-password"]
        self.assertTrue(aws and all(c.mitigated for c in aws))
        self.assertTrue(env and all(c.mitigated for c in env))

    def test_no_secret_value_in_any_output(self):
        agents = self.run_scan()
        blob = to_json(agents) + to_markdown(agents) + to_text(agents) + to_mermaid(agents) + to_sarif(agents)
        for fake in ALL_FAKES:
            self.assertNotIn(fake, blob)

    def test_mermaid_graph_shape(self):
        m = to_mermaid(self.run_scan())
        self.assertTrue(m.startswith("flowchart LR"))
        self.assertIn("-->", m)
        self.assertIn("severity 9", m)
        self.assertNotIn('"', m.split("\n")[1])

    def test_sarif_valid_and_levels(self):
        doc = json.loads(to_sarif(self.run_scan()))
        self.assertEqual(doc["version"], "2.1.0")
        res = doc["runs"][0]["results"]
        self.assertTrue(res and all(r["ruleId"] in ("LM001", "LM002") for r in res))
        self.assertIn("error", {r["level"] for r in res})
        for r in res:
            for loc in r.get("locations", []):
                uri = loc["physicalLocation"]["artifactLocation"]["uri"]
                self.assertFalse(uri.startswith(("/", "~")), uri)

    def test_cli_formats_and_fail_above(self):
        from scopewake import cli
        import io, contextlib
        for fmt in ("text", "json", "md", "mermaid", "sarif"):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main(["scan", str(self.proj), "--home", str(self.home), "--format", fmt])
            self.assertEqual(rc, 0)
            self.assertTrue(buf.getvalue().strip())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["scan", str(self.proj), "--home", str(self.home), "--fail-above", "50"]), 1)
            self.assertEqual(cli.main(["scan", str(self.proj), "--home", str(self.home), "--fail-above", "99"]), 0)

    def test_hostile_inputs_do_not_crash(self):
        """Malformed, huge, deeply nested or wrongly typed config files must not crash the scan."""
        h, p = self.home, self.proj
        (h / ".claude").mkdir(exist_ok=True)
        (h / ".claude" / "settings.json").write_text("[" * 5000 + "]" * 5000)
        (h / ".codex").mkdir(exist_ok=True)
        (h / ".codex" / "config.toml").write_text("[[[bad toml\n" + "x=" * 10)
        (h / ".claude.json").write_text(json.dumps({"mcpServers": {
            "a": {"env": "notadict", "args": 5, "command": None}, "b": "str", "c": [1],
            "d": {"env": {"K": [1, 2]}, "args": [{"x": 1}], "url": 5, "headers": "s"}}}))
        (h / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": [1, 2], "servers": {"z": {"env": 5}}}))
        (p / ".github" / "workflows" / "bad.yml").write_text("\t\t: : bad yaml\n" + "- " * 100000)
        (p / ".github" / "workflows" / "bin.yml").write_bytes(b"\xff\xfe\x00\x00 uses: anthropics/claude-code-action")
        (p / ".env.local").write_bytes(b"\x00\x01=\n=\n==\nA")
        agents = self.run_scan()
        self.assertIsInstance(agents, list)

    def test_no_network_during_scan_and_report(self):
        real = socket.socket

        def boom(*a, **k):
            raise AssertionError("network access attempted")
        socket.socket = boom
        try:
            agents = self.run_scan()
            to_json(agents), to_markdown(agents), to_text(agents)
        finally:
            socket.socket = real

    def test_scan_is_read_only(self):
        before = snapshot(self.tmp)
        self.run_scan()
        self.assertEqual(before, snapshot(self.tmp))

    def test_empty_home_has_no_agents(self):
        with tempfile.TemporaryDirectory() as e:
            self.assertEqual(score_all(scan(Path(e), Path(e))), [])

    def test_symlink_not_followed(self):
        target = self.tmp / "outside.json"
        target.write_text(json.dumps({"mcpServers": {"x": {"command": "bash"}}}))
        (self.proj / ".mcp.json").symlink_to(target)
        agents = self.run_scan()
        cc = next(a for a in agents if a.kind == "claude-code")
        self.assertFalse(any("mcp:x" == c.via for c in cc.capabilities))


    def test_trifecta_flags(self):
        agents = {a.kind: a for a in self.run_scan()}
        cursor = next(a for a in agents.values() if "cursor" in a.kind)
        self.assertTrue(cursor.trifecta, cursor.trifecta_parts)
        self.assertIn("mcp:github", cursor.trifecta_parts["untrusted_input"])
        self.assertTrue(cursor.fixes[0].startswith("Potential lethal trifecta"))
        self.assertTrue(agents["github-action"].trifecta)
        self.assertFalse(agents["claude-code"].trifecta)
        sarif = json.loads(to_sarif(list(agents.values())))
        self.assertIn("LM002", {r["ruleId"] for r in sarif["runs"][0]["results"]})

    def test_diff_detects_increase_and_decrease(self):
        from scopewake.cli import main
        from scopewake.diff import diff_reports
        a, b = self.tmp / "a.json", self.tmp / "b.json"
        a.write_text(to_json(self.run_scan()))
        cfg = self.home / ".cursor" / "mcp.json"
        data = json.loads(cfg.read_text())
        data["mcpServers"]["chat"] = {"command": "npx", "args": ["slack-mcp"], "env": {"SLACK_BOT_TOKEN": "xoxb-" + "1" * 20}}
        cfg.write_text(json.dumps(data))
        b.write_text(to_json(self.run_scan()))
        up = diff_reports(str(a), str(b))
        self.assertTrue(up["worse"])
        ch = next(c for c in up["changed"] if any(x[0] == "slack" for x in c["capabilities_added"]))
        self.assertTrue(ch["credentials_added"])
        self.assertFalse(diff_reports(str(b), str(a))["worse"])
        self.assertFalse(diff_reports(str(a), str(a))["worse"])
        self.assertEqual(main(["diff", str(a), str(b), "--fail-on-increase"]), 1)
        self.assertEqual(main(["diff", str(b), str(a), "--fail-on-increase"]), 0)
        bad = self.tmp / "bad.json"
        bad.write_text("[1,2]")
        self.assertEqual(main(["diff", str(bad), str(a)]), 2)
        for out in (to_json(self.run_scan()),):
            for fake in ALL_FAKES + ["xoxb-" + "1" * 20]:
                self.assertNotIn(fake, out)

if __name__ == "__main__":
    unittest.main()


import ast

FORBIDDEN_MODULES = {"socket", "ssl", "http", "urllib", "requests", "ftplib", "smtplib", "subprocess", "shutil", "multiprocessing",
                     "ctypes", "telnetlib", "xmlrpc", "webbrowser", "asyncio", "pickle", "importlib", "tempfile"}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__", "open", "input"}
FORBIDDEN_ATTR_CALLS = {"system", "popen", "write_text", "write_bytes", "touch", "unlink", "rmdir", "mkdir", "makedirs",
                        "rename", "remove", "removedirs", "chmod", "chown", "symlink_to", "hardlink_to", "truncate",
                        "writelines", "fdopen", "putenv", "fork", "kill", "startfile"}
FORBIDDEN_NAMES_FROM_OS = FORBIDDEN_ATTR_CALLS | {"popen", "spawnl", "execv", "execvp"}
WRITE_FLAGS = {"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"}


def policy_violations(source: str):
    """AST policy: no network, subprocess, dynamic code, or write-capable calls. Bounded evidence, not a proof."""
    bad = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            bad += [f"import {a.name}" for a in node.names if a.name.split(".")[0] in FORBIDDEN_MODULES]
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            if mod in FORBIDDEN_MODULES:
                bad.append(f"from {node.module} import ...")
            if mod == "os":
                bad += [f"from os import {a.name}" for a in node.names if a.name in FORBIDDEN_NAMES_FROM_OS or a.name in ("open", "*")]
        elif isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name):
                if f.id in FORBIDDEN_CALLS:
                    bad.append(f"call {f.id}()")
                if f.id == "getattr" and not (len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)
                                              and str(node.args[1].value).startswith("O_")):
                    bad.append("dynamic getattr()")
                if f.id in ("setattr", "delattr", "globals", "locals", "vars"):
                    bad.append(f"call {f.id}()")
            elif isinstance(f, ast.Attribute) and f.attr in FORBIDDEN_ATTR_CALLS:
                bad.append(f"call .{f.attr}()")
        elif isinstance(node, ast.Attribute) and node.attr in WRITE_FLAGS:
            bad.append(f"write flag {node.attr}")
    return bad


class SourcePolicyTests(unittest.TestCase):
    """Release gate: the package must contain no network, subprocess, dynamic-code or write-capable code."""

    def test_package_is_clean(self):
        pkg = Path(__file__).resolve().parent.parent / "scopewake"
        files = list(pkg.rglob("*.py"))
        self.assertTrue(files)
        for f in files:
            self.assertEqual(policy_violations(f.read_text()), [], f.name)

    def test_policy_catches_known_bypasses(self):
        for snippet in ("from socket import socket", "from subprocess import run", "from pathlib import Path\nPath('x').touch()",
                        "from os import remove", "import os\nos.open('x', os.O_WRONLY)", "compile('x=1','x','exec')",
                        "getattr(os, 'sys' + 'tem')", "import urllib.request", "open('x','w')", "__import__('socket')"):
            self.assertTrue(policy_violations(snippet), snippet)


class LegacyNameTest(unittest.TestCase):
    def test_diff_accepts_reports_from_tideline(self):
        from scopewake.diff import normalize
        legacy = {"tool": "tideline", "version": "0.2.0", "schema": 1, "agents": []}
        self.assertIsInstance(normalize(legacy), dict)  # a stored tideline baseline still loads

    def test_diff_rejects_other_tools(self):
        from scopewake.diff import normalize
        with self.assertRaises(Exception):
            normalize({"tool": "something-else", "agents": []})
