"""Regressions for defects reported by the second Codex audit (N01-N17), written against the stated behaviour."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from tideline import scanner
from tideline.cli import main
from tideline.diff import diff_reports
from tideline.report import to_json, to_markdown, to_mermaid, to_sarif, to_text
from tideline.scanner import classify_server, scan
from tideline.scoring import score_all

T = "ghp_" + "Q" * 36
ALL = (to_json, to_text, to_markdown, to_mermaid, to_sarif)


def write(p: Path, d):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(d if isinstance(d, str) else json.dumps(d))


class ReAudit(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.t = Path(self._t.name)
        self.h, self.p = self.t / "home", self.t / "proj"
        self.h.mkdir()
        self.p.mkdir()

    def tearDown(self):
        self._t.cleanup()

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def scan(self):
        return score_all(scan(self.p, self.h))

    def assert_clean(self, agents, secret=T):
        for f in ALL:
            self.assertNotIn(secret, f(agents), f.__name__)

    # --- N01 / N10: redaction of every field and of escaped / disguised secrets
    def test_n01_newline_in_workflow_filename(self):
        write(self.p / ".github/workflows" / ("prefix\n" + T + ".yml"),
              "on:\n  issue_comment:\n    types: [created]\njobs:\n  a:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n")
        self.assert_clean(self.scan())

    def test_n01_prefixed_zero_width_and_fullwidth_forms(self):
        zw = "ghp_" + "\u200b" + "Q" * 36
        fw = "ｇｈｐ＿" + "Q" * 36
        for name in ("x" + T, zw, fw):
            write(self.p / ".mcp.json", {"mcpServers": {name: {"command": "fetch"}}})
            agents = self.scan()
            for f in ALL:
                out = f(agents)
                self.assertNotIn("Q" * 36, out, (name, f.__name__))

    def test_n10_pem_body_is_redacted(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAfakefakefake\n-----END RSA PRIVATE KEY-----"
        write(self.p / ".mcp.json", {"mcpServers": {pem: {"command": "fetch"}}})
        self.assert_clean(self.scan(), "MIIEowIBAAKCAQEAfakefakefake")

    # --- N02: diff outputs and errors
    def test_n02_diff_and_errors_do_not_echo_secrets(self):
        old, new = self.t / "old.json", self.t / "new.json"
        write(old, {"tool": "tideline", "agents": []})
        write(new, {"tool": "tideline", "agents": [{"kind": "cursor", "name": T, "score": 1}]})
        for fmt in ("text", "json"):
            rc, out, err = self.cli("diff", str(old), str(new), "--format", fmt)
            self.assertNotIn(T, out + err)
        rc, out, err = self.cli("diff", str(self.t / T), str(new))
        self.assertEqual(rc, 2)
        self.assertNotIn(T, out + err)

    # --- N03: nothing may look complete when it was not analysed
    def test_n03_wrong_shapes_make_scan_incomplete(self):
        cases = {
            "top-level array": "[]", "null": "null", "servers not object": json.dumps({"mcpServers": []}),
            "server not object": json.dumps({"mcpServers": {"a": 5}}),
            "args not list": json.dumps({"mcpServers": {"a": {"command": "x", "args": 7}}}),
            "env not object": json.dumps({"mcpServers": {"a": {"command": "x", "env": []}}}),
        }
        for label, body in cases.items():
            write(self.h / ".cursor/mcp.json", body)
            scan(self.p, self.h)
            self.assertTrue(scanner.get_issues(), label)
        (self.h / ".cursor/mcp.json").write_bytes(b'{"mcpServers": {}}\xff')
        scan(self.p, self.h)
        self.assertTrue(scanner.get_issues(), "invalid utf-8")
        (self.h / ".cursor/mcp.json").unlink()
        (self.h / ".cursor/mcp.json").mkdir()
        scan(self.p, self.h)
        self.assertTrue(scanner.get_issues(), "directory in place of file")

    def test_n03_missing_project_root_is_incomplete(self):
        rc, _, err = self.cli("scan", str(self.t / "nope"), "--home", str(self.h), "--fail-above", "99")
        self.assertEqual(rc, 3)

    # --- N04: diff must not pass an incomplete new scan
    def test_n04_incomplete_new_scan_is_not_a_pass(self):
        write(self.h / ".cursor/mcp.json", {"mcpServers": {"a": {"command": "bash"}}})
        old, new = self.t / "o.json", self.t / "n.json"
        old.write_text(to_json(self.scan(), scanner.get_issues()))
        write(self.h / ".cursor/mcp.json", "{broken")
        new.write_text(to_json(self.scan(), scanner.get_issues()))
        self.assertEqual(self.cli("diff", str(old), str(new), "--fail-on-increase")[0], 1)

    # --- N05: a Read deny does not hide credentials from an agent that has unrestricted shell
    def test_n05_read_deny_with_bypass_mode_is_not_a_mitigation(self):
        write(self.p / ".env", "API_TOKEN=synthetic-value\n")
        write(self.h / ".claude/settings.json", {"permissions": {"defaultMode": "bypassPermissions", "deny": ["Read(**/.env)"]}})
        env = [c for c in self.scan()[0].credentials if c.location.endswith(".env")]
        self.assertTrue(env and all(c.read_denied and not c.mitigated for c in env))
        write(self.h / ".claude/settings.json", {"permissions": {"defaultMode": "default", "deny": ["Read(**/.env)"]}})
        env = [c for c in self.scan()[0].credentials if c.location.endswith(".env")]
        self.assertTrue(env and all(c.mitigated for c in env))

    # --- N06: display truncation must not erase an added tool
    def test_n06_long_names_stay_distinct(self):
        a, b = "s" * 90 + "A", "s" * 90 + "B"
        write(self.h / ".cursor/mcp.json", {"mcpServers": {a: {"command": "bash"}}})
        old, new = self.t / "o.json", self.t / "n.json"
        old.write_text(to_json(self.scan()))
        write(self.h / ".cursor/mcp.json", {"mcpServers": {a: {"command": "bash"}, b: {"command": "bash"}}})
        new.write_text(to_json(self.scan()))
        self.assertTrue(diff_reports(str(old), str(new))["worse"])

    # --- N07: strict report validation
    def test_n07_malformed_reports_exit_2(self):
        good = {"tool": "tideline", "agents": [{"kind": "cursor", "name": "Cursor", "score": 1}]}
        bads = [
            {"tool": "tideline", "agents": [{"kind": "cursor", "name": "C", "score": None}]},
            {"tool": "tideline", "agents": [{"kind": "cursor", "name": "C", "score": 1, "credentials": [{"kind": "k", "name": []}]}]},
            {"tool": "tideline", "agents": [{"kind": "cursor", "name": "C", "score": 1, "capabilities": [{"name": 5}]}]},
            {"tool": "tideline", "agents": [{"kind": "cursor", "name": "C", "score": 101}]},
            {"tool": "tideline", "agents": [{"kind": "cursor", "name": "C", "score": 1, "trifecta": "yes"}]},
            {"tool": "tideline", "agents": [{"kind": 3, "name": "C", "score": 1}]},
        ]
        g = self.t / "g.json"
        write(g, good)
        for i, b in enumerate(bads):
            f = self.t / f"b{i}.json"
            write(f, b)
            self.assertEqual(self.cli("diff", str(g), str(f))[0], 2, i)
        nan = self.t / "nan.json"
        nan.write_text('{"tool":"tideline","agents":[{"kind":"cursor","name":"C","score":NaN}]}')
        self.assertEqual(self.cli("diff", str(g), str(nan))[0], 2)

    # --- N08: identity independent of checkout path and agent order
    def test_n08_same_layout_in_two_checkouts_is_no_change(self):
        a, b = self.t / "a", self.t / "b"
        for r in (a, b):
            write(r / ".env", "API_TOKEN=synthetic-value\n")
            write(r / ".mcp.json", {"mcpServers": {"x": {"command": "bash"}}})
        fa, fb = self.t / "fa.json", self.t / "fb.json"
        fa.write_text(to_json(score_all(scan(a, self.h))))
        fb.write_text(to_json(score_all(scan(b, self.h))))
        self.assertFalse(diff_reports(str(fa), str(fb))["worse"])

    def test_n08_agent_order_does_not_matter(self):
        doc = {"tool": "tideline", "agents": [
            {"kind": "cursor", "name": "C", "source_rel": "a", "score": 5, "capabilities": [{"name": "x", "via": "1"}]},
            {"kind": "cursor", "name": "C", "source_rel": "b", "score": 5, "capabilities": [{"name": "y", "via": "2"}]}]}
        rev = {"tool": "tideline", "agents": list(reversed(doc["agents"]))}
        f1, f2 = self.t / "1.json", self.t / "2.json"
        write(f1, doc)
        write(f2, rev)
        self.assertFalse(diff_reports(str(f1), str(f2))["worse"])

    # --- N09: loops and replacement races
    def test_n09_symlink_loop_root_does_not_crash(self):
        a, b = self.t / "la", self.t / "lb"
        a.symlink_to(b)
        b.symlink_to(a)
        scan(a, self.h)
        self.assertTrue(scanner.get_issues())

    def test_n09_oversized_file_is_incomplete(self):
        write(self.h / ".cursor/mcp.json", " " * (scanner.MAX_BYTES + 10))
        scan(self.p, self.h)
        self.assertTrue(scanner.get_issues())

    # --- N11: classifier behaviour
    def test_n11_classifier(self):
        names = lambda n, c, a: [x.name for x in classify_server(n, c, a)]
        self.assertIn("shell-execution", names("x", "bash", ["-c", "run"]))
        self.assertIn("shell-execution", names("x", "/bin/bash", []))
        self.assertIn("shell-execution", names("x", "python", ["--tool=shell"]))
        self.assertNotIn("web-content", names("fs", "npx", ["@modelcontextprotocol/server-filesystem", "/project/web"]))
        self.assertIn("database", names("pg", "npx", ["server-postgresql"]))

    def test_n11_empty_env_value_is_not_a_credential(self):
        write(self.p / ".mcp.json", {"mcpServers": {"s": {"command": "fetch", "env": {"GITHUB_TOKEN": "", "API_KEY": None}}}})
        self.assertFalse([c for c in self.scan()[0].credentials if c.name in ("GITHUB_TOKEN", "API_KEY")])

    # --- N12: depth limit must be reported
    def test_n12_deep_env_file_is_reported_as_not_checked(self):
        write(self.p / "a/b/c/d/e/f/.env", "API_TOKEN=synthetic-value\n")
        scan(self.p, self.h)
        self.assertTrue(any("deeper" in i for i in scanner.get_issues()))

    # --- N13: SARIF locations
    def test_n13_sarif_uris(self):
        wf = self.p / ".github/workflows/agent #1.yml"
        write(wf, "on:\n  issue_comment:\n    types: [created]\njobs:\n  a:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n")
        write(self.h / ".cursor/mcp.json", {"mcpServers": {"x": {"command": "bash"}}})
        res = json.loads(to_sarif(self.scan()))["runs"][0]["results"]
        uris = [l["physicalLocation"]["artifactLocation"]["uri"] for r in res for l in r.get("locations", [])]
        self.assertIn(".github/workflows/agent%20%231.yml", uris)
        self.assertFalse([u for u in uris if u.startswith(("~", "/"))])
        home_res = [r for r in res if "locations" not in r]
        self.assertTrue(home_res and "~/.cursor/mcp.json" in home_res[0]["message"]["text"])

    # --- N15: markup and incomplete graph
    def test_n15_markup_and_incomplete_notice(self):
        write(self.p / ".mcp.json", {"mcpServers": {"<img src=x onerror=alert(1)>": {"command": "fetch"}}})
        self.assertNotIn("<img", to_markdown(self.scan()))
        self.assertIn("INCOMPLETE", to_mermaid(self.scan(), ["unreadable file: x"]))
        self.assertIn("INCOMPLETE", to_mermaid([], ["unreadable file: x"]))

    # --- N17
    def test_n17_empty_mcpservers_does_not_mask_servers_key(self):
        write(self.p / ".vscode/mcp.json", {"mcpServers": {}, "servers": {"s": {"command": "bash"}}})
        vias = [c.via for a in self.scan() for c in a.capabilities]
        self.assertIn("mcp:s", vias)


if __name__ == "__main__":
    unittest.main()
