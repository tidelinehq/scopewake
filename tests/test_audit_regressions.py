"""Regressions for defects reported by the independent Codex audit of 2026-10-22 (C1-C10)."""
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

MARK = "ghp_" + "A" * 36


def write(p: Path, d):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(d if isinstance(d, str) else json.dumps(d))


class AuditRegressions(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.t = Path(self._t.name)
        self.h, self.p = self.t / "home", self.t / "proj"
        self.h.mkdir()
        self.p.mkdir()

    def tearDown(self):
        self._t.cleanup()

    def run_cli(self, *argv):
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            rc = main(list(argv))
        return rc, buf.getvalue(), err.getvalue()

    def scan(self):
        return score_all(scan(self.p, self.h))

    def test_c1_unrelated_deny_rule_does_not_mitigate(self):
        write(self.h / ".claude/settings.json", {"permissions": {"deny": ["Edit(**/.env.example)"]}})
        write(self.p / ".env", "API_TOKEN=synthetic-test-value\n")
        a = self.scan()[0]
        env = [c for c in a.credentials if c.location.endswith(".env")]
        self.assertTrue(env and not any(c.mitigated for c in env))

    def test_c1_only_read_rules_that_match_the_path_mitigate(self):
        write(self.h / ".aws/credentials", "[default]\n")
        write(self.h / ".claude/settings.json", {"permissions": {"deny": ["Read(~/.ssh/**)", "Bash(rm:*)"]}})
        aws = [c for c in self.scan()[0].credentials if c.kind == "aws-credentials-file"]
        self.assertTrue(aws and not any(c.mitigated for c in aws))
        write(self.h / ".claude/settings.json", {"permissions": {"deny": ["Read(~/.aws/**)"]}})
        aws = [c for c in self.scan()[0].credentials if c.kind == "aws-credentials-file"]
        self.assertTrue(aws and all(c.mitigated for c in aws))

    def test_c2_secret_shaped_metadata_never_reaches_any_output(self):
        write(self.p / ".mcp.json", {"mcpServers": {MARK: {"command": "fetch"}}})
        agents = self.scan()
        for f in (to_json, to_text, to_markdown, to_mermaid, to_sarif):
            self.assertNotIn(MARK, f(agents), f.__name__)

    def test_c2_markdown_cells_are_escaped(self):
        write(self.p / ".mcp.json", {"mcpServers": {"a|b\nc`d": {"command": "fetch"}}})
        md = to_markdown(self.scan())
        self.assertNotIn("a|b", md)
        self.assertNotIn("\nc`d", md)

    def test_c3_unparseable_config_makes_scan_incomplete(self):
        write(self.h / ".cursor/mcp.json", "{bad")
        rc, out, err = self.run_cli("scan", str(self.p), "--home", str(self.h), "--fail-above", "0")
        self.assertEqual(rc, 3)
        self.assertIn("incomplete", err.lower())
        rc, out, _ = self.run_cli("scan", str(self.p), "--home", str(self.h), "--format", "json")
        self.assertFalse(json.loads(out)["coverage"]["complete"])
        rc, _, _ = self.run_cli("scan", str(self.p), "--home", str(self.h), "--fail-above", "0", "--allow-incomplete")
        self.assertEqual(rc, 0)

    def test_c3_complete_scan_reports_complete(self):
        write(self.h / ".cursor/mcp.json", {"mcpServers": {"x": {"command": "bash"}}})
        rc, out, _ = self.run_cli("scan", str(self.p), "--home", str(self.h), "--format", "json")
        self.assertTrue(json.loads(out)["coverage"]["complete"])

    def test_c4_added_capability_trips_the_drift_gate(self):
        write(self.h / ".cursor/mcp.json", {"mcpServers": {"one": {"command": "bash"}}})
        old, new = self.t / "old.json", self.t / "new.json"
        old.write_text(to_json(self.scan()))
        write(self.h / ".cursor/mcp.json", {"mcpServers": {"one": {"command": "bash"}, "two": {"command": "bash"}}})
        new.write_text(to_json(self.scan()))
        self.assertTrue(diff_reports(str(old), str(new))["worse"])
        self.assertEqual(self.run_cli("diff", str(old), str(new), "--fail-on-increase")[0], 1)
        self.assertFalse(diff_reports(str(new), str(old))["worse"])

    def test_c4_same_agent_in_a_different_checkout_is_not_replaced_wholesale(self):
        write(self.h / ".cursor/mcp.json", {"mcpServers": {"one": {"command": "bash"}}})
        a = self.t / "a.json"
        a.write_text(to_json(self.scan()))
        other = self.t / "other"
        other.mkdir()
        b = self.t / "b.json"
        b.write_text(to_json(score_all(scan(other, self.h))))
        d = diff_reports(str(a), str(b))
        self.assertEqual(d["added_agents"], [])
        self.assertEqual(d["removed_agents"], [])

    def test_c5_malformed_permissions_do_not_crash_and_flag_incomplete(self):
        write(self.h / ".claude/settings.json", {"permissions": {"allow": 123, "deny": "x"}})
        scanner.reset_issues()
        scan(self.p, self.h)
        self.assertTrue(scanner.get_issues())

    def test_c5_malformed_report_is_a_clean_error(self):
        old, new = self.t / "o.json", self.t / "n.json"
        write(old, {"tool": "tideline", "agents": [{"id": "x", "credentials": None}]})
        write(new, {"tool": "tideline", "agents": [{"id": "x"}]})
        self.assertEqual(self.run_cli("diff", str(old), str(new))[0], 2)

    def test_c6_ancestor_symlink_is_not_followed(self):
        out = self.t / "outside"
        write(out / "mcp.json", {"mcpServers": {"external": {"command": "bash"}}})
        (self.h / ".cursor").symlink_to(out, target_is_directory=True)
        vias = [c.via for a in scan(self.p, self.h) for c in a.capabilities]
        self.assertNotIn("mcp:external", vias)
        self.assertTrue(scanner.get_issues())

    def test_c7_keyword_matching_is_token_based(self):
        self.assertNotIn("web-content", [c.name for c in classify_server("local-build", "webpack", [])])
        self.assertIn("web-content", [c.name for c in classify_server("web-search", "npx", [])])
        caps = [c.name for c in classify_server("fs", "docker", ["run", "-i", "--rm", "mcp/filesystem"])]
        self.assertIn("filesystem", caps)
        self.assertNotIn("docker", caps)

    def test_c8_label_alone_is_not_a_trifecta(self):
        # A host that runs no commands and has no credentials: a github label alone must not supply all three legs.
        write(self.h / "Library/Application Support/Claude/claude_desktop_config.json",
              {"mcpServers": {"github": {"url": "https://example.invalid/public-readonly"}}})
        a = next(x for x in self.scan() if x.kind == "claude-desktop")
        self.assertFalse(a.trifecta, a.trifecta_parts)

    def test_c8_trifecta_is_labelled_potential(self):
        fake = "ghp_" + "B" * 36
        write(self.p / ".mcp.json", {"mcpServers": {"github": {"command": "npx", "env": {"GITHUB_TOKEN": fake}}}})
        a = self.scan()[0]
        self.assertTrue(a.trifecta)
        self.assertIn("potential", a.fixes[0].lower())
        self.assertNotIn(fake, to_json([a]))

    def test_c9_action_pins_the_package_version(self):
        text = (Path(__file__).resolve().parent.parent / "action.yml").read_text()
        self.assertNotIn('default: ""\nruns', text.split("version:")[1].split("runs:")[0] + "runs")
        self.assertIn("tideline==", text)
        self.assertNotIn("pip install tideline;", text)

    def test_c10_sarif_keeps_repo_relative_paths(self):
        write(self.p / ".github/workflows/agent.yml",
              "on:\n  issue_comment:\n    types: [created]\njobs:\n  a:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n")
        uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                for r in json.loads(to_sarif(self.scan()))["runs"][0]["results"]]
        self.assertIn(".github/workflows/agent.yml", uris)


if __name__ == "__main__":
    unittest.main()
