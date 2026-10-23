import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from tideline import aws
from tideline.cli import main
from tideline.model import Agent, Credential
from tideline.scoring import score_agent

FIX = Path(__file__).parent / "fixtures" / "aws_auth.json"


def data():
    return json.loads(FIX.read_text())


def reach(name):
    acct = aws.Account(data())
    return acct.reach(acct.find(name))


def classes(name):
    return {c["class"]: c for c in reach(name)["classes"]}


class AwsAnalysisTests(unittest.TestCase):
    def test_group_admin_is_full_admin(self):
        c = classes("alice-admin")
        self.assertEqual(c["full-admin"]["severity"], 10)
        self.assertEqual(c["full-admin"]["level"], "full")

    def test_explicit_deny_removes_action(self):
        self.assertNotIn("data-destroy", classes("dev-agent"))

    def test_scoped_allow_is_lower_severity(self):
        c = classes("dev-agent")["data-read"]
        self.assertEqual(c["level"], "scoped")
        self.assertEqual(c["severity"], 6)

    def test_role_chain_reaches_secrets(self):
        c = classes("dev-agent")["secrets-read"]
        self.assertEqual(c["severity"], 9)
        self.assertIn("deploy-role", c["via"])
        self.assertEqual(reach("dev-agent")["assumable_roles"], ["deploy-role"])

    def test_untrusting_role_not_reachable(self):
        self.assertNotIn("full-admin", classes("dev-agent"))

    def test_url_encoded_policy_document(self):
        self.assertEqual(reach("readonly-bot")["classes"], [])

    def test_poweruser_is_not_full_admin(self):
        c = classes("power")
        self.assertNotIn("full-admin", c)
        self.assertNotIn("privilege-escalation", c)
        self.assertIn("secrets-read", c)

    def test_permission_boundary_caps_admin(self):
        c = classes("bounded")
        self.assertEqual(set(c), {"data-read"})

    def test_passrole_with_lambda_is_escalation(self):
        self.assertEqual(classes("passer")["privilege-escalation"]["severity"], 10)

    def test_condition_marks_conditional(self):
        c = classes("cond")["secrets-read"]
        self.assertEqual(c["level"], "conditional")
        self.assertEqual(c["severity"], 8)

    def test_missing_policy_is_reported_not_zero(self):
        d = data()
        d["UserDetailList"][0]["AttachedManagedPolicies"] = [{"PolicyName": "Custom", "PolicyArn": "arn:aws:iam::111122223333:policy/Custom"}]
        rows, issues = aws.analyse(d)
        self.assertTrue(any("not in export" in i for i in issues))

    def test_rejects_non_export(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "x.json"
            p.write_text("{}")
            with self.assertRaises(aws.AwsExportError):
                aws.load_export(str(p))

    def test_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as t:
            link = Path(t) / "l.json"
            os.symlink(FIX, link)
            with self.assertRaises(aws.AwsExportError):
                aws.load_export(str(link))


class AwsAttachTests(unittest.TestCase):
    def agent(self):
        a = Agent(id="claude-code", name="Claude Code", kind="claude-code", source="x", autonomy=0.6)
        a.credentials.append(Credential("aws-credentials-file", 9, "~/.aws/credentials", "readable-file"))
        return a

    def test_readonly_principal_lowers_credential_severity(self):
        a = self.agent()
        issues = aws.attach([a], data(), aws.parse_mapping(["readonly-bot"]))
        self.assertEqual(issues, [])
        self.assertEqual(a.credentials[0].severity, 3)
        self.assertEqual(a.cloud["max_severity"], 0)

    def test_admin_principal_adds_capability_and_raises_score(self):
        lo, hi = self.agent(), self.agent()
        aws.attach([lo], data(), aws.parse_mapping(["readonly-bot"]))
        aws.attach([hi], data(), aws.parse_mapping(["claude-code=alice-admin"]))
        self.assertIn("aws:full-admin", {c.name for c in hi.capabilities})
        self.assertGreater(score_agent(hi).score, score_agent(lo).score)

    def test_unmapped_agent_reports_issue(self):
        issues = aws.attach([self.agent()], data(), {})
        self.assertTrue(any("--aws-as" in i for i in issues))

    def test_cli_aws_command_json(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["aws", str(FIX), "--format", "json"])
        self.assertEqual(rc, 0)
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["principals"][0]["max_severity"], 10)

    def test_cli_scan_with_aws(self):
        with tempfile.TemporaryDirectory() as t:
            home, proj = Path(t) / "home", Path(t) / "proj"
            (home / ".aws").mkdir(parents=True)
            (home / ".aws" / "credentials").write_text("[default]\n")
            (home / ".claude").mkdir()
            (home / ".claude" / "settings.json").write_text("{}")
            proj.mkdir()
            buf = io.StringIO()
            with redirect_stdout(buf):
                main(["scan", str(proj), "--home", str(home), "--format", "json", "--aws-auth", str(FIX), "--aws-as", "alice-admin"])
            doc = json.loads(buf.getvalue())
            cc = [a for a in doc["agents"] if a["kind"] == "claude-code"][0]
            self.assertEqual(cc["cloud"]["name"], "alice-admin")
            self.assertTrue(any(c["name"] == "aws:full-admin" for c in cc["capabilities"]))


if __name__ == "__main__":
    unittest.main()
