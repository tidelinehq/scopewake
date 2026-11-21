"""Azure and Google Cloud reach from exports: classes, levels, approximations stated, nothing silently zero."""
import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from scopewake import cloudrbac as rb
from scopewake.cli import main
from scopewake.model import Agent, Credential
from scopewake.report import to_json, to_markdown

FX = Path(__file__).parent / "fixtures"
J = lambda n: json.loads((FX / n).read_text())


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def classes(acct, who):
    return {c["class"]: c for c in acct.reach(acct.find(who))["classes"]}


class AzureTests(unittest.TestCase):
    def setUp(self):
        self.a = rb.load_azure(J("azure_assignments.json"), J("azure_roles.json"))

    def test_owner_is_full_admin_at_subscription_scope(self):
        c = classes(self.a, "alice@contoso.com")
        self.assertEqual((c["full-admin"]["severity"], c["full-admin"]["level"]), (10, "full"))

    def test_contributor_cannot_grant_access_but_can_run_code_as_an_identity(self):
        c = classes(self.a, "ci-deployer")
        self.assertNotIn("full-admin", c)
        self.assertIn("Microsoft.ManagedIdentity/userAssignedIdentities/assign/action", c["privilege-escalation"]["actions"])
        self.assertNotIn("Microsoft.Authorization/roleAssignments/write", c["privilege-escalation"]["actions"])
        self.assertIn("data-destroy", c)

    def test_resource_scope_and_condition_lower_severity(self):
        c = classes(self.a, "invoice-agent")
        self.assertEqual((c["secrets-read"]["level"], c["secrets-read"]["severity"]), ("scoped", 7))
        self.assertEqual((c["data-read"]["level"], c["data-read"]["severity"]), ("conditional", 7))

    def test_reader_has_no_high_impact_class(self):
        self.assertEqual(classes(self.a, "reader-bot"), {})

    def test_custom_role_uses_supplied_definition_and_not_actions(self):
        c = classes(self.a, "custom-bot")
        self.assertEqual(set(c), {"compute-launch", "audit-tamper"})

    def test_unknown_role_is_reported_not_counted_as_zero(self):
        r = self.a.reach(self.a.find("mystery-bot"))
        self.assertEqual(r["unevaluated_roles"], ["Some Unlisted Role"])
        self.assertTrue(any("role not evaluated" in i for i in self.a.issues))

    def test_group_assignment_and_name_approximation_are_stated(self):
        self.assertTrue(any("groups" in i for i in self.a.issues))
        self.assertTrue(any("approximated from its name: Owner" in i for i in self.a.issues))
        self.assertFalse(any("approximated from its name: Contributor" in i for i in self.a.issues))  # definition supplied

    def test_find_by_object_id_and_name(self):
        self.assertEqual(self.a.find("11111111-0000-0000-0000-000000000002"), self.a.find("CI-Deployer"))
        self.assertIsNone(self.a.find("nobody"))

    def test_wrong_shape_is_rejected(self):
        for bad in ({}, [1], [{"foo": 1}]):
            with self.assertRaises(rb.CloudExportError):
                rb.load_azure(bad)
        with self.assertRaises(rb.CloudExportError):
            rb.load_azure([], {"not": "a list"})


class GcpTests(unittest.TestCase):
    def setUp(self):
        self.g = rb.load_gcp(J("gcp_policy.json"), J("gcp_roles.json"))
        self.sa = lambda n: f"serviceAccount:{n}@acme-prod.iam.gserviceaccount.com"

    def test_owner_is_full_admin(self):
        self.assertEqual(classes(self.g, "user:alice@acme.com")["full-admin"]["severity"], 10)

    def test_editor_cannot_set_policy_or_read_secrets_but_can_mint_keys(self):
        c = classes(self.g, self.sa("ci"))
        self.assertNotIn("full-admin", c)
        # Not directly (Editor lacks secretmanager.versions.access), but it can mint a key for an account that can.
        self.assertTrue(c["secrets-read"]["via"].startswith("via serviceAccount:invoice-agent@"))
        self.assertNotIn("secrets-read", self.g.direct_classes(self.g.find(self.sa("ci"))))
        self.assertEqual(c["privilege-escalation"]["actions"], ["iam.serviceAccountKeys.create", "deploymentmanager.deployments.create"])

    def test_condition_is_marked(self):
        c = classes(self.g, self.sa("invoice-agent"))["secrets-read"]
        self.assertEqual((c["level"], c["severity"]), ("conditional", 8))

    def test_project_level_token_creator_reaches_other_service_accounts(self):
        c = classes(self.g, self.sa("helper"))
        self.assertTrue(c["data-destroy"]["via"].startswith("via serviceAccount:ci@"))
        self.assertEqual(c["role-assumption"]["via"], "role roles/iam.serviceAccountTokenCreator")

    def test_binding_on_one_service_account_reaches_only_that_account(self):
        r = self.g.reach(self.g.find(self.sa("narrow")))
        self.assertEqual(r["assumable_roles"], [self.sa("ci")])
        self.assertEqual(self.g.direct_classes(self.g.find(self.sa("narrow")))["role-assumption"]["level"], "scoped")

    def test_custom_role_uses_supplied_permissions(self):
        c = classes(self.g, self.sa("reader"))
        self.assertEqual(c["data-read"]["level"], "full")
        self.assertEqual(c["data-destroy"]["level"], "scoped")     # object admin on one bucket

    def test_unknown_role_public_and_group_members_are_stated(self):
        self.assertEqual(self.g.reach(self.g.find(self.sa("mystery")))["unevaluated_roles"], ["roles/some.unlistedRole"])
        self.assertIn("allUsers", self.g.principals)
        self.assertFalse(any(k.startswith("deleted:") for k in self.g.principals))
        self.assertTrue(any("allUsers" in i for i in self.g.issues))
        self.assertTrue(any("groups or domains" in i for i in self.g.issues))

    def test_single_project_policy_shape(self):
        g = rb.load_gcp({"bindings": [{"role": "roles/storage.admin", "members": ["user:a@b.c"]}], "etag": "x", "version": 1})
        self.assertEqual(set(classes(g, "a@b.c")), {"data-read", "data-destroy"})

    def test_wrong_shape_is_rejected(self):
        for bad in ([1], {"foo": 1}, [{"nope": 1}]):
            with self.assertRaises(rb.CloudExportError):
                rb.load_gcp(bad)


class AttachAndCliTests(unittest.TestCase):
    def agent(self, kind, cred):
        return Agent(id=f"{kind}:x", name="Invoice agent", kind=kind, source="x", credentials=[Credential(cred, 9, "~/x", "readable-file")])

    def test_attach_adds_reach_only_to_agents_holding_that_cloud(self):
        az, other = self.agent("cursor", "azure-token-cache"), self.agent("cursor", "ssh-private-key")
        issues = rb.attach([az, other], rb.load_azure(J("azure_assignments.json"), J("azure_roles.json")), {"*": "invoice-agent"})
        self.assertEqual([c.name for c in az.capabilities], ["azure:data-read", "azure:secrets-read"])
        self.assertEqual(az.clouds[0]["provider"], "azure")
        self.assertEqual(az.credentials[0].severity, 7)
        self.assertEqual(other.clouds, [])
        self.assertTrue(issues)
        doc = json.loads(to_json([az]))
        self.assertEqual(doc["agents"][0]["clouds"][0]["name"], "invoice-agent")
        self.assertIn("azure reach as ServicePrincipal", to_markdown([az]))

    def test_unmapped_and_missing_principals_are_issues(self):
        g = rb.load_gcp(J("gcp_policy.json"))
        self.assertTrue(any("no principal was mapped" in i for i in rb.attach([self.agent("cursor", "gcp-adc")], g, {})))
        self.assertTrue(any("not found" in i for i in rb.attach([self.agent("cursor", "gcp-adc")], g, {"*": "nobody@x"})))

    def test_cli_text_json_and_errors(self):
        code, out, _ = run(["azure", str(FX / "azure_assignments.json"), "--roles", str(FX / "azure_roles.json")])
        self.assertEqual(code, 0)
        self.assertIn("role not evaluated, so this may understate reach: Some Unlisted Role", out)
        code, out, _ = run(["gcp", str(FX / "gcp_policy.json"), "--format", "json"])
        doc = json.loads(out)
        self.assertEqual((code, doc["provider"], doc["coverage"]["complete"]), (0, "gcp", False))
        self.assertEqual(run(["gcp", str(FX / "azure_assignments.json")])[0], 2)
        self.assertEqual(run(["azure", str(FX / "missing.json")])[0], 2)


if __name__ == "__main__":
    unittest.main()
