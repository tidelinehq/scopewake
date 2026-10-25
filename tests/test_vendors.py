"""Tests for vendor AI identification (MAS AIRM paras 4.2-4.4, fn 21)."""
import io
import json
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from pathlib import Path

from scopewake import vendors as vnd
from scopewake.cli import main

TODAY = "2026-10-26"
OKTA_CSV = "id,label,status,signOnMode\n1,Salesforce.com,ACTIVE,SAML_2_0\n2,Zoom,ACTIVE,SAML_2_0\n" \
           "3,Acme Internal Ledger,ACTIVE,SAML_2_0\n4,Atlassian Cloud,ACTIVE,SAML_2_0\n5,Slack,ACTIVE,SAML_2_0\n"
ENTRA_JSON = {"value": [{"displayName": "Microsoft 365", "publisherName": "Microsoft Corporation"},
                        {"displayName": "Box", "publisherName": "Box, Inc."},
                        {"displayName": "Payroll Portal SG", "publisherName": "Local Vendor Pte Ltd"}]}
DOMAINS_CSV = "domain,count\nchat.deepseek.com,40\nchatgpt.com,120\nzoom.us,900\nexample.org,5\nwww.otter.ai,3\n"
EXTS_CSV = "Extension Name,Extension ID\nGrammarly: AI Writing and Grammar Checker,kbfnbcaeplbcioakkpcpgfkobkghlhen\nuBlock Origin,x\n"
MATERIAL = "vendor\nSalesforce\nMicrosoft\n"


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class VendorTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.d = Path(self._t.name)
        (self.d / "okta.csv").write_text(OKTA_CSV)
        (self.d / "entra.json").write_text(json.dumps(ENTRA_JSON))
        (self.d / "dns.csv").write_text(DOMAINS_CSV)
        (self.d / "ext.csv").write_text(EXTS_CSV)
        (self.d / "material.csv").write_text(MATERIAL)
        self.cat = vnd.load_catalogue()

    def tearDown(self):
        self._t.cleanup()

    def ident(self, **kw):
        return vnd.identify(self.cat, today=date.fromisoformat(TODAY), **kw)

    def test_okta_and_entra_exports_parse_and_match(self):
        apps = vnd.parse_apps(self.d / "okta.csv") + vnd.parse_apps(self.d / "entra.json")
        res = self.ident(apps=apps)
        products = {p["product_id"] for p in res["proposals"]}
        self.assertTrue({"salesforce", "zoom", "atlassian", "slack", "microsoft-365-copilot", "box"} <= products)
        self.assertIn("Acme Internal Ledger", res["coverage"]["unmatched_apps"])
        self.assertIn("Payroll Portal SG", res["coverage"]["unmatched_apps"])
        self.assertTrue(all(p["status"] == "proposed" for p in res["proposals"]))

    def test_no_shadow_inputs_is_reported_as_a_gap(self):
        res = self.ident(apps=vnd.parse_apps(self.d / "okta.csv"))
        self.assertFalse(res["coverage"]["shadow_ai_assessed"])
        self.assertTrue(any("Shadow AI NOT assessed" in g and "4.4" in g for g in res["gaps"]))

    def test_shadow_ai_from_dns_and_extensions(self):
        apps = vnd.parse_apps(self.d / "okta.csv")
        res = self.ident(apps=apps, domains=vnd.parse_domains(self.d / "dns.csv"),
                         extensions=vnd.parse_extensions(self.d / "ext.csv"))
        by = {(p["source"], p["product_id"]): p for p in res["proposals"]}
        self.assertTrue(by[("dns", "deepseek")]["shadow"])
        self.assertEqual(by[("dns", "deepseek")]["count"], 40)
        self.assertTrue(by[("dns", "chatgpt")]["shadow"])
        self.assertTrue(by[("dns", "otter")]["shadow"])  # subdomain match
        self.assertFalse(by[("dns", "zoom")]["shadow"])  # Zoom is sanctioned via the IdP
        self.assertTrue(by[("extension", "grammarly")]["shadow"])
        self.assertTrue(res["coverage"]["shadow_ai_assessed"])
        self.assertNotIn(("dns", "example"), by)

    def test_material_providers_rank_first(self):
        apps = vnd.parse_apps(self.d / "okta.csv") + vnd.parse_apps(self.d / "entra.json")
        res = self.ident(apps=apps, material=vnd.parse_material(self.d / "material.csv"))
        flags = [p["material"] for p in res["proposals"]]
        self.assertTrue(flags[0])
        self.assertEqual(flags, sorted(flags, key=lambda m: 0 if m else 1))
        mat = {p["product_id"] for p in res["proposals"] if p["material"]}
        self.assertEqual(mat, {"salesforce", "slack", "microsoft-365-copilot"})  # Slack via vendor Salesforce

    def test_no_material_list_leaves_materiality_open(self):
        res = self.ident(apps=vnd.parse_apps(self.d / "okta.csv"))
        self.assertTrue(all(p["material"] is None for p in res["proposals"]))
        self.assertTrue(any("Materiality is the institution's determination" in g for g in res["gaps"]))

    def test_cli_decision_round_trip(self):
        code, out, _ = run(["vendors", "--apps", str(self.d / "okta.csv"), "--format", "json", "--today", TODAY])
        self.assertEqual(code, 0)
        pid = [p["id"] for p in json.loads(out)["proposals"] if p["product_id"] == "zoom"][0]
        code, out, _ = run(["vendors", "--apps", str(self.d / "okta.csv"), "--decide", pid, "--decision", "accept",
                            "--by", "Head of Technology Risk", "--reason", "AI Companion enabled for sales", "--today", TODAY])
        self.assertEqual(code, 0)
        (self.d / "dec.json").write_text(out)
        code, out, _ = run(["vendors", "--apps", str(self.d / "okta.csv"), "--decisions", str(self.d / "dec.json"),
                            "--format", "json", "--today", TODAY])
        z = [p for p in json.loads(out)["proposals"] if p["id"] == pid][0]
        self.assertEqual(z["status"], "accepted")
        self.assertEqual(z["decision"]["by"], "Head of Technology Risk")
        self.assertEqual(z["decision"]["ref"], "MAS AIRM para 4.3")

    def test_decide_requires_decider_and_known_id(self):
        code, _, err = run(["vendors", "--apps", str(self.d / "okta.csv"), "--decide", "nope", "--decision", "reject",
                            "--by", "x", "--today", TODAY])
        self.assertEqual(code, 2)
        self.assertIn("no proposal", err)
        res = self.ident(apps=vnd.parse_apps(self.d / "okta.csv"))
        with self.assertRaises(ValueError):
            vnd.decide(vnd.empty_decisions(), res, res["proposals"][0]["id"], "accept", " ", date(2026, 10, 26))

    def test_text_md_csv_outputs(self):
        for fmt in ("text", "md", "csv"):
            code, out, err = run(["vendors", "--apps", str(self.d / "okta.csv"), "--format", fmt, "--today", TODAY])
            self.assertEqual(code, 0)
            self.assertIn("Zoom", out)
        self.assertIn("shadow AI not assessed", err)
        code, out, _ = run(["vendors", "--apps", str(self.d / "okta.csv"), "--today", TODAY])
        self.assertIn("final arbiter", out)
        self.assertIn("Apps not in catalogue", out)

    def test_requires_an_input(self):
        code, _, err = run(["vendors"])
        self.assertEqual(code, 2)

    def test_bad_inputs_fail_cleanly(self):
        (self.d / "bad.json").write_text("{not json")
        code, _, err = run(["vendors", "--apps", str(self.d / "bad.json")])
        self.assertEqual(code, 2)
        code, _, err = run(["vendors", "--apps", str(self.d / "missing.csv")])
        self.assertEqual(code, 2)

    def test_catalogue_diff(self):
        old = json.loads(json.dumps(self.cat))
        new = json.loads(json.dumps(self.cat))
        new["version"] = "next"
        new["products"][0]["features"][0]["default_on"] = True
        new["products"].append({"id": "newco", "product": "NewCo", "features": []})
        (self.d / "o.json").write_text(json.dumps(old))
        (self.d / "n.json").write_text(json.dumps(new))
        code, out, _ = run(["catalogue-diff", str(self.d / "o.json"), str(self.d / "n.json")])
        res = json.loads(out)
        self.assertEqual(res["added"], ["newco"])
        self.assertTrue(res["changed"][0]["changes"][0].startswith(self.cat["products"][0]["features"][0]["name"]))

    def test_stale_entries_flagged(self):
        res = vnd.identify(self.cat, apps=[{"name": "Zoom", "vendor": ""}], today=date(2027, 3, 1))
        self.assertGreater(res["coverage"]["catalogue_entries_stale"], 0)
        self.assertTrue(any("last checked more than" in g for g in res["gaps"]))


class CatalogueIntegrityTests(unittest.TestCase):
    def test_every_verified_fact_has_a_source_and_date(self):
        cat = vnd.load_catalogue()
        for p in cat["products"]:
            for f in p["features"]:
                verified = [k for k in vnd.FACT_FIELDS if f.get(k, "unverified") != "unverified"]
                if verified:
                    self.assertTrue(f["sources"], f"{p['id']}/{f['name']} has facts but no source")
                    self.assertTrue(re.fullmatch(r"\d{4}-\d{2}-\d{2}", f["checked"]), p["id"])
                for s in f["sources"]:
                    self.assertTrue(s.startswith("https://"), s)

    def test_no_prohibited_claims(self):
        text = (Path(vnd.__file__).read_text() + vnd.CATALOGUE.read_text()).lower()
        for word in ("compliant", "guarantee", "prevents", "ensures compliance"):
            self.assertNotIn(word, text)

    def test_ids_unique_and_domains_well_formed(self):
        cat = vnd.load_catalogue()
        ids = [p["id"] for p in cat["products"]]
        self.assertEqual(len(ids), len(set(ids)))
        for p in cat["products"]:
            for d in p["domains"]:
                self.assertEqual(vnd._host(d), d, d)


if __name__ == "__main__":
    unittest.main()
