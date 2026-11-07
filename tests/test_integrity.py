"""Tests for 0.4.0: integrity log on the approvals ledger, neutral references, the evidence bundle, and pack wording."""
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import date
from pathlib import Path

from scopewake import approvals as apv
from scopewake.cli import main
from scopewake.diff import normalize
from scopewake.report import to_json
from scopewake.scanner import scan
from scopewake.scoring import score_all
from test_scopewake import build_fixture

D0, D1 = date(2026, 10, 23), date(2026, 10, 24)


def run(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(argv)
    return code, buf.getvalue()


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.tmp = Path(self._t.name)
        self.home, self.proj = build_fixture(self.tmp)
        rep = normalize(json.loads(to_json(score_all(scan(self.proj, self.home)))))
        led = apv.approve(apv.empty_ledger(), rep, "Invoice reader", ["cursor"], "Jane Tan", D0)
        self.led = apv.approve(led, rep, "Release agent", ["claude-code"], "Head of Security", D1)
        self.rep = rep

    def tearDown(self):
        self._t.cleanup()

    def test_fresh_ledger_is_intact(self):
        v = apv.verify_ledger(self.led)
        self.assertEqual(v["status"], "intact")
        self.assertEqual(v["events"], 2)
        self.assertEqual(v["head"], self.led["log"][-1]["hash"])

    def test_edit_to_approval_is_detected(self):
        led = json.loads(json.dumps(self.led))
        led["approvals"][0]["approved_by"] = "Someone Else"
        v = apv.verify_ledger(led)
        self.assertEqual(v["status"], "tampered")
        self.assertTrue(any("edited after" in p for p in v["problems"]))

    def test_edit_to_log_and_removal_are_detected(self):
        led = json.loads(json.dumps(self.led))
        led["log"][0]["on"] = "2026-01-01"
        self.assertTrue(any("contents changed" in p for p in apv.verify_ledger(led)["problems"]))
        led = json.loads(json.dumps(self.led))
        led["approvals"].pop()
        self.assertTrue(any("missing from the ledger" in p for p in apv.verify_ledger(led)["problems"]))
        led = json.loads(json.dumps(self.led))
        del led["log"][0]
        self.assertEqual(apv.verify_ledger(led)["status"], "tampered")

    def test_renewal_keeps_chain(self):
        led = apv.approve(self.led, self.rep, "Invoice reader", ["cursor"], "Jane Tan", date(2026, 11, 1))
        v = apv.verify_ledger(led)
        self.assertEqual(v["status"], "intact")
        self.assertEqual(led["log"][-1]["action"], "renewed")

    def test_pre_log_ledger_gets_baseline(self):
        old = json.loads(json.dumps(self.led))
        del old["log"]
        self.assertEqual(apv.verify_ledger(old)["status"], "no integrity log")
        led = apv.approve(old, self.rep, "Third use", ["cursor"], "Jane Tan", D1)
        v = apv.verify_ledger(led)
        self.assertEqual(v["status"], "intact")
        self.assertEqual(v["baseline_events"], 2)

    def test_neutral_refs(self):
        res = apv.review(self.led, self.rep, D1, refs="none")
        self.assertTrue(all(x["ref"] == "" for a in res["approvals"] for x in a["reasons"]))
        self.assertNotIn("MAS", apv.review_text(res))
        with self.assertRaises(ValueError):
            apv.review(self.led, self.rep, D1, refs="xyz")

    def test_cli_verify_and_evidence(self):
        lp = self.tmp / "ledger.json"
        lp.write_text(json.dumps(self.led))
        code, out = run(["verify-ledger", str(lp)])
        self.assertEqual(code, 0)
        self.assertIn("intact", out)
        bad = json.loads(json.dumps(self.led)); bad["approvals"][0]["scope"] = "anything"
        lp2 = self.tmp / "bad.json"; lp2.write_text(json.dumps(bad))
        self.assertEqual(run(["verify-ledger", str(lp2)])[0], 1)
        code, out = run(["evidence", str(self.proj), "--home", str(self.home), "--approvals", str(lp), "--refs", "none"])
        self.assertEqual(code, 0)
        pack = json.loads(out)
        for fn, text in pack["files"].items():
            self.assertEqual(pack["manifest"]["sha256"][fn], hashlib.sha256(text.encode("utf-8")).hexdigest())
        self.assertEqual(pack["manifest"]["ledger_status"], "intact")
        self.assertEqual(pack["manifest"]["ledger_head"], self.led["log"][-1]["hash"])
        code, md = run(["evidence", str(self.proj), "--home", str(self.home), "--framework", "none", "--format", "md"])
        self.assertEqual(code, 0)
        self.assertIn("## Manifest", md)

    def test_pack_wording_survives_display_filter(self):
        code, out = run(["compliance", str(self.proj), "--home", str(self.home), "--framework", "nydfs"])
        self.assertNotIn(")= 70", out)


if __name__ == "__main__":
    unittest.main()
