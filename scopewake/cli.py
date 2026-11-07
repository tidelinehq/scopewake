import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .report import to_json, to_markdown, to_mermaid, to_sarif, to_text
from .diff import diff_reports, diff_text
from .safe import safe, scrub, scrub_tree
from .scanner import get_issues, scan
from .scoring import score_all
from . import aws as awsmod
from . import compliance as comp
from .fix import fixes
from . import approvals as apv
from .diff import normalize
from . import vendors as vnd
from . import inventory as invmod
from datetime import date


def main(argv=None):
    p = argparse.ArgumentParser(prog="scopewake", description="Map what each AI agent on this machine could reach. Local and read-only.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("scan", help="scan a project directory and the user's home for agents and credentials")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--home", default=str(Path.home()), help="home directory to inspect (default: current user's)")
    s.add_argument("--format", choices=["text", "json", "md", "mermaid", "sarif"], default="text")
    s.add_argument("--fail-above", type=int, default=None, help="exit 1 if any agent scores above this (for CI)")
    s.add_argument("--allow-incomplete", action="store_true", help="with --fail-above, do not fail (exit 3) when some files could not be analysed")
    s.add_argument("--aws-auth", metavar="FILE", help="output of `aws iam get-account-authorization-details` (read offline)")
    s.add_argument("--aws-as", action="append", default=[], metavar="[AGENT=]PRINCIPAL",
                   help="IAM user/role the agents' AWS credentials belong to; repeat as AGENT=PRINCIPAL per agent id or kind")
    w = sub.add_parser("aws", help="rank IAM users and roles in an exported account by what they can reach")
    w.add_argument("export", help="output of `aws iam get-account-authorization-details`")
    w.add_argument("--format", choices=["text", "json"], default="text")
    for name, helptext in (("compliance", "regulatory evidence pack: scan + your AI inventory (MAS, EU AI Act, NYDFS, APRA, HKMA)"),
                           ("fix", "print Claude Code managed settings that shrink the reach found by the scan")):
        c = sub.add_parser(name, help=helptext)
        c.add_argument("path", nargs="?", default=".")
        c.add_argument("--home", default=str(Path.home()))
        c.add_argument("--aws-auth", metavar="FILE")
        c.add_argument("--aws-as", action="append", default=[], metavar="[AGENT=]PRINCIPAL")
    for name, helptext in (("approve", "record an approval of an AI use case, freezing its agents' current reach (prints the updated ledger)"),
                           ("review", "flag approvals that a change in reach or an expired review has made stale (MAS 5.24-5.25)")):
        c = sub.add_parser(name, help=helptext)
        c.add_argument("path", nargs="?", default=".", help="directory to scan (ignored with --report)")
        c.add_argument("--home", default=str(Path.home()))
        c.add_argument("--report", metavar="FILE", help="use a saved `scopewake scan --format json` report instead of scanning")
        c.add_argument("--aws-auth", metavar="FILE")
        c.add_argument("--aws-as", action="append", default=[], metavar="[AGENT=]PRINCIPAL")
        c.add_argument("--ledger", metavar="FILE", required=(name == "review"), help="approvals ledger (JSON)")
        c.add_argument("--today", metavar="YYYY-MM-DD", help=argparse.SUPPRESS)
    ap = sub.choices["approve"]
    ap.add_argument("--system", required=True, help="the approved AI use case, as named in the inventory")
    ap.add_argument("--agent", action="append", default=[], help="agent kind, name or kind/name covered by the approval; repeatable")
    ap.add_argument("--by", required=True, help="who approved it")
    ap.add_argument("--owner", default="")
    ap.add_argument("--scope", default="", help="approved scope of use (MAS para 4.7)")
    ap.add_argument("--valid-days", type=int, default=365, help="days until the approval evidence must be refreshed")
    ap.add_argument("--evidence", action="append", default=[], help="link or reference to supporting evidence; repeatable")
    ap.add_argument("--note", default="")
    rv = sub.choices["review"]
    rv.add_argument("--format", choices=["text", "md", "json", "csv"], default="text")
    rv.add_argument("--fail-on-review", action="store_true", help="exit 1 if any approval needs re-review or has expired, or an agent has none (for CI)")
    rv.add_argument("--refs", choices=list(apv.REFS), default="mas", help="regulatory references to print (default mas; 'none' for neutral output)")
    im = sub.add_parser("import", help="turn an exported agent inventory (Defender XDR AgentsInfo, or any CSV/JSON) into a scopewake report")
    im.add_argument("file")
    im.add_argument("--source", choices=["defender", "generic"], default="defender")
    im.add_argument("--map", action="append", default=[], metavar="FIELD=COLUMN",
                    help="column for a field (" + ", ".join(invmod.GENERIC_FIELDS) + "); repeat; overrides the preset")
    im.add_argument("--platform", default="", help="platform label to use when the export has none (e.g. agentforce)")
    mg = sub.add_parser("merge", help="combine scan and import reports into one, for approve/review across every agent type")
    mg.add_argument("reports", nargs="+")
    vl = sub.add_parser("verify-ledger", help="check the approvals ledger's integrity log for edits made after the fact")
    vl.add_argument("ledger")
    vl.add_argument("--format", choices=["text", "json"], default="text")
    ev = sub.add_parser("evidence", help="write a dated evidence pack (scan, approval review, compliance mapping) with a SHA-256 manifest")
    ev.add_argument("path", nargs="?", default=".")
    ev.add_argument("--home", default=str(Path.home()))
    ev.add_argument("--aws-auth", metavar="FILE")
    ev.add_argument("--aws-as", action="append", default=[], metavar="[AGENT=]PRINCIPAL")
    ev.add_argument("--approvals", metavar="FILE", help="approvals ledger; adds the review and the integrity check")
    ev.add_argument("--inventory", metavar="FILE", help="JSON AI inventory kept by the firm")
    ev.add_argument("--framework", action="append", choices=list(comp.FRAMEWORKS) + ["all", "none"], default=None,
                    help="compliance mapping(s) to include; repeat; default mas-airm; 'none' to skip")
    ev.add_argument("--refs", choices=list(apv.REFS), default="mas", help="references printed in the approval review")
    ev.add_argument("--include", action="append", default=[], metavar="REPORT",
                    help="imported or saved report (from `scopewake import`) to include in the approval review; repeat")
    ev.add_argument("--format", choices=["json", "md"], default="json",
                    help="json: one bundle with every file and its SHA-256 (save with > pack.json); md: one readable document")
    cp = sub.choices["compliance"]
    cp.add_argument("--approvals", metavar="FILE", help="approvals ledger, to evidence change-triggered re-approval (MAS 5.24-5.25)")
    cp.add_argument("--framework", action="append", choices=list(comp.FRAMEWORKS) + ["all"], default=None,
                    help="repeat for several; default mas-airm")
    cp.add_argument("--inventory", metavar="FILE", help="JSON AI inventory kept by the firm (see --inventory-template)")
    cp.add_argument("--inventory-template", action="store_true", help="print an inventory template pre-filled from the scan")
    cp.add_argument("--format", choices=["md", "json"], default="md")
    d = sub.add_parser("diff", help="compare two JSON reports and show what each agent gained or lost")
    d.add_argument("old")
    d.add_argument("new")
    d.add_argument("--format", choices=["text", "json"], default="text")
    d.add_argument("--fail-on-increase", action="store_true", help="exit 1 if any agent's reach grew (for CI drift gates)")
    v = sub.add_parser("vendors", help="find AI features inside the SaaS you use, plus shadow AI (MAS paras 4.2-4.4, fn 21); proposals only")
    v.add_argument("--apps", metavar="FILE", help="app list exported from Okta or Microsoft Entra (CSV or JSON)")
    v.add_argument("--domains", metavar="FILE", help="DNS or proxy log summary: domains, optionally with counts (shadow AI)")
    v.add_argument("--extensions", metavar="FILE", help="browser-extension inventory from MDM/endpoint tooling (shadow AI)")
    v.add_argument("--material", metavar="FILE", help="your list of material third-party service providers (ranks proposals)")
    v.add_argument("--decisions", metavar="FILE", help="control-function decisions log (JSON) to apply")
    v.add_argument("--catalogue", metavar="FILE", help="use this catalogue instead of the bundled one")
    v.add_argument("--format", choices=["text", "md", "json", "csv"], default="text")
    v.add_argument("--decide", metavar="PROPOSAL_ID", help="record a decision on a proposal and print the updated decisions log")
    v.add_argument("--decision", choices=["accept", "reject"])
    v.add_argument("--by", default="", help="who in the designated control function made the decision")
    v.add_argument("--reason", default="")
    v.add_argument("--today", metavar="YYYY-MM-DD", help=argparse.SUPPRESS)
    vc = sub.add_parser("catalogue-diff", help="compare two vendor AI catalogue versions (monthly re-check log)")
    vc.add_argument("old")
    vc.add_argument("new")
    args = p.parse_args(argv)
    if args.cmd == "vendors":
        return _vendors(args)
    if args.cmd == "catalogue-diff":
        try:
            res = vnd.catalogue_diff(vnd.load_catalogue(args.old), vnd.load_catalogue(args.new))
        except (OSError, ValueError) as e:
            print(f"scopewake catalogue-diff: {safe(e, 400)}", file=sys.stderr)
            return 2
        print(json.dumps(scrub_tree(res), indent=2))
        return 0
    if args.cmd == "diff":
        try:
            res = diff_reports(args.old, args.new)
        except (OSError, ValueError, RecursionError) as e:
            print(f"scopewake diff: {safe(e, 400)}", file=sys.stderr)
            return 2
        print(json.dumps(scrub_tree(res), indent=2, allow_nan=False) if args.format == "json" else scrub(diff_text(res)))
        return 1 if args.fail_on_increase and res["worse"] else 0
    if args.cmd == "aws":
        try:
            rows, aissues = awsmod.analyse(awsmod.load_export(args.export))
        except (OSError, ValueError) as e:
            print(f"scopewake aws: {safe(e, 400)}", file=sys.stderr)
            return 2
        if args.format == "json":
            print(json.dumps(scrub_tree({"tool": "scopewake", "version": __version__, "note": awsmod.LIMITS,
                                         "coverage": {"complete": not aissues, "issues": aissues}, "principals": rows}), indent=2))
        else:
            print(scrub(awsmod.principals_text(rows, aissues)))
        return 0
    if args.cmd in ("approve", "review"):
        return _approvals(args)
    if args.cmd == "import":
        try:
            rep = invmod.import_inventory(args.file, args.source, invmod.parse_map(args.map), args.platform)
        except (OSError, ValueError, RecursionError) as e:
            print(f"scopewake import: {safe(e, 400)}", file=sys.stderr)
            return 2
        print(json.dumps(rep, indent=2))
        print(f"scopewake import: {len(rep['agents'])} agent(s) imported", file=sys.stderr)
        return 0
    if args.cmd == "merge":
        try:
            reps = []
            for f in args.reports:
                p = Path(f)
                if p.stat().st_size > 16 * 1024 * 1024:
                    raise ValueError(f"{safe(f, 200)} is larger than 16 MB")
                reps.append(json.loads(p.read_text(encoding="utf-8")))
            out = invmod.merge_reports(reps)
            normalize(json.loads(json.dumps(out)), "<merged>")  # validate before printing
        except (OSError, ValueError, RecursionError) as e:
            print(f"scopewake merge: {safe(e, 400)}", file=sys.stderr)
            return 2
        print(json.dumps(scrub_tree(out), indent=2))
        return 0
    if args.cmd == "verify-ledger":
        try:
            res = apv.verify_ledger(apv.load_ledger(args.ledger))
        except (OSError, ValueError, RecursionError) as e:
            print(f"scopewake verify-ledger: {safe(e, 400)}", file=sys.stderr)
            return 2
        print(json.dumps(res, indent=2) if args.format == "json" else scrub(apv.verify_text(res)))
        return 1 if res["status"] == "tampered" else 0
    if args.cmd == "evidence":
        return _evidence(args)
    if args.cmd not in ("scan", "compliance", "fix"):
        p.print_help()
        return 2
    agents, issues = _live(args)
    if args.cmd == "fix":
        print(json.dumps(scrub_tree(fixes(agents)), indent=2))
        return 0
    if args.cmd == "compliance":
        if args.inventory_template:
            print(json.dumps(scrub_tree(comp.inventory_template(agents)), indent=2))
            return 0
        inv = None
        if args.inventory:
            try:
                inv = comp.load_inventory(args.inventory)
            except ValueError as e:
                print(f"scopewake compliance: {safe(e, 400)}", file=sys.stderr)
                return 2
        fws = args.framework or ["mas-airm"]
        fws = list(comp.FRAMEWORKS) if "all" in fws else list(dict.fromkeys(fws))
        rev = None
        if args.approvals:
            try:
                ledger = apv.load_ledger(args.approvals)
                rev = apv.review(ledger, normalize(json.loads(to_json(agents, issues)), "<scan>"), date.today())
            except ValueError as e:
                print(f"scopewake compliance: {safe(e, 400)}", file=sys.stderr)
                return 2
        pack = comp.build_pack(agents, inv, fws, issues, rev)
        print(json.dumps(pack, indent=2) if args.format == "json" else scrub(comp.pack_markdown(pack)))
        if issues:
            print(f"scopewake: incomplete scan, {len(issues)} problem(s); results may understate risk.", file=sys.stderr)
        return 0
    render = {"text": to_text, "json": to_json, "md": to_markdown, "mermaid": to_mermaid, "sarif": to_sarif}[args.format]
    print(scrub(render(agents, issues)))
    if issues:
        print(f"scopewake: incomplete scan, {len(issues)} problem(s); results may understate risk.", file=sys.stderr)
    if args.fail_above is not None and any(a.score > args.fail_above for a in agents):
        return 1
    if issues and args.fail_above is not None and not args.allow_incomplete:
        return 3
    return 0


def _live(args):
    agents = scan(Path(args.path), Path(args.home))
    issues = get_issues()
    if args.aws_auth:
        try:
            issues += awsmod.attach(agents, awsmod.load_export(args.aws_auth), awsmod.parse_mapping(args.aws_as))
        except (OSError, ValueError) as e:
            issues.append(f"AWS export not analysed: {e}")
    return score_all(agents), issues


def _vendors(args):
    name = "scopewake vendors"
    try:
        today = date.fromisoformat(args.today) if args.today else date.today()
        cat = vnd.load_catalogue(args.catalogue)
        apps = vnd.parse_apps(args.apps) if args.apps else []
        doms = vnd.parse_domains(args.domains) if args.domains else []
        exts = vnd.parse_extensions(args.extensions) if args.extensions else []
        mat = vnd.parse_material(args.material) if args.material else []
        if not (apps or doms or exts):
            raise ValueError("supply at least one of --apps, --domains, --extensions")
        log = vnd.load_decisions(args.decisions) if args.decisions else vnd.empty_decisions()
        res = vnd.identify(cat, apps, doms, exts, mat, log, today)
        if args.decide:
            if not args.decision:
                raise ValueError("--decide needs --decision accept|reject")
            print(json.dumps(vnd.decide(log, res, args.decide, args.decision, args.by, today, args.reason), indent=2))
            return 0
    except (OSError, ValueError, RecursionError) as e:
        print(f"{name}: {safe(e, 400)}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(res, indent=2))
    elif args.format == "csv":
        print(vnd.to_csv(res), end="")
    else:
        print(scrub(vnd.to_text(res, markdown=args.format == "md")))
    if not res["coverage"]["shadow_ai_assessed"]:
        print(f"{name}: shadow AI not assessed (no --domains or --extensions); see MAS AIRM para 4.4.", file=sys.stderr)
    return 0


def _approvals(args):
    name = f"scopewake {args.cmd}"
    try:
        today = date.fromisoformat(args.today) if args.today else date.today()
        if args.report:
            from .diff import _load
            report = _load(args.report)
        else:
            agents, issues = _live(args)
            report = normalize(json.loads(to_json(agents, issues)), "<scan>")
        ledger = apv.load_ledger(args.ledger) if args.ledger else apv.empty_ledger()
        if args.cmd == "approve":
            out = apv.approve(ledger, report, args.system, args.agent, args.by, today, owner=args.owner, scope=args.scope,
                              valid_days=args.valid_days, evidence=args.evidence, note=args.note)
            print(json.dumps(out, indent=2))
            if not report["complete"]:
                print(f"{name}: the scan was incomplete; the frozen reach may understate what the agents can reach.", file=sys.stderr)
            return 0
        res = apv.review(ledger, report, today, refs=args.refs)
    except (OSError, ValueError, RecursionError) as e:
        print(f"{name}: {safe(e, 400)}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(res, indent=2))
    elif args.format == "csv":
        print(apv.review_csv(res), end="")
    else:
        print(scrub(apv.review_text(res, markdown=args.format == "md")))
    return 1 if args.fail_on_review and apv.needs_action(res) else 0


def _evidence(args):
    """Bundle scan, approval review, ledger check and compliance mapping, each with a SHA-256. Prints; writes nothing."""
    import hashlib
    from datetime import datetime, timezone
    name = "scopewake evidence"
    try:
        ledger = apv.load_ledger(args.approvals) if args.approvals else None
        inv = comp.load_inventory(args.inventory) if args.inventory else None
        fws = args.framework or ["mas-airm"]
        fws = [] if "none" in fws else list(comp.FRAMEWORKS) if "all" in fws else list(dict.fromkeys(fws))
    except (OSError, ValueError, RecursionError) as e:
        print(f"{name}: {safe(e, 400)}", file=sys.stderr)
        return 2
    agents, issues = _live(args)
    files = {"scan.json": to_json(agents, issues), "scan.md": scrub(to_markdown(agents, issues))}
    try:
        extra = [json.loads(Path(f).read_text(encoding="utf-8")) for f in args.include]
        merged = invmod.merge_reports([json.loads(files["scan.json"])] + extra)
        report = normalize(merged, "<scan+imports>")
    except (OSError, ValueError, RecursionError) as e:
        print(f"{name}: {safe(e, 400)}", file=sys.stderr)
        return 2
    if extra:
        files["imported.json"] = json.dumps(scrub_tree({"inputs": [safe(f, 200) for f in args.include],
                                                        "agents": [a for r in extra for a in r.get("agents", [])]}), indent=2)
    rev, ver = None, None
    if ledger is not None:
        rev = apv.review(ledger, report, date.today(), refs=args.refs)
        ver = apv.verify_ledger(ledger)
        files["review.json"] = json.dumps(rev, indent=2)
        files["review.md"] = scrub(apv.review_text(rev, markdown=True))
        files["ledger.json"] = json.dumps(ledger, indent=2)
        files["ledger-verification.json"] = json.dumps(ver, indent=2)
    if fws:
        pack = comp.build_pack(agents, inv, fws, issues, rev)
        files["compliance.json"] = json.dumps(pack, indent=2)
        files["compliance.md"] = scrub(comp.pack_markdown(pack))
    digests = {fn: hashlib.sha256(text.encode("utf-8")).hexdigest() for fn, text in files.items()}
    manifest = {"tool": "scopewake", "version": __version__, "kind": "evidence-pack",
                "created_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                "scan_complete": not issues, "frameworks": fws,
                "ledger_head": apv.head_hash(ledger) if ledger is not None else "",
                "ledger_status": ver["status"] if ver else "no ledger supplied",
                "sha256": digests,
                "note": "Indicative mapping, not legal advice. Each sha256 is over the UTF-8 text of that file in this pack."}
    if args.format == "json":
        print(json.dumps({"manifest": manifest, "files": files}, indent=2))
    else:
        L = [f"# Scopewake evidence pack ({manifest['created_utc']})", "",
             f"Scan complete: {'yes' if not issues else 'NO, results may understate reach'}. "
             f"Ledger: {manifest['ledger_status']}" + (f", head {manifest['ledger_head']}" if manifest["ledger_head"] else "") + ".", ""]
        for fn in ("scan.md", "review.md", "compliance.md"):
            if fn in files:
                L += [f"<!-- {fn} sha256 {digests[fn]} -->", files[fn], ""]
        L += ["## Manifest", "", "| File | SHA-256 |", "|---|---|"] + [f"| {fn} | `{h}` |" for fn, h in digests.items()]
        L += ["", manifest["note"]]
        print("\n".join(L))
    if issues:
        print(f"{name}: incomplete scan, {len(issues)} problem(s); results may understate risk.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
