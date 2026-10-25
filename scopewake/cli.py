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
        res = apv.review(ledger, report, today)
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


if __name__ == "__main__":
    sys.exit(main())
