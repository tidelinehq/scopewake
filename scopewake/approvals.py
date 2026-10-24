"""Approval review: tie each approved AI use case to the reach its agents had when it was approved, and flag the
approvals a later change has made stale.

MAS Guidelines on AI Risk Management, para 5.25(a): significant changes should trigger review and re-approval before
implementation; para 5.24: re-validation on significant changes to the AI or its operating environment; para 4.11:
materiality assessments are reviewed regularly. Indicative mapping, not legal advice.

The tool writes nothing: `approve` prints the updated ledger and the user saves it. Offline; names and locations only.
"""
import csv
import hashlib
import io
import json
from datetime import date, timedelta
from pathlib import Path
from typing import Dict, List, Optional

from . import __version__
from .diff import _server_change_is_risk, _server_changes
from .safe import safe, scrub_tree

MAX_LEDGER_BYTES = 4 * 1024 * 1024
LEDGER_KIND = "approvals"
SOON_DAYS = 30

REF_CHANGE = "MAS AIRM para 5.25(a), 5.24"
REF_PERIODIC = "MAS AIRM para 4.11, 2.5(f)"
REF_APPROVED = "MAS AIRM paras 2.3-2.5, 4.7"

STATUS_ORDER = ["re-review required", "evidence expired", "verify", "expiring soon", "current"]


def _iso(d: date) -> str:
    return d.isoformat()


def _parse_date(v, what: str) -> date:
    try:
        return date.fromisoformat(str(v))
    except ValueError:
        raise ValueError(f"{what} must be a date in YYYY-MM-DD form")


def agent_key(a: dict) -> str:
    return f"{a['kind']}/{a['name']}" + (f" ({a['rel']})" if a["rel"] else "")


def selects(selector: str, a: dict) -> bool:
    s = selector.strip().lower()
    return bool(s) and s in {a["kind"].lower(), a["name"].lower(), f"{a['kind']}/{a['name']}".lower(),
                             a["rel"].lower(), agent_key(a).lower()}


def snapshot_agent(a: dict) -> dict:
    """What the agent could reach: unmitigated credentials, capabilities, MCP servers, cloud classes, trifecta."""
    return {"key": agent_key(a), "kind": a["kind"], "name": a["name"], "rel": a["rel"], "score": a["score"],
            "trifecta": a["trifecta"],
            "credentials": sorted([c["kind"], c["loc"], c["name"]] for c in a["credentials"] if not c["mitigated"]),
            "capabilities": sorted([c["name"], c["via"]] for c in a["capabilities"]),
            "servers": [dict(v, config=k[0], name=k[1]) for k, v in sorted(a["servers"].items())],
            "cloud": list(a.get("cloud", []))}


def _snap_hash(agents: List[dict]) -> str:
    return hashlib.sha256(json.dumps(agents, sort_keys=True).encode()).hexdigest()[:16]


def _as_report_agent(s: dict) -> dict:
    """Snapshot back into the normalised form used by diff."""
    return {"kind": s["kind"], "name": s["name"], "rel": s["rel"], "score": s.get("score", 0), "trifecta": bool(s.get("trifecta")),
            "credentials": [{"kind": c[0], "loc": c[1], "name": c[2], "mitigated": False} for c in s.get("credentials", [])],
            "capabilities": [{"name": c[0], "via": c[1]} for c in s.get("capabilities", [])],
            "servers": {(v.get("config", ""), v.get("name", "")): {f: v.get(f, [] if f.endswith("_names") else "")
                        for f in ("transport", "endpoint", "args_hash", "fingerprint", "env_names", "header_names")}
                        for v in s.get("servers", [])},
            "cloud": list(s.get("cloud", []))}


# ---------------------------------------------------------------- ledger

def empty_ledger() -> dict:
    return {"tool": "scopewake", "kind": LEDGER_KIND, "schema": 1, "approvals": []}


def load_ledger(path: str) -> dict:
    p = Path(path)
    try:
        if p.stat().st_size > MAX_LEDGER_BYTES:
            raise ValueError("approvals ledger is larger than 4 MB")
        data = json.loads(p.read_text(encoding="utf-8"))
    except OSError:
        raise ValueError(f"cannot read approvals ledger {safe(path, 200)}")
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ValueError(f"approvals ledger {safe(path, 200)} is not valid JSON")
    if not isinstance(data, dict) or data.get("kind") != LEDGER_KIND or not isinstance(data.get("approvals"), list):
        raise ValueError("not a scopewake approvals ledger (expected kind 'approvals' and an 'approvals' list)")
    for i, ap in enumerate(data["approvals"]):
        if not isinstance(ap, dict):
            raise ValueError(f"approval {i} is not an object")
        for f in ("system", "approved_by", "approved_on", "valid_until"):
            if not isinstance(ap.get(f), str) or not ap[f].strip():
                raise ValueError(f"approval {i}: '{f}' is required")
        _parse_date(ap["approved_on"], f"approval {i}: approved_on")
        _parse_date(ap["valid_until"], f"approval {i}: valid_until")
        if not isinstance(ap.get("agents"), list) or not all(isinstance(x, str) for x in ap["agents"]):
            raise ValueError(f"approval {i}: 'agents' must be a list of selectors")
        snap = ap.get("snapshot")
        if not isinstance(snap, dict) or not isinstance(snap.get("agents"), list) or not all(isinstance(x, dict) for x in snap["agents"]):
            raise ValueError(f"approval {i}: 'snapshot' is missing or malformed")
        for s in snap["agents"]:
            if not all(isinstance(s.get(f), str) for f in ("kind", "name", "rel")):
                raise ValueError(f"approval {i}: snapshot agent needs kind, name and rel")
    return data


def approve(ledger: dict, report: dict, system: str, selectors: List[str], by: str, today: date,
            owner: str = "", scope: str = "", valid_days: int = 365, evidence: Optional[List[str]] = None,
            note: str = "") -> dict:
    """Record (or renew) the approval of `system`, freezing the current reach of the agents it covers."""
    if not system.strip() or not by.strip():
        raise ValueError("--system and --by are required")
    if not selectors:
        raise ValueError("give at least one --agent")
    if not 1 <= valid_days <= 3 * 366:
        raise ValueError("--valid-days must be between 1 and 1098")
    chosen = [a for a in report["agents"].values() if any(selects(s, a) for s in selectors)]
    if not chosen:
        raise ValueError("no agent in the scan matches " + ", ".join(safe(s, 60) for s in selectors))
    snap = [snapshot_agent(a) for a in sorted(chosen, key=agent_key)]
    rec = {"system": system, "owner": owner, "scope": scope, "agents": list(dict.fromkeys(selectors)),
           "approved_by": by, "approved_on": _iso(today), "valid_until": _iso(today + timedelta(days=valid_days)),
           "evidence": list(evidence or []), "note": note,
           "snapshot": {"complete": report["complete"], "hash": _snap_hash(snap), "agents": snap}, "history": []}
    out = json.loads(json.dumps(ledger))
    for i, old in enumerate(out["approvals"]):
        if old["system"].strip().lower() == system.strip().lower():
            hist = list(old.get("history", []))
            hist.append({f: old.get(f, "") for f in ("approved_by", "approved_on", "valid_until", "scope", "note")}
                        | {"snapshot_hash": old.get("snapshot", {}).get("hash", "")})
            rec["history"] = hist
            rec["owner"] = owner or old.get("owner", "")
            rec["scope"] = scope or old.get("scope", "")
            out["approvals"][i] = rec
            break
    else:
        out["approvals"].append(rec)
    out["approvals"].sort(key=lambda r: r["system"].lower())
    return scrub_tree(out)


# ---------------------------------------------------------------- review

def _reasons_for(old: dict, new: dict) -> List[dict]:
    """Additions to reach are a change of approved scope whatever their severity; removals are noted only."""
    r = []
    ka = {tuple(c) for c in old["credentials"]}
    kb = {(c["kind"], c["loc"], c["name"]) for c in new["credentials"] if not c["mitigated"]}
    for kind, loc, name in sorted(kb - ka):
        r.append({"type": "credential added", "detail": f"{kind} at {loc}" + (f" ({name})" if name else ""), "review": True})
    ca = {tuple(c) for c in old["capabilities"]}
    cb = {(c["name"], c["via"]) for c in new["capabilities"]}
    for name, via in sorted(cb - ca):
        r.append({"type": "capability added", "detail": f"{name} via {via}", "review": True})
    sc = _server_changes(_as_report_agent(old), new)
    for sv in sc["servers_added"]:
        r.append({"type": "MCP server added", "detail": f"{sv['server']} ({sv['transport']}, {sv['endpoint']})", "review": True})
    for sv in sc["servers_changed"]:
        risky = _server_change_is_risk({"servers_added": [], "servers_changed": [sv]})
        r.append({"type": "MCP server changed", "detail": f"{sv['server']}: " + "; ".join(sv["changes"]), "review": risky})
    for sv in sc["servers_removed"]:
        r.append({"type": "MCP server removed", "detail": sv["server"], "review": False})
    for cls in sorted(set(new.get("cloud", [])) - set(old.get("cloud", []))):
        r.append({"type": "cloud reach added", "detail": f"aws:{cls}", "review": True})
    if new["trifecta"] and not old["trifecta"]:
        r.append({"type": "trifecta completed", "detail": "private data + untrusted input + a way out are now all present", "review": True})
    reduced = len(ka - kb) + len(ca - cb) + len(set(old.get("cloud", [])) - set(new.get("cloud", [])))
    if reduced:
        r.append({"type": "reach reduced", "detail": f"{reduced} credential/capability/cloud item(s) no longer reachable", "review": False})
    return r


def review(ledger: dict, report: dict, today: date, soon_days: int = SOON_DAYS) -> dict:
    current = report["agents"]
    covered = set()
    rows = []
    for ap in ledger["approvals"]:
        reasons = []
        snap = {s.get("key") or agent_key(s): s for s in ap["snapshot"]["agents"]}
        now = {agent_key(a): a for a in current.values() if any(selects(s, a) for s in ap["agents"])}
        covered |= set(now)
        for k in sorted(set(snap) - set(now)):
            reasons.append({"type": "agent not found", "detail": f"{k}: confirm it was retired, or that the scan covered it", "review": False, "verify": True})
        for k in sorted(set(now) - set(snap)):
            reasons.append({"type": "new agent under this approval", "detail": k, "review": True})
        for k in sorted(set(now) & set(snap)):
            for x in _reasons_for(snap[k], now[k]):
                x["detail"] = f"{k}: {x['detail']}"
                reasons.append(x)
        until = _parse_date(ap["valid_until"], "valid_until")
        if today > until:
            reasons.append({"type": "evidence expired", "detail": f"approval evidence expired on {ap['valid_until']}", "review": False, "expired": True})
        elif (until - today).days <= soon_days:
            reasons.append({"type": "evidence expiring", "detail": f"approval evidence expires on {ap['valid_until']}", "review": False, "soon": True})
        if any(x.get("review") for x in reasons):
            status = "re-review required"
        elif any(x.get("expired") for x in reasons):
            status = "evidence expired"
        elif any(x.get("verify") for x in reasons) or not report["complete"]:
            status = "verify"
        elif any(x.get("soon") for x in reasons):
            status = "expiring soon"
        else:
            status = "current"
        for x in reasons:
            x["ref"] = REF_CHANGE if x.get("review") else REF_PERIODIC if (x.get("expired") or x.get("soon")) else ""
        rows.append({"system": ap["system"], "owner": ap.get("owner", ""), "scope": ap.get("scope", ""),
                     "approved_by": ap["approved_by"], "approved_on": ap["approved_on"], "valid_until": ap["valid_until"],
                     "status": status, "reasons": reasons, "agents_checked": sorted(now)})
    rows.sort(key=lambda r: (STATUS_ORDER.index(r["status"]), r["system"].lower()))
    unapproved = sorted(set(agent_key(a) for a in current.values()) - covered)
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in STATUS_ORDER}
    return scrub_tree({"tool": "scopewake", "version": __version__, "kind": "approval-review", "date": _iso(today),
                       "scan_complete": report["complete"],
                       "disclaimer": "Indicative mapping, not legal advice. The owner decides whether a change is significant.",
                       "summary": counts, "approvals": rows, "unapproved_agents": unapproved,
                       "unapproved_ref": REF_APPROVED if unapproved else ""})


def needs_action(res: dict) -> bool:
    s = res["summary"]
    return bool(s["re-review required"] or s["evidence expired"] or res["unapproved_agents"])


def review_text(res: dict, markdown: bool = False) -> str:
    s = res["summary"]
    head = (f"{s['re-review required']} re-review required, {s['evidence expired']} evidence expired, {s['verify']} to verify, "
            f"{s['expiring soon']} expiring soon, {s['current']} current; {len(res['unapproved_agents'])} unapproved agent(s)")
    L = [("# Approval review" if markdown else "scopewake review") + f" ({res['date']})", "", head, ""]
    if not res["scan_complete"]:
        L += ["WARNING: the scan was incomplete, so no approval can be shown to be current.", ""]
    for r in res["approvals"]:
        L.append((f"## {safe(r['system'], 80)}: {r['status']}" if markdown else f"[{r['status']}] {safe(r['system'], 80)}"))
        ind = "" if markdown else "  "
        L.append(f"{ind}approved by {safe(r['approved_by'], 60)} on {r['approved_on']}, valid until {r['valid_until']}"
                 + (f"; owner {safe(r['owner'], 60)}" if r["owner"] else ""))
        if markdown and r["reasons"]:
            L.append("")
        for x in r["reasons"]:
            mark = ("- **" + safe(x["type"], 40) + "**" if x.get("review") else "- " + safe(x["type"], 40)) if markdown else \
                f"  {'!' if x.get('review') else '-'} {safe(x['type'], 40)}"
            L.append(f"{mark}: {safe(x['detail'], 300)}" + (f"  [{x['ref']}]" if x["ref"] else ""))
        L.append("")
    if res["unapproved_agents"]:
        L.append(("## Agents with no approval" if markdown else "agents with no approval") + f"  [{res['unapproved_ref']}]")
        L += [("- " if markdown else "  - ") + safe(k, 200) for k in res["unapproved_agents"]]
    L += ["", res["disclaimer"]]
    return "\n".join(L)


def review_csv(res: dict) -> str:
    """One row per approval, for import into a GRC or ticketing tool."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["system", "status", "owner", "approved_by", "approved_on", "valid_until", "reasons", "regulatory_ref"])
    for r in res["approvals"]:
        refs = sorted({x["ref"] for x in r["reasons"] if x["ref"]})
        w.writerow([r["system"], r["status"], r["owner"], r["approved_by"], r["approved_on"], r["valid_until"],
                    "; ".join(f"{x['type']}: {x['detail']}" for x in r["reasons"]), "; ".join(refs)])
    for k in res["unapproved_agents"]:
        w.writerow([k, "no approval", "", "", "", "", "agent in use with no recorded approval", res["unapproved_ref"]])
    return buf.getvalue()
