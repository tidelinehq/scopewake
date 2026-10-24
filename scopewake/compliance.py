"""Regulatory evidence pack: merges a scan with an AI inventory the firm maintains.

Indicative mapping, not legal advice. The firm decides whether it complies; this file only reports what the
scan and the inventory show, and marks what a local scan cannot see.
"""
import json
from pathlib import Path
from typing import Dict, List, Optional

from . import __version__
from .model import Agent
from .safe import safe, scrub_tree

MAX_INVENTORY_BYTES = 2 * 1024 * 1024

# MAS Guidelines on AI Risk Management, paragraph 4.7 (inventory attributes) + owner and documentation links.
INVENTORY_FIELDS = ["purpose", "scope_of_use", "model_type", "data_used", "lifecycle_status",
                    "materiality", "review_status", "owner", "documentation"]
MATERIALITY = {"low", "medium", "high"}

FRAMEWORKS = {
    "mas-airm": {
        "title": "MAS Guidelines on AI Risk Management (issued 7 Oct 2026)",
        "dates": "Sections 3-4 (oversight, identification, inventory, materiality) apply from 7 Oct 2027; sections 5-6 (life-cycle controls) by 7 Oct 2028.",
        "review": "Mapped to paragraph numbers in the issued text.",
        "controls": [
            ("para 4.2, fn 21", "Identify AI, including AI in services from material third parties and SaaS not sold as AI", "identify"),
            ("para 4.7", "Inventory with purpose, scope, model type, data, dependencies, status, materiality, review status, owners, documentation", "inventory"),
            ("para 4.8, fn 25", "For AI agents: the tools and systems the agent can access, and the guardrails applied", "agent_reach"),
            ("section 4", "Risk materiality assessment for each AI use", "materiality"),
            ("para 5.11", "The FI stays accountable for third-party AI", "third_party"),
            ("paras 2.3-2.5", "Basic governance: approved AI tool list and process (minimum for every FI)", "approved"),
            ("paras 5.24-5.25", "Significant changes trigger review and re-approval before implementation (applies by 7 Oct 2028)", "change_review"),
        ],
    },
    "eu-ai-act": {
        "title": "EU AI Act, deployer obligations (high-risk systems)",
        "review": "DRAFT mapping: applicability, entity role and control references need review by counsel before customer use.",
        "dates": "High-risk dates moved to 2 Dec 2027 (Annex III) and 2 Aug 2028 (Annex I) under the omnibus agreement, pending formal adoption.",
        "controls": [
            ("Art. 26(2)", "Assign human oversight", "oversight"),
            ("Art. 26(5)", "Monitor operation of the system", "monitoring"),
            ("Art. 26(6)", "Keep automatically generated logs", "none"),
            ("Art. 4", "AI literacy of staff", "none"),
        ],
    },
    "nydfs": {
        "title": "NYDFS 23 NYCRR Part 500 (cybersecurity), as applied to AI",
        "review": "DRAFT mapping: applicability, entity role and control references need review by counsel before customer use.",
        "dates": "In force; asset inventory and MFA requirements apply from Nov 2025.",
        "controls": [
            ("500.13", "Asset inventory", "inventory"),
            ("500.7", "Access privileges limited to what is needed", "least_privilege"),
            ("500.11", "Third-party service provider security", "third_party"),
            ("500.9", "Risk assessment covering AI", "materiality"),
        ],
    },
    "apra": {
        "title": "APRA: AI letter (May 2026), CPS 234 and CPS 230",
        "review": "DRAFT mapping: applicability, entity role and control references need review by counsel before customer use.",
        "dates": "The AI letter sets expectations, not a binding rule; CPS 234 and CPS 230 are binding standards.",
        "controls": [
            ("AI letter", "Inventory of AI tooling and use cases, with clear ownership", "inventory"),
            ("AI letter", "Privileged access management and controls over agentic workflows", "least_privilege"),
            ("CPS 230", "Management of material service providers, incl. AI supply chain", "third_party"),
            ("CPS 234", "Identify and classify information assets", "identify"),
        ],
    },
    "hkma": {
        "title": "HKMA High-level Principles on AI (Nov 2019)",
        "review": "DRAFT mapping: applicability, entity role and control references need review by counsel before customer use.",
        "dates": "Supervisory principles for authorised institutions.",
        "controls": [
            ("Governance", "Board and senior management accountable; clear ownership", "owners"),
            ("Third parties", "Due diligence and oversight of AI vendors", "third_party"),
            ("Monitoring", "Ongoing monitoring of AI applications", "monitoring"),
        ],
    },
}


def load_inventory(path: str) -> dict:
    p = Path(path)
    try:
        if p.stat().st_size > MAX_INVENTORY_BYTES:
            raise ValueError("inventory is larger than 2 MB")
        data = json.loads(p.read_text(encoding="utf-8"))
    except OSError:
        raise ValueError(f"cannot read inventory {safe(path, 200)}")
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ValueError(f"inventory {safe(path, 200)} is not valid JSON")
    if not isinstance(data, dict) or not isinstance(data.get("systems", []), list):
        raise ValueError("inventory must be an object with a 'systems' list")
    systems = []
    for i, row in enumerate(data.get("systems", [])):
        if not isinstance(row, dict):
            raise ValueError(f"inventory system {i} is not an object")
        systems.append({k: v for k, v in row.items() if isinstance(k, str)})
    approved = data.get("approved_tools", [])
    if not isinstance(approved, list) or not all(isinstance(x, str) for x in approved):
        raise ValueError("'approved_tools' must be a list of strings")
    return {"organisation": str(data.get("organisation", "")), "systems": systems, "approved_tools": approved}


def suggested_materiality(score: int) -> str:
    return "high" if score >= 70 else "medium" if score >= 40 else "low"


def _match(row: dict, a: Agent) -> bool:
    m = str(row.get("match", "")).strip().lower()
    return bool(m) and m in {a.id.lower(), a.kind.lower(), a.name.lower()}


def build_rows(agents: List[Agent], inv: Optional[dict]) -> List[dict]:
    """One row per discovered agent (scan + inventory) and per declared-only system (e.g. AI inside SaaS)."""
    inv = inv or {"systems": [], "approved_tools": []}
    used, rows = set(), []
    for a in agents:
        idx = next((i for i, r in enumerate(inv["systems"]) if i not in used and _match(r, a)), None)
        row = dict(inv["systems"][idx]) if idx is not None else {}
        if idx is not None:
            used.add(idx)
        live = [c for c in a.credentials if not c.mitigated]
        reach = sorted({c.kind for c in live} | {c.name for c in a.capabilities}
                       | {"aws:" + c["class"] for c in a.cloud.get("classes", [])})
        guard = [f"autonomy {a.autonomy:.1f} ({a.autonomy_note or 'default'})"]
        mitig = sum(1 for c in a.credentials if c.mitigated)
        if mitig:
            guard.append(f"{mitig} credential path(s) blocked by deny rules")
        rows.append({
            "system": a.name, "source": "scan", "agent_id": a.id, "score": a.score,
            "tools_and_systems_accessible": reach,
            "guardrails_observed": guard,
            "dependencies": [f"{s['name']} ({s['transport']}, {s['endpoint']})" for s in a.servers],
            "remote_dependencies": [s["name"] for s in a.servers if s.get("transport") == "remote"],
            "suggested_materiality": suggested_materiality(a.score),
            **{f: row.get(f, "") for f in INVENTORY_FIELDS},
        })
    for i, r in enumerate(inv["systems"]):
        if i in used:
            continue
        rows.append({"system": str(r.get("name") or r.get("match") or f"system {i}"), "source": "declared",
                     "agent_id": "", "score": None, "tools_and_systems_accessible": [], "guardrails_observed": [],
                     "dependencies": [str(x) for x in r.get("dependencies", [])] if isinstance(r.get("dependencies"), list) else [],
                     "remote_dependencies": [], "suggested_materiality": "",
                     **{f: r.get(f, "") for f in INVENTORY_FIELDS}})
    for r in rows:
        r["missing_fields"] = [f for f in INVENTORY_FIELDS if not str(r.get(f, "")).strip()]
        if r.get("materiality") and str(r["materiality"]).lower() not in MATERIALITY:
            r["missing_fields"].append("materiality (must be low, medium or high)")
    return rows


def _check(kind: str, rows: List[dict], agents: List[Agent], inv: Optional[dict], review: Optional[dict] = None):
    """(status, evidence). Status: evidenced | partial | gap | not covered."""
    scanned = [r for r in rows if r["source"] == "scan"]
    declared = [r for r in rows if r["source"] == "declared"]
    if kind in ("least_privilege", "oversight", "agent_reach", "monitoring") and not scanned:
        return "gap", "No agents found by the scan, so nothing here can be evidenced."
    if kind == "identify" and not rows:
        return "gap", "No AI systems found by the scan or declared in the inventory."
    if kind == "identify":
        msg = f"{len(scanned)} agent(s) found by local scan; {len(declared)} system(s) declared in the inventory."
        if not declared:
            return "partial", msg + " A local scan cannot see AI inside SaaS products; declare those systems in the inventory."
        return "evidenced", msg
    if kind in ("inventory", "owners"):
        if not rows:
            return "gap", "No AI systems found or declared."
        field = ["owner"] if kind == "owners" else INVENTORY_FIELDS
        bad = [r for r in rows if any(f in r["missing_fields"] for f in field)]
        if not inv:
            return "gap", "No inventory supplied (--inventory). Generate a template with --inventory-template."
        if bad:
            return "gap", f"{len(bad)} of {len(rows)} system(s) missing attributes: " + "; ".join(
                f"{safe(r['system'], 60)}: {', '.join(f for f in r['missing_fields'] if f in field or kind == 'inventory')}" for r in bad[:10])
        return "evidenced", f"All {len(rows)} system(s) have the required attributes."
    if kind == "agent_reach":
        if not scanned:
            return "gap", "No agents found by the scan."
        return "evidenced", f"Tools, systems and guardrails recorded for {len(scanned)} agent(s) from the scan."
    if kind == "materiality":
        if not rows:
            return "gap", "No AI systems found or declared."
        missing = [r for r in rows if not str(r.get("materiality", "")).strip()]
        if missing:
            return "partial", f"{len(missing)} system(s) have only a suggested materiality from the blast-radius score; the firm must assess and record it."
        return "evidenced", f"Materiality recorded for all {len(rows)} system(s)."
    if kind == "third_party":
        remote = sorted({d for r in rows for d in r["remote_dependencies"]})
        return "partial", (f"Remote (third-party) MCP servers in use: {', '.join(safe(x, 60) for x in remote)}. " if remote else "No remote MCP servers found. ") + \
            "Due diligence on providers is the firm's; Scopewake lists them and flags changes (scopewake diff)."
    if kind == "approved":
        if not inv or not inv.get("approved_tools"):
            return "gap", "No approved AI tool list in the inventory ('approved_tools')."
        ok = {t.lower() for t in inv["approved_tools"]}
        unapproved = sorted({a.name for a in agents if a.name.lower() not in ok and a.kind.lower() not in ok}
                            | {s["name"] for a in agents for s in a.servers if s["name"].lower() not in ok})
        if unapproved:
            return "gap", "In use but not on the approved list: " + ", ".join(safe(x, 60) for x in unapproved[:20])
        return "evidenced", "Every discovered agent and MCP server is on the approved list."
    if kind == "least_privilege":
        wide = [r for r in rows if r["source"] == "scan" and (r["score"] or 0) >= 70]
        if wide:
            return "gap", f"{len(wide)} agent(s) reach high-impact credentials or capabilities (score >= 70): " + \
                ", ".join(safe(r["system"], 60) for r in wide) + ". See `scopewake fix`."
        return "evidenced", "No agent scores 70 or above."
    if kind == "oversight":
        auto = [a.name for a in agents if a.autonomy >= 0.9]
        if auto:
            return "gap", "Agents running commands without approval: " + ", ".join(safe(x, 60) for x in auto)
        return "partial", "Command approval is required for all scanned agents; named human overseers are the firm's to record."
    if kind == "change_review":
        if review is None:
            return "gap", "No approvals ledger supplied (--approvals). Record approvals with `scopewake approve`."
        if not review["approvals"]:
            return "gap", "The approvals ledger is empty."
        s = review["summary"]
        stale = [r["system"] for r in review["approvals"] if r["status"] in ("re-review required", "evidence expired")]
        msg = (f"{len(review['approvals'])} approval(s) checked against the current scan: {s['re-review required']} need re-review, "
               f"{s['evidence expired']} expired, {s['current']} current.")
        if stale or review["unapproved_agents"]:
            return "gap", msg + (" Stale: " + ", ".join(safe(x, 60) for x in stale[:10]) + "." if stale else "") + \
                (f" {len(review['unapproved_agents'])} agent(s) have no approval." if review["unapproved_agents"] else "")
        if not review["scan_complete"] or s["verify"]:
            return "partial", msg + " Some agents could not be confirmed; see `scopewake review`."
        return "evidenced", msg + " Each approval matches the reach recorded when it was granted."
    if kind == "monitoring":
        return "partial", "Reach drift is monitored when `scopewake diff --fail-on-increase` runs in CI against a stored baseline."
    return "not covered", "Outside what a local scan can show."


def build_pack(agents: List[Agent], inv: Optional[dict], frameworks: List[str], issues: Optional[List[str]] = None,
               review: Optional[dict] = None) -> dict:
    rows = build_rows(agents, inv)
    fw = []
    for key in frameworks:
        spec = FRAMEWORKS[key]
        controls = []
        for ref, req, kind in spec["controls"]:
            status, ev = _check(kind, rows, agents, inv, review)
            controls.append({"ref": ref, "requirement": req, "status": status, "evidence": ev})
        fw.append({"framework": key, "title": spec["title"], "dates": spec["dates"], "review": spec["review"], "controls": controls})
    return scrub_tree({"tool": "scopewake", "version": __version__, "kind": "evidence-pack",
                       "organisation": (inv or {}).get("organisation", ""),
                       "disclaimer": "Indicative mapping, not legal advice. The firm decides whether it complies.",
                       "coverage": {"complete": not issues, "issues": list(issues or [])},
                       "systems": rows, "frameworks": fw})


def inventory_template(agents: List[Agent]) -> dict:
    return {"organisation": "", "approved_tools": sorted({a.name for a in agents} | {s["name"] for a in agents for s in a.servers}),
            "systems": [_template_row(a.id, a.name, suggested_materiality(a.score)) for a in agents]
            + [_template_row("", "Example: AI feature inside a SaaS product", "")]}


def _template_row(match: str, name: str, suggested: str) -> dict:
    row = {"match": match, "name": name}
    row.update({f: "" for f in INVENTORY_FIELDS})
    if suggested:
        row["_suggested_materiality"] = suggested
    else:
        row["dependencies"] = []
    return row


def pack_markdown(pack: dict) -> str:
    L = [f"# AI evidence pack{(' - ' + safe(pack['organisation'], 80)) if pack['organisation'] else ''}", "",
         f"Generated by scopewake {pack['version']}. {pack['disclaimer']} No secret values are included.", ""]
    if not pack["coverage"]["complete"]:
        L += [f"**Incomplete scan:** {len(pack['coverage']['issues'])} problem(s); results may understate risk.", ""]
    for f in pack["frameworks"]:
        L += [f"## {f['title']}", "", f["dates"], "", f"*{f['review']}*", "", "| Ref | Requirement | Status | Evidence |", "| --- | --- | --- | --- |"]
        L += [f"| {safe(c['ref'], 30)} | {safe(c['requirement'], 160)} | {c['status']} | {safe(c['evidence'], 600)} |" for c in f["controls"]]
        L.append("")
    L += ["## AI inventory", "", "| System | Source | Score | Materiality (recorded / suggested) | Owner | Missing attributes |", "| --- | --- | --- | --- | --- | --- |"]
    for r in pack["systems"]:
        L.append(f"| {safe(r['system'], 60)} | {r['source']} | {'' if r['score'] is None else r['score']} | "
                 f"{safe(r.get('materiality') or '-', 20)} / {r['suggested_materiality'] or '-'} | {safe(r.get('owner') or '-', 60)} | "
                 f"{safe(', '.join(r['missing_fields']) or 'none', 200)} |")
    for r in pack["systems"]:
        if r["source"] != "scan":
            continue
        L += ["", f"### {safe(r['system'], 60)}", f"- Tools and systems accessible: {safe(', '.join(r['tools_and_systems_accessible']) or 'none found', 800)}",
              f"- Guardrails observed: {safe('; '.join(r['guardrails_observed']), 400)}",
              f"- Dependencies (MCP servers): {safe(', '.join(r['dependencies']) or 'none', 800)}"]
    return "\n".join(L)
