import json
import re
from typing import List, Optional

from . import __version__
from .model import Agent
from .safe import safe, scrub, scrub_tree


def _coverage(issues: Optional[List[str]]) -> dict:
    issues = list(issues or [])
    return {"complete": not issues, "issues": issues}


def to_json(agents: List[Agent], issues: Optional[List[str]] = None) -> str:
    doc = {"tool": "tideline", "version": __version__, "schema": 1, "coverage": _coverage(issues),
           "note": "Capabilities are inferred from config names and launch arguments, not verified.",
           "agents": [a.to_dict() for a in agents]}
    # Redact before serialising: JSON escaping (for example a newline) can hide a secret from a text scrub.
    return json.dumps(scrub_tree(doc), indent=2, allow_nan=False)


def to_markdown(agents: List[Agent], issues: Optional[List[str]] = None) -> str:
    lines = ["# Agent blast-radius report", "",
             "Local scan; read-only; no secret values were read into this report (names and locations only). "
             "Capabilities are inferred from config names and launch arguments, not verified.", ""]
    if issues:
        lines += [f"**Incomplete scan:** {len(issues)} problem(s); results may understate risk."] + [f"- {safe(i, 200)}" for i in issues] + [""]
    if not agents:
        lines.append("No AI agents or agent configs were found in the scanned locations.")
        return "\n".join(lines)
    lines += ["| Rank | Agent | Score | Potential trifecta | Autonomy | Exposure | Unmitigated credentials | Capabilities |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for i, a in enumerate(agents, 1):
        live = sum(1 for c in a.credentials if not c.mitigated)
        caps = ", ".join(sorted({safe(c.name, 40) for c in a.capabilities})) or "-"
        lines.append(f"| {i} | {safe(a.name, 60)} | {a.score}/100 | {'yes' if a.trifecta else 'no'} | {a.autonomy:.1f} | {a.exposure:.1f} | {live} | {caps} |")
    for a in agents:
        lines += ["", f"## {safe(a.name, 60)} (score {a.score}/100)", f"Source: `{safe(a.source, 200)}`  ", f"Autonomy: {a.autonomy} {a.autonomy_note}".strip()]
        for n in a.notes:
            lines.append(f"- {safe(n, 300)}")
        if a.credentials:
            lines += ["", "Credentials reachable:"]
            seen = set()
            for c in a.credentials:
                key = (c.kind, c.location, c.name)
                if key in seen:
                    continue
                seen.add(key)
                tag = " (denied by rule)" if c.mitigated else ""
                lines.append(f"- {c.kind} severity {c.severity}: `{safe(c.location, 200)}` [{c.how}] name `{safe(c.name, 60)}`{tag}")
        if a.cloud:
            lines += ["", f"AWS reach as {safe(a.cloud.get('type'), 8)} `{safe(a.cloud.get('name'), 60)}` (from IAM export, approximate):"]
            lines += [f"- {c['class']} severity {c['severity']} ({c['level']}, {safe(c['via'], 120)}): {c['impact']}" for c in a.cloud.get("classes", [])] or ["- no high-impact action classes"]
        if a.chains:
            lines += ["", "Worst-case chains:"] + [f"- {safe(c, 400)}" for c in a.chains]
        if a.fixes:
            lines += ["", "Fixes:"] + [f"- {safe(f, 600)}" for f in a.fixes]
    lines += ["", "Scores are a heuristic ranking, not a measured probability."]
    return "\n".join(lines)


def to_text(agents: List[Agent], issues: Optional[List[str]] = None) -> str:
    warn = [f"WARNING incomplete scan ({len(issues)} problem(s)); results may understate risk:"] + [f"  - {safe(i, 200)}" for i in issues] + [""] if issues else []
    if not agents:
        return "\n".join(warn + ["tideline: no AI agents or agent configs found."])
    out = warn + ["tideline: agents ranked by worst-case blast radius (capabilities inferred from config, not verified)", ""]
    for i, a in enumerate(agents, 1):
        live = sum(1 for c in a.credentials if not c.mitigated)
        flag = "  POTENTIAL-TRIFECTA" if a.trifecta else ""
        out.append(f"{i}. {safe(a.name, 60):<28} score {a.score:>3}/100  autonomy {a.autonomy:.1f}  exposure {a.exposure:.1f}  creds {live}{flag}")
        if a.cloud:
            out.append(f"     aws: {safe(a.cloud.get('type'), 8)} {safe(a.cloud.get('name'), 60)} worst severity {a.cloud.get('max_severity')} "
                       f"({', '.join(c['class'] for c in a.cloud.get('classes', [])[:4]) or 'no high-impact actions'})")
        for ch in a.chains[:2]:
            out.append(f"     - {safe(ch, 400)}")
        for f in a.fixes[:2]:
            out.append(f"     fix: {safe(f, 600)}")
    return "\n".join(out)



def _label(text: str, limit: int = 48) -> str:
    """Make a string safe inside a Mermaid quoted label."""
    t = re.sub(r"[^A-Za-z0-9 _./:@()+\-]", " ", str(text)).strip()
    return (t[: limit - 1] + "...") if len(t) > limit else t


def to_mermaid(agents: List[Agent], issues: Optional[List[str]] = None) -> str:
    """One flowchart: untrusted inputs -> agent -> what it can reach. Names and kinds only."""
    lines = ["flowchart LR",
             "  classDef agent fill:#0B7F73,stroke:#0B7F73,color:#fff;",
             "  classDef high fill:#B42318,stroke:#B42318,color:#fff;",
             "  classDef mid fill:#8F5500,stroke:#8F5500,color:#fff;",
             "  classDef low fill:#4A5668,stroke:#4A5668,color:#fff;",
             "  classDef entry fill:#fff,stroke:#8F5500,color:#0E1726,stroke-dasharray: 4 3;"]
    if issues:
        lines.append(f'  incomplete["INCOMPLETE SCAN: {len(issues)} problem(s); graph may understate risk"]:::high')
    if not agents:
        lines.append('  none["No AI agents found"]')
        return "\n".join(lines)
    for i, a in enumerate(agents):
        aid = f"A{i}"
        lines.append(f'  {aid}["{_label(a.name)}<br/>score {a.score}/100"]:::agent')
        entries = sorted({c.via for c in a.capabilities if c.untrusted_input and c.via})
        for j, e in enumerate(entries):
            lines.append(f'  {aid}e{j}(["{_label(e)}"]):::entry --> {aid}')
        assets, seen = [], set()
        for c in a.credentials:
            if c.mitigated:
                continue
            key = ("cred", c.kind, c.location)
            if key not in seen:
                seen.add(key)
                assets.append((c.severity, f"{c.kind} ({c.how})"))
        for c in a.capabilities:
            key = ("cap", c.name)
            if key not in seen:
                seen.add(key)
                assets.append((c.severity, c.name))
        for k, (sev, text) in enumerate(sorted(assets, reverse=True)[:8]):
            cls = "high" if sev >= 9 else "mid" if sev >= 7 else "low"
            lines.append(f'  {aid} --> {aid}r{k}["{_label(text)}<br/>severity {sev}"]:::{cls}')
    return "\n".join(lines)


def _uri(rel: str) -> Optional[str]:
    """Percent-encode a repository-relative path. Sources outside the repository get no location."""
    if not rel or rel.startswith(("~", "/")) or re.match(r"^[A-Za-z]:", rel) or ".." in rel.split("/"):
        return None
    ok = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/"
    return "".join(c if c in ok else "".join("%%%02X" % b for b in c.encode("utf-8")) for c in rel)


def to_sarif(agents: List[Agent], issues: Optional[List[str]] = None) -> str:
    """SARIF 2.1.0. Results for files outside the scanned repository carry no location (GitHub may not display them)."""
    def level(score: int) -> str:
        return "error" if score >= 70 else "warning" if score >= 40 else "note"
    results = []
    for a in agents:
        top = a.chains[0] if a.chains else "no reachable credentials or capabilities found"
        uri = _uri(a.source_rel)
        where = {"locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]} if uri else {}
        src = f" (source: {safe(a.source_rel, 200)})" if not uri else ""
        results.append(dict({
            "ruleId": "LM001",
            "level": level(a.score),
            "message": {"text": f"{safe(a.name, 60)}: blast radius {a.score}/100. {top}{src}"},
        }, **where))
        if a.trifecta:
            results.append(dict({
                "ruleId": "LM002",
                "level": "error",
                "message": {"text": f"{safe(a.name, 60)}: potential lethal trifecta (inferred from config). Untrusted input via {', '.join(a.trifecta_parts['untrusted_input'])}; "
                                    f"private data reachable; outbound via {', '.join(a.trifecta_parts['exfiltration'])}.{src}"},
            }, **where))
    doc = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
           "runs": [{"tool": {"driver": {"name": "tideline", "version": __version__,
                                         "rules": [{"id": "LM001", "name": "AgentBlastRadius",
                                                    "shortDescription": {"text": "AI agent can reach sensitive credentials or capabilities"}},
                                                   {"id": "LM002", "name": "PotentialLethalTrifecta",
                                                    "shortDescription": {"text": "Potential: agent combines untrusted input, private data and an outbound channel (inferred from config)"}}]}},
                     "invocations": [{"executionSuccessful": not issues,
                                      "toolExecutionNotifications": [{"level": "warning", "message": {"text": safe(i, 200)}} for i in (issues or [])]}],
                     "results": results}]}
    return json.dumps(scrub_tree(doc), indent=2, allow_nan=False)
