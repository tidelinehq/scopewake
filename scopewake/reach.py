"""Reach graph: what every agent in a report can touch, directly or through other agents.

`scan`, `import` and `merge` describe each agent on its own. An agent that can call another agent inherits that
agent's reach, so a change to the second agent changes the first one's reach without touching its configuration.
This module joins the agents of one report into a graph and answers two questions: who can reach a given system,
and what does each agent reach only through other agents.

Offline and read-only: works on a normalised report (see `diff.normalize`); names and locations only.
Limits: agent-to-agent links come from what an export declares (for example `ConnectedAgents`); a link whose target
is not in the report is listed as unresolved, and its reach is unknown, not zero. Links are followed up to MAX_HOPS.
"""
from typing import Dict, List, Tuple

from . import __version__
from .approvals import agent_key
from .safe import safe, scrub_tree

MAX_HOPS = 5
LINK_PREFIX = "agent:"


def direct_targets(a: dict) -> List[Tuple[str, str]]:
    """(type, label) for everything the agent reaches itself. Links to other agents are edges, not targets."""
    t = set()
    for c in a["credentials"]:
        if not c["mitigated"]:
            t.add(("credential", f"{c['kind']} at {c['loc']}" + (f" ({c['name']})" if c["name"] else "")))
    for c in a["capabilities"]:
        if not c["name"].startswith(LINK_PREFIX):
            t.add(("capability", c["name"]))
    for (_, name), sv in a["servers"].items():
        t.add(("server", name + (f" ({sv['endpoint']})" if sv.get("endpoint") else "")))
    for cls in a.get("cloud", []):
        t.add(("cloud", f"aws:{cls}"))
    return sorted(t)


def links(a: dict) -> List[str]:
    """Declared connected agents, as written in the export (fingerprint suffix removed)."""
    out = {c["name"][len(LINK_PREFIX):].split("#")[0].strip() for c in a["capabilities"] if c["name"].startswith(LINK_PREFIX)}
    return sorted(x for x in out if x)


def evidence_for(a: dict) -> Dict[Tuple[str, str], List[str]]:
    """Where each direct target was read from. Credentials and servers come from the scan of the agent's own files."""
    ev: Dict[Tuple[str, str], set] = {}
    for c in a["capabilities"]:
        if not c["name"].startswith(LINK_PREFIX):
            ev.setdefault(("capability", c["name"]), set()).add(c["via"] or "agent configuration")
    out = {k: sorted(v) for k, v in ev.items()}
    for t in direct_targets(a):
        out.setdefault(t, ["cloud export (approximate)"] if t[0] == "cloud" else ["agent configuration"])
    return out


def link_evidence(a: dict) -> Dict[str, List[str]]:
    ev: Dict[str, set] = {}
    for c in a["capabilities"]:
        if c["name"].startswith(LINK_PREFIX):
            ev.setdefault(c["name"][len(LINK_PREFIX):].split("#")[0].strip(), set()).add(c["via"] or "agent configuration")
    return {k: sorted(v) for k, v in ev.items()}


# What an edge in this graph does and does not claim. Each later state needs evidence this tool does not collect.
SEMANTICS = {
    "state": "configured",
    "ladder": ["configured", "connected", "invocable", "authorised", "effective", "observed"],
    "meaning": "Every edge is configured reach: it is written in the agent's configuration or declared in an export. "
               "The graph does not show that a connection works, that a call would be authorised at run time, what "
               "the effective permission is after deny rules or group membership, or that anything was ever invoked.",
}


def build(report: dict) -> dict:
    agents = {agent_key(a): a for a in report["agents"].values()}
    by_name: Dict[str, List[str]] = {}
    for k, a in agents.items():
        for handle in {a["name"].lower(), a["rel"].lower()} - {""}:
            by_name.setdefault(handle, []).append(k)
    edges: Dict[str, List[str]] = {k: [] for k in agents}
    unresolved, ambiguous = [], []
    for k, a in agents.items():
        for label in links(a):
            hits = sorted(set(by_name.get(label.lower(), [])) - {k})
            if len(hits) == 1:
                edges[k].append(hits[0])
            elif hits:
                ambiguous.append({"agent": k, "link": label, "candidates": hits})
            else:
                unresolved.append({"agent": k, "link": label})
        edges[k] = sorted(set(edges[k]))
    direct = {k: direct_targets(a) for k, a in agents.items()}
    evid = {k: evidence_for(a) for k, a in agents.items()}
    link_ev = {k: link_evidence(a) for k, a in agents.items()}
    resolved_as: Dict[Tuple[str, str], str] = {}
    for k, a in agents.items():
        for label in links(a):
            hits = sorted(set(by_name.get(label.lower(), [])) - {k})
            if len(hits) == 1:
                resolved_as[(k, hits[0])] = label
    indirect: Dict[str, List[dict]] = {}
    truncated = False
    for k in agents:
        seen, frontier, found = {k}, [(k, [k])], {}
        own = set(direct[k])
        for hop in range(MAX_HOPS + 1):
            nxt = []
            for node, path in frontier:
                for m in edges[node]:
                    if m in seen:
                        continue
                    if hop == MAX_HOPS:
                        truncated = True
                        continue
                    seen.add(m)
                    p = path + [m]
                    for t in direct[m]:
                        if t not in own and t not in found:
                            found[t] = p          # breadth-first, so the first path is a shortest one
                    nxt.append((m, p))
            frontier = nxt
            if not frontier:
                break
        indirect[k] = [{"type": t[0], "target": t[1], "path": p, "state": "configured", "evidence": evid[p[-1]][t]}
                       for t, p in sorted(found.items())]
    targets: Dict[Tuple[str, str], List[dict]] = {}
    for k in sorted(agents):
        for t in direct[k]:
            targets.setdefault(t, []).append({"agent": k, "direct": True, "path": [k], "state": "configured", "evidence": evid[k][t]})
        for x in indirect[k]:
            targets.setdefault((x["type"], x["target"]), []).append({"agent": k, "direct": False, "path": x["path"],
                                                                     "state": "configured", "evidence": x["evidence"]})
    complete = bool(report["complete"]) and not unresolved and not ambiguous and not truncated
    return scrub_tree({
        "tool": "scopewake", "version": __version__, "kind": "reach-graph", "semantics": SEMANTICS,
        "coverage": {"complete": complete, "scan_complete": bool(report["complete"]), "max_hops": MAX_HOPS,
                     "truncated": truncated, "unresolved_links": unresolved, "ambiguous_links": ambiguous},
        "note": "Reach is inferred from configuration and exports, not observed at runtime. An unresolved link means "
                "reach through that agent is unknown, not absent.",
        "agents": [{"agent": k, "direct": [list(t) for t in direct[k]], "calls": edges[k],
                    "links": [{"to": m, "state": "configured", "declared_as": resolved_as[(k, m)],
                               "evidence": link_ev[k].get(resolved_as[(k, m)], [])} for m in edges[k]],
                    "indirect": indirect[k]}
                   for k in sorted(agents)],
        "targets": [{"type": t[0], "target": t[1], "reached_by": v} for t, v in sorted(targets.items())]})


def indirect_by_agent(graph: dict) -> Dict[str, List[List[str]]]:
    """agent key -> sorted [type, target, via] where `via` is the last agent on the path (the one that holds it)."""
    return {a["agent"]: sorted([x["type"], x["target"], x["path"][-1]] for x in a["indirect"]) for a in graph["agents"]}


def select(graph: dict, needle: str) -> dict:
    """Keep only the targets whose type or label contains `needle` (case-insensitive)."""
    n = needle.strip().lower()
    g = dict(graph)
    g["query"] = needle
    g["targets"] = [t for t in graph["targets"] if n in t["target"].lower() or n == t["type"]]
    return g


def _via(path: List[str]) -> str:
    return "direct" if len(path) == 1 else "via " + " -> ".join(safe(p, 80) for p in path[1:])


def to_text(g: dict, markdown: bool = False) -> str:
    cov = g["coverage"]
    n_ind = sum(len(a["indirect"]) for a in g["agents"])
    h = (lambda s: f"## {s}") if markdown else (lambda s: s)
    b = "- " if markdown else "  - "
    L = [("# Reach graph" if markdown else "scopewake reach") + f": {len(g['agents'])} agent(s), "
         f"{len(g['targets'])} target(s){' matching ' + repr(safe(g['query'], 60)) if 'query' in g else ''}, "
         f"{n_ind} reached only through another agent", ""]
    if not cov["scan_complete"]:
        L += ["WARNING: the scan was incomplete, so reach may be understated.", ""]
    if "query" in g:
        L.append(h("who can reach it"))
        shown = g["targets"]
    else:
        L.append(h("shared or indirect reach (targets reached by more than one agent, or through another agent)"))
        shown = [t for t in g["targets"] if len(t["reached_by"]) > 1 or any(not r["direct"] for r in t["reached_by"])]
    if not shown:
        L.append(b + "none")
    for t in shown:
        L.append(f"{b}{t['type']} {safe(t['target'], 200)}")
        for r in t["reached_by"]:
            L.append(f"{'  ' if markdown else '    '}{b.strip()} {safe(r['agent'], 160)}: {_via(r['path'])}")
    if "query" not in g:
        L += ["", h("reach gained through other agents")]
        rows = [a for a in g["agents"] if a["indirect"]]
        if not rows:
            L.append(b + "none")
        for a in rows:
            L.append(f"{b}{safe(a['agent'], 160)}")
            for x in a["indirect"]:
                L.append(f"{'  ' if markdown else '    '}+ {x['type']} {safe(x['target'], 200)} ({_via(x['path'])})")
    if cov["unresolved_links"] or cov["ambiguous_links"]:
        L += ["", h("connected agents that could not be followed (reach through them is unknown)")]
        L += [f"{b}{safe(u['agent'], 160)} -> {safe(u['link'], 120)}: not in this report" for u in cov["unresolved_links"]]
        L += [f"{b}{safe(u['agent'], 160)} -> {safe(u['link'], 120)}: matches {len(u['candidates'])} agents" for u in cov["ambiguous_links"]]
    if cov["truncated"]:
        L += ["", f"Chains longer than {cov['max_hops']} agents were not followed."]
    L += ["", g["semantics"]["meaning"], g["note"]]
    return "\n".join(L)


def _mm(text: str, limit: int = 56) -> str:
    import re
    t = re.sub(r"[^A-Za-z0-9 _./:@()+\-]", " ", str(text)).strip()
    return (t[: limit - 1] + "...") if len(t) > limit else t


def to_mermaid(g: dict, max_targets: int = 40) -> str:
    """Agents, the calls between them, and the targets that are shared or reached indirectly."""
    L = ["flowchart LR", "  classDef agent fill:#0B7F73,stroke:#0B7F73,color:#fff;",
         "  classDef target fill:#4A5668,stroke:#4A5668,color:#fff;",
         "  classDef gap fill:#fff,stroke:#B42318,color:#0E1726,stroke-dasharray: 4 3;"]
    ids = {a["agent"]: f"A{i}" for i, a in enumerate(g["agents"])}
    for a in g["agents"]:
        L.append(f'  {ids[a["agent"]]}["{_mm(a["agent"])}"]:::agent')
    for a in g["agents"]:
        for c in a["calls"]:
            L.append(f'  {ids[a["agent"]]} -->|calls| {ids[c]}')
    shown = g["targets"] if "query" in g else [t for t in g["targets"] if len(t["reached_by"]) > 1 or any(not r["direct"] for r in t["reached_by"])]
    for i, t in enumerate(shown[:max_targets]):
        L.append(f'  T{i}["{_mm(t["type"] + " " + t["target"])}"]:::target')
        for r in t["reached_by"]:
            L.append(f'  {ids[r["agent"]]} {"-->" if r["direct"] else "-.->"} T{i}')
    if len(shown) > max_targets:
        L.append(f'  more["{len(shown) - max_targets} more target(s) not drawn"]:::gap')
    for i, u in enumerate(g["coverage"]["unresolved_links"]):
        L.append(f'  U{i}["{_mm(u["link"])} (not in report)"]:::gap')
        L.append(f'  {ids[u["agent"]]} -.->|calls| U{i}')
    return "\n".join(L)
