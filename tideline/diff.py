"""Compare two `tideline scan --format json` reports. Pure file comparison; no scanning, no network."""
import json
import math
from pathlib import Path

from .safe import safe

MAX_REPORT_BYTES = 8 * 1024 * 1024


def _no_constant(name):
    raise ValueError(f"non-finite number {name} is not allowed")


def _err(path, msg):
    return ValueError(f"{safe(path, 200)}: {safe(msg, 300)}")


def _str(obj, key, path, where, required=False):
    v = obj.get(key)
    if v is None:
        if required:
            raise _err(path, f"{where}: '{key}' is required")
        return ""
    if not isinstance(v, str):
        raise _err(path, f"{where}: '{key}' must be a string")
    return v


def _list_of_dicts(obj, key, path, where):
    v = obj.get(key)
    if v is None:
        return []
    if not isinstance(v, list) or not all(isinstance(x, dict) for x in v):
        raise _err(path, f"{where}: '{key}' must be a list of objects")
    return v


def _load(path: str) -> dict:
    p = Path(path)
    try:
        if p.stat().st_size > MAX_REPORT_BYTES:
            raise _err(path, "report is larger than 8 MB")
        text = p.read_text(encoding="utf-8")
    except OSError:
        raise _err(path, "cannot read file")
    except UnicodeDecodeError:
        raise _err(path, "not valid UTF-8")
    try:
        data = json.loads(text, parse_constant=_no_constant)
    except (ValueError, RecursionError):
        raise _err(path, "not valid JSON")
    return normalize(data, path)


def normalize(data, path: str = "<report>") -> dict:
    """Validate a parsed tideline JSON report and reduce each agent to the fields that define its reach."""
    if not isinstance(data, dict) or data.get("tool") != "tideline" or not isinstance(data.get("agents"), list):
        raise _err(path, "not a tideline JSON report")
    cov = data.get("coverage")
    complete = True
    if cov is not None:
        if not isinstance(cov, dict) or not isinstance(cov.get("complete", True), bool):
            raise _err(path, "'coverage' is malformed")
        complete = cov.get("complete", True)
    agents = []
    for i, a in enumerate(data["agents"]):
        where = f"agent {i}"
        if not isinstance(a, dict):
            raise _err(path, f"{where} is not an object")
        score = a.get("score", 0)
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 100:
            raise _err(path, f"{where}: 'score' must be a number from 0 to 100")
        creds = []
        for c in _list_of_dicts(a, "credentials", path, where):
            m = c.get("mitigated", False)
            if not isinstance(m, bool):
                raise _err(path, f"{where}: credential 'mitigated' must be true or false")
            creds.append({"kind": _str(c, "kind", path, where), "loc": _str(c, "loc_rel", path, where) or _str(c, "location", path, where),
                          "name": _str(c, "name", path, where), "mitigated": m})
        caps = [{"name": _str(c, "name", path, where), "via": _str(c, "via", path, where)}
                for c in _list_of_dicts(a, "capabilities", path, where)]
        tri = a.get("trifecta", False)
        if not isinstance(tri, bool):
            raise _err(path, f"{where}: 'trifecta' must be true or false")
        servers = {}
        for sv in _list_of_dicts(a, "servers", path, where):
            key = (_str(sv, "config", path, where), _str(sv, "name", path, where))
            servers[key] = {f: _str(sv, f, path, where) for f in ("transport", "endpoint", "args_hash", "fingerprint")}
            for f in ("env_names", "header_names"):
                v = sv.get(f, [])
                if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                    raise _err(path, f"{where}: server '{f}' must be a list of strings")
                servers[key][f] = sorted(v)
        cloud = a.get("cloud") or {}
        if not isinstance(cloud, dict):
            raise _err(path, f"{where}: 'cloud' must be an object")
        classes = sorted({_str(c, "class", path, where) for c in _list_of_dicts(cloud, "classes", path, where)} - {""})
        agents.append({"kind": _str(a, "kind", path, where, True), "name": _str(a, "name", path, where, True),
                       "rel": _str(a, "source_rel", path, where), "score": score, "trifecta": tri,
                       "credentials": creds, "capabilities": caps, "servers": servers, "cloud": classes})
    # Match agents by what and where they are (kind, name, path relative to the scan root), never by checkout path.
    agents.sort(key=lambda x: (x["kind"], x["name"], x["rel"]))
    out, seen = {}, {}
    for a in agents:
        base = (a["kind"], a["name"], a["rel"])
        seen[base] = seen.get(base, 0) + 1
        out[base + (seen[base],)] = a
    return {"agents": out, "complete": complete}


def _creds(a: dict) -> set:
    return {(c["kind"], c["loc"], c["name"]) for c in a["credentials"] if not c["mitigated"]}


def _caps(a: dict) -> set:
    return {(c["name"], c["via"]) for c in a["capabilities"]}


def _label(key) -> str:
    return safe(f"{key[0]}/{key[1]}" + (f" ({key[2]})" if key[2] else ""), 160)


def _server_changes(a: dict, b: dict) -> dict:
    """MCP server definitions added, removed or changed between two scans of one agent (names and shapes only)."""
    sa, sb = a.get("servers", {}), b.get("servers", {})
    out = {"servers_added": [], "servers_removed": [], "servers_changed": []}
    for k in sorted(set(sb) - set(sa)):
        out["servers_added"].append({"server": k[1], "config": k[0], "transport": sb[k]["transport"], "endpoint": sb[k]["endpoint"]})
    for k in sorted(set(sa) - set(sb)):
        out["servers_removed"].append({"server": k[1], "config": k[0]})
    for k in sorted(set(sa) & set(sb)):
        x, y = sa[k], sb[k]
        if x["fingerprint"] == y["fingerprint"] and x["fingerprint"]:
            continue
        what = []
        if x["transport"] != y["transport"]:
            what.append(f"transport {x['transport']} -> {y['transport']}")
        if x["endpoint"] != y["endpoint"]:
            what.append(f"endpoint {x['endpoint']} -> {y['endpoint']}")
        if x["args_hash"] != y["args_hash"]:
            what.append("launch arguments changed")
        for f, label in (("env_names", "env var"), ("header_names", "header")):
            for n in sorted(set(y[f]) - set(x[f])):
                what.append(f"new {label} {n}")
            for n in sorted(set(x[f]) - set(y[f])):
                what.append(f"removed {label} {n}")
        if what:
            out["servers_changed"].append({"server": k[1], "config": k[0], "changes": what})
    return out


def _server_change_is_risk(sc: dict) -> bool:
    if sc["servers_added"]:
        return True
    for c in sc["servers_changed"]:
        if any(w.startswith(("transport", "endpoint", "launch arguments", "new ")) for w in c["changes"]):
            return True
    return False


def diff_reports(old_path: str, new_path: str) -> dict:
    o, n = _load(old_path), _load(new_path)
    old, new = o["agents"], n["agents"]
    out = {"added_agents": [], "removed_agents": [], "changed": [], "worse": False,
           "old_complete": o["complete"], "new_complete": n["complete"]}
    if not n["complete"]:
        out["worse"] = True  # a scan that could not read everything cannot prove nothing grew
    for k in sorted(set(new) - set(old)):
        a = new[k]
        out["added_agents"].append({"agent": _label(k), "score": a["score"], "trifecta": a["trifecta"]})
        out["worse"] = True
    for k in sorted(set(old) - set(new)):
        out["removed_agents"].append({"agent": _label(k), "score": old[k]["score"]})
    for k in sorted(set(old) & set(new)):
        a, b = old[k], new[k]
        d = {"agent": _label(k), "score_before": a["score"], "score_after": b["score"],
             "credentials_added": [list(t) for t in sorted(_creds(b) - _creds(a))],
             "credentials_removed": [list(t) for t in sorted(_creds(a) - _creds(b))],
             "capabilities_added": [list(t) for t in sorted(_caps(b) - _caps(a))],
             "capabilities_removed": [list(t) for t in sorted(_caps(a) - _caps(b))],
             "trifecta_before": a["trifecta"], "trifecta_after": b["trifecta"]}
        d.update(_server_changes(a, b))
        changed = (d["score_before"] != d["score_after"] or d["credentials_added"] or d["credentials_removed"]
                   or d["capabilities_added"] or d["capabilities_removed"] or d["trifecta_before"] != d["trifecta_after"]
                   or d["servers_added"] or d["servers_removed"] or d["servers_changed"])
        if changed:
            out["changed"].append(d)
            if (d["score_after"] > d["score_before"] or d["credentials_added"] or d["capabilities_added"]
                    or (d["trifecta_after"] and not d["trifecta_before"]) or _server_change_is_risk(d)):
                out["worse"] = True
    return out


def diff_text(d: dict) -> str:
    head = "reach INCREASED" if d["worse"] else "reach decreased or unchanged"
    lines = ["tideline diff: " + head, ""]
    if not d["new_complete"]:
        lines += ["WARNING: the new scan was incomplete, so this result cannot show that reach did not grow.", ""]
    elif not d["old_complete"]:
        lines += ["Note: the old scan was incomplete; additions may reflect files it could not read.", ""]
    if not (d["added_agents"] or d["removed_agents"] or d["changed"]):
        lines.append("no change in the agents that were scanned.")
    for a in d["added_agents"]:
        lines.append(f"+ new agent {safe(a['agent'])} (score {a['score']}{', POTENTIAL TRIFECTA' if a['trifecta'] else ''})")
    for a in d["removed_agents"]:
        lines.append(f"- removed agent {safe(a['agent'])} (was {a['score']})")
    for c in d["changed"]:
        lines.append(f"~ {safe(c['agent'])}: score {c['score_before']} -> {c['score_after']}")
        if c["trifecta_after"] != c["trifecta_before"]:
            lines.append("    potential trifecta " + ("now COMPLETE" if c["trifecta_after"] else "broken (good)"))
        for k, sign in (("credentials_added", "+ cred"), ("credentials_removed", "- cred")):
            for kind, loc, name in c[k]:
                lines.append(f"    {sign} {safe(kind)} at {safe(loc, 200)}" + (f" ({safe(name)})" if name else ""))
        for k, sign in (("capabilities_added", "+ cap"), ("capabilities_removed", "- cap")):
            for name, via in c[k]:
                lines.append(f"    {sign} {safe(name)} via {safe(via, 200)}")
        for sv in c.get("servers_added", []):
            lines.append(f"    + mcp server {safe(sv['server'])} ({safe(sv['transport'])}, {safe(sv['endpoint'], 200)})")
        for sv in c.get("servers_removed", []):
            lines.append(f"    - mcp server {safe(sv['server'])}")
        for sv in c.get("servers_changed", []):
            lines.append(f"    ~ mcp server {safe(sv['server'])}: " + "; ".join(safe(w, 200) for w in sv["changes"]))
    return "\n".join(lines)
