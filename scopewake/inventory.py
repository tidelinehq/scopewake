"""Import agent inventories that firms already have (Microsoft Defender XDR `AgentsInfo` exports, or any CSV/JSON
inventory) into Scopewake reports, so approvals and reviews cover every agent type, not only what `scan` finds.

Offline and read-only: reads an exported file and prints a report. Names, identifiers and shapes only; free-text
fields such as system prompts (`Instructions`) are never copied. Imported agents are not scored (score 0): their
reach is recorded as declared tools, data sources, permissions, MCP servers, connected agents and audience, so
`review` flags any addition. Indicative, not legal advice.
"""
import csv
import hashlib
import io
import json
from pathlib import Path
from typing import Dict, List, Optional

from . import __version__
from .safe import safe, scrub_tree

MAX_BYTES = 16 * 1024 * 1024
LIST_SEP = ";"

# Columns documented for the Defender XDR advanced hunting table AgentsInfo (learn.microsoft.com, checked 2026-11-07).
# The inner structure of the dynamic columns is not documented, so names are taken from common keys where present and
# every element is also fingerprinted, which makes any change visible even when no name can be read.
DEFENDER = {"id": "AgentId", "name": "AgentName", "platform": "Platform", "time": "Timestamp", "status": "LifecycleStatus",
            "tools": "DeclaredTools", "data": "DeclaredDataSources", "permissions": "Permissions", "servers": "McpServers",
            "agents": "ConnectedAgents", "skills": "Skills", "channels": "Channels", "audience": "Availability",
            "shared": "SharedWith", "owner": "Owners", "auth": "ToolsAuthenticationType", "endpoints": "Endpoints"}
GENERIC_FIELDS = ("id", "name", "platform", "time", "status", "tools", "data", "permissions", "servers", "agents",
                  "skills", "channels", "audience", "shared", "owner", "auth", "endpoints")
INACTIVE = {"deleted", "uninstalled"}
NAME_KEYS = ("name", "Name", "displayName", "DisplayName", "id", "Id", "url", "Url", "URL", "serverUrl", "ServerUrl", "endpoint")
CAP_PREFIX = {"tools": "tool", "data": "data", "permissions": "permission", "agents": "agent", "skills": "skill",
              "channels": "channel", "audience": "audience", "shared": "shared-with", "auth": "auth", "endpoints": "endpoint"}


def _fp(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()[:12]


def _items(v) -> List:
    """A cell as a list: JSON arrays/objects (also when given as a JSON string), or ';'-separated text."""
    if v is None or v == "":
        return []
    if isinstance(v, str):
        t = v.strip()
        if t[:1] in "[{":
            try:
                v = json.loads(t)
            except ValueError:
                return [x.strip() for x in t.split(LIST_SEP) if x.strip()]
        else:
            return [x.strip() for x in t.split(LIST_SEP) if x.strip()]
    if isinstance(v, dict):
        return [v]
    if isinstance(v, list):
        return v
    return [str(v)]


def _label(x) -> str:
    if isinstance(x, dict):
        for k in NAME_KEYS:
            if isinstance(x.get(k), str) and x[k].strip():
                return safe(x[k].strip(), 120) + f"#{_fp(x)}"
        return f"#{_fp(x)}"
    return safe(str(x), 120)


def _rows(path: str) -> List[dict]:
    p = Path(path)
    try:
        if p.stat().st_size > MAX_BYTES:
            raise ValueError("inventory file is larger than 16 MB")
        text = p.read_text(encoding="utf-8-sig")
    except OSError:
        raise ValueError(f"cannot read {safe(path, 200)}")
    except UnicodeDecodeError:
        raise ValueError(f"{safe(path, 200)} is not valid UTF-8")
    if text.lstrip()[:1] in "[{":
        try:
            data = json.loads(text)
        except (ValueError, RecursionError):
            raise ValueError(f"{safe(path, 200)} is not valid JSON")
        if isinstance(data, dict):
            data = data.get("Results") or data.get("results") or data.get("value") or data.get("agents") or []
        if not isinstance(data, list) or not all(isinstance(r, dict) for r in data):
            raise ValueError("JSON inventory must be a list of objects (or an object with 'Results', 'value' or 'agents')")
        return data
    rows = list(csv.DictReader(io.StringIO(text)))
    if not rows:
        raise ValueError(f"{safe(path, 200)} has no rows")
    return rows


def parse_map(pairs: List[str]) -> Dict[str, str]:
    out = {}
    for p in pairs:
        if "=" not in p:
            raise ValueError(f"--map expects FIELD=COLUMN, got {safe(p, 80)}")
        k, v = (x.strip() for x in p.split("=", 1))
        if k not in GENERIC_FIELDS:
            raise ValueError(f"--map field must be one of: {', '.join(GENERIC_FIELDS)}")
        out[k] = v
    return out


def import_inventory(path: str, source: str = "defender", mapping: Optional[Dict[str, str]] = None,
                     platform: str = "") -> dict:
    if source not in ("defender", "generic"):
        raise ValueError("--source must be defender or generic")
    cols = dict(DEFENDER) if source == "defender" else {}
    cols.update(mapping or {})
    if "name" not in cols:
        raise ValueError("map at least the agent name column (--map name=COLUMN)")
    rows = _rows(path)
    if cols["name"] not in rows[0] and not any(cols["name"] in r for r in rows):
        raise ValueError(f"column {safe(cols['name'], 60)} not found; check --source or --map")
    latest, skipped = {}, 0
    for r in rows:
        name = str(r.get(cols["name"], "") or "").strip()
        if not name:
            skipped += 1
            continue
        aid = str(r.get(cols.get("id", ""), "") or "").strip() or name
        if str(r.get(cols.get("status", ""), "") or "").strip().lower() in INACTIVE:
            latest.pop(aid, None)
            continue
        t = str(r.get(cols.get("time", ""), "") or "")
        if aid not in latest or t >= latest[aid][0]:
            latest[aid] = (t, r)
    agents = []
    for aid, (_, r) in sorted(latest.items()):
        plat = (platform or str(r.get(cols.get("platform", ""), "") or "") or source).strip()
        caps = []
        for field, prefix in CAP_PREFIX.items():
            for x in _items(r.get(cols.get(field, ""), "")):
                caps.append({"name": f"{prefix}:{_label(x)}", "via": f"{source}:{cols.get(field, field)}"})
        servers = []
        for x in _items(r.get(cols.get("servers", ""), "")):
            label = _label(x)
            endpoint = ""
            if isinstance(x, dict):
                for k in ("url", "Url", "URL", "serverUrl", "ServerUrl", "endpoint"):
                    if isinstance(x.get(k), str):
                        endpoint = safe(x[k], 200)
                        break
            elif isinstance(x, str) and x.startswith(("http://", "https://")):
                endpoint = safe(x, 200)
            servers.append({"config": f"{source}:{cols.get('servers', 'servers')}", "name": label.split("#")[0] or label,
                            "transport": "http" if endpoint else "", "endpoint": endpoint, "args_hash": "",
                            "fingerprint": _fp(x), "env_names": [], "header_names": []})
        owner = ", ".join(_label(x).split("#")[0] for x in _items(r.get(cols.get("owner", ""), "")))
        agents.append({"id": safe(aid, 120), "kind": safe(plat.lower().replace(" ", "-"), 60), "name": safe(name, 120),
                       "source_rel": safe(aid, 120), "score": 0, "scored": False, "trifecta": False, "owner": owner,
                       "credentials": [], "capabilities": sorted(caps, key=lambda c: (c["name"], c["via"])),
                       "servers": sorted(servers, key=lambda s: (s["config"], s["name"])), "cloud": {}})
    issues = [f"{skipped} row(s) without an agent name were skipped"] if skipped else []
    return scrub_tree({"tool": "scopewake", "version": __version__, "kind": "imported-inventory",
                       "source": source, "file": safe(Path(path).name, 120),
                       "note": "Imported agents are not scored; their reach is the declared tools, data, permissions, "
                               "MCP servers, connected agents and audience in the export.",
                       "coverage": {"complete": not issues, "issues": issues}, "agents": agents})


def merge_reports(reports: List[dict]) -> dict:
    """Combine scan and import reports into one, for approve/review across every agent type."""
    agents, issues, complete = [], [], True
    for i, rep in enumerate(reports):
        if not isinstance(rep, dict) or rep.get("tool") not in ("scopewake", "tideline") or not isinstance(rep.get("agents"), list):
            raise ValueError(f"input {i + 1} is not a scopewake JSON report")
        cov = rep.get("coverage") or {}
        complete = complete and bool(cov.get("complete", True))
        issues += [f"input {i + 1}: {x}" for x in cov.get("issues", []) if isinstance(x, str)]
        agents += rep["agents"]
    return {"tool": "scopewake", "version": __version__, "kind": "merged-report", "inputs": len(reports),
            "coverage": {"complete": complete, "issues": issues}, "agents": agents}
