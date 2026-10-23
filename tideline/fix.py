"""Concrete fixes as Claude Code managed settings. Printed for review; nothing is written."""
from typing import List

from .model import Agent

# Home directories whose whole contents are credentials: deny the directory, not one file.
CRED_DIRS = (".aws", ".ssh", ".kube", ".azure", ".docker", ".config/gcloud", ".config/gh")


def _rule(loc_rel: str) -> str:
    if loc_rel.startswith("~/"):
        rest = loc_rel[2:]
        for d in CRED_DIRS:
            if rest == d or rest.startswith(d + "/"):
                return f"Read(~/{d}/**)"
        return f"Read({loc_rel})"
    if loc_rel.startswith(("/", "..")) or not loc_rel:
        return ""
    return f"Read(./{loc_rel})"


def fixes(agents: List[Agent]) -> dict:
    cc = [a for a in agents if a.kind == "claude-code"]
    deny, notes = set(), []
    bypass = False
    for a in cc:
        for c in a.credentials:
            if c.how == "readable-file" and not c.read_denied and c.severity >= 5:
                r = _rule(c.loc_rel)
                if r:
                    deny.add(r)
        if a.autonomy >= 0.9:
            bypass = True
    settings = {"permissions": {"deny": sorted(deny)}}
    if bypass:
        settings["permissions"]["disableBypassPermissionsMode"] = "disable"
    if deny:
        notes.append("Read deny rules stop Claude's file tools, not shell commands; enable sandboxing (sandbox.enabled) "
                     "or keep shell commands behind approval so these files stay out of reach.")
    servers = sorted({s["name"] for a in cc for s in a.servers})
    if servers:
        notes.append("To stop new MCP servers appearing unreviewed, allow only these in managed settings "
                     "(allowedMcpServers / managed-mcp.json): " + ", ".join(servers))
    for a in agents:
        if a.cloud.get("max_severity", 0) >= 9:
            notes.append(f"{a.name}: give this agent its own IAM role instead of {a.cloud.get('type')} {a.cloud.get('name')}; "
                         "generate the policy from its real activity with AWS IAM Access Analyzer.")
        if a.kind == "github-action" and any(c.name == "untrusted-trigger" for c in a.capabilities):
            notes.append(f"{a.name}: an agent triggered by issue or PR text should not get write-scoped tokens or secrets; "
                         "if it needs `id-token: write`, restrict the trusted cloud role's subject and branch conditions.")
    if not cc:
        notes.append("No Claude Code configuration found; managed settings apply to Claude Code only.")
    return {"tool": "tideline", "kind": "fix",
            "claude_code_managed_settings": settings,
            "deploy": "Merge into managed settings (admin console, MDM plist/registry, or managed-settings.json); "
                      "managed values take precedence over user and project settings.",
            "notes": notes}
