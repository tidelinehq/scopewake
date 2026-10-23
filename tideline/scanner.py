"""Read-only scanner. Opens no sockets, writes nothing, never stores a secret value.

Everything it cannot analyse is recorded as an issue, so a broken config cannot look like a clean one.
"""
import hashlib
import json
import os
import re
from fnmatch import fnmatchcase
from pathlib import Path
from typing import List, Optional

from .model import Agent, Capability, Credential
from .patterns import HOME_CRED_FILES, MCP_CLASSES, NAME_RE, VALUE_PATTERNS
from .safe import safe, sanitize_agent, scrub

MAX_BYTES = 256 * 1024
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build", ".tox", "target"}
MAX_DEPTH = 4
MAX_ENTRIES = 50000
MAX_WORKFLOWS = 200
LAUNCHERS = {"npx", "uvx", "node", "python", "python3", "docker", "podman", "bunx", "pipx", "deno", "uv", "bun", "npm", "pnpm", "yarn", "env", "cmd"}
SHELLS = {"bash", "sh", "zsh", "fish", "dash", "ksh", "powershell", "pwsh", "cmd.exe"}

# Problems that make a scan incomplete (file unreadable, invalid, oversized, symlinked, wrong type, limit hit).
_ISSUES: List[str] = []


def reset_issues():
    del _ISSUES[:]


def get_issues() -> List[str]:
    return list(_ISSUES)


def _issue(msg: str):
    m = safe(msg, 300)
    if m not in _ISSUES and len(_ISSUES) < 200:
        _ISSUES.append(m)


def _symlinked(path: Path, base: Optional[Path]) -> bool:
    """True if the file or any directory between base and the file is a symlink."""
    try:
        if path.is_symlink():
            return True
        if base is not None:
            rel = path.relative_to(base)
            cur = base
            for part in rel.parts[:-1]:
                cur = cur / part
                if cur.is_symlink():
                    return True
    except (OSError, ValueError):
        return True
    return False


def _read(path: Path, base: Optional[Path] = None) -> Optional[str]:
    """Bounded, no-follow read of one regular file. Returns None and records an issue when it cannot be analysed."""
    try:
        if not (path.exists() or path.is_symlink()):
            return None
        if _symlinked(path, base):
            _issue(f"skipped symlinked path: {path}")
            return None
        if not path.is_file():
            _issue(f"not a regular file, skipped: {path}")
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(str(path), flags)
        try:
            chunks, total = [], 0
            while total <= MAX_BYTES:
                chunk = os.read(fd, MAX_BYTES + 1 - total)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
        finally:
            os.close(fd)
        if total > MAX_BYTES:
            _issue(f"skipped oversized file (>{MAX_BYTES} bytes): {path}")
            return None
        try:
            return b"".join(chunks).decode("utf-8-sig")
        except UnicodeDecodeError:
            _issue(f"not valid UTF-8, not analysed: {path}")
            return None
    except OSError:
        _issue(f"unreadable file: {path}")
        return None


def _json(path: Path, base: Optional[Path] = None):
    text = _read(path, base)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except (ValueError, RecursionError, MemoryError):
        _issue(f"invalid JSON, not analysed: {path}")
        return None
    if not isinstance(data, dict):
        _issue(f"unexpected top-level JSON type, not analysed: {path}")
        return None
    return data


def literal_secret_kinds(value: str):
    """Return [(kind, severity)] for secret-shaped substrings. The matched text is discarded."""
    found = []
    for kind, rx, sev in VALUE_PATTERNS:
        if rx.search(value):
            found.append((kind, sev))
    return found


# ---------- ambient credentials (anything running as the user can read them) ----------
def home_credentials(home: Path) -> List[Credential]:
    out = []
    for rel, kind, sev in HOME_CRED_FILES:
        p = home / rel
        if p.is_file():  # existence only; contents are never read. Follows symlinks on purpose: the agent can too.
            out.append(Credential(kind, sev, safe(p, 1000), "readable-file", name=rel))
    return out


def project_env_credentials(root: Path) -> List[Credential]:
    """Bounded walk with scandir. .env files are handled as each directory is read, so a limit cannot hide them."""
    out = []
    entries = 0
    pending = [(root, 0)]
    pruned = False
    while pending:
        d, depth = pending.pop()
        try:
            with os.scandir(d) as it:
                items = []
                for e in it:
                    items.append(e)
                    entries += 1
                    if entries > MAX_ENTRIES:
                        break
        except OSError:
            _issue(f"unreadable directory: {d}")
            continue
        for e in items:
            try:
                if e.is_symlink():
                    continue
                if e.is_dir(follow_symlinks=False):
                    if e.name in SKIP_DIRS:
                        continue
                    if depth + 1 > MAX_DEPTH:
                        pruned = True
                    else:
                        pending.append((Path(e.path), depth + 1))
                    continue
                fn = e.name
                if not (fn == ".env" or fn.startswith(".env.")) or fn.endswith((".example", ".sample", ".template")):
                    continue
            except OSError:
                _issue(f"unreadable entry: {e.path}")
                continue
            p = Path(e.path)
            text = _read(p, root)
            if text is None:
                continue
            for line in text.splitlines():
                if "=" not in line or line.lstrip().startswith("#"):
                    continue
                key, _, val = line.partition("=")
                key = safe(key.strip().replace("export ", ""), 120)
                val = val.strip().strip("'\"")
                if not val:
                    continue
                kinds = literal_secret_kinds(val)
                if kinds:
                    for kind, sev in kinds:
                        out.append(Credential(kind, sev, safe(p, 1000), "readable-file", name=key))
                elif NAME_RE.search(key):
                    out.append(Credential("generic-secret", 4, safe(p, 1000), "readable-file", name=key))
        if entries > MAX_ENTRIES:
            _issue(f"project walk stopped after {MAX_ENTRIES} entries; later files not checked")
            break
    if pruned:
        _issue(f"directories deeper than {MAX_DEPTH} levels were not searched for .env files")
    return out


# ---------- MCP ----------
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def _tokens(*parts) -> set:
    out = set()
    for part in parts:
        out.update(t for t in _TOKEN_SPLIT.split(str(part).lower()) if t)
    return out


def _is_path_arg(a: str) -> bool:
    return a.startswith(("/", "./", "../", "~")) or bool(re.match(r"^[A-Za-z]:[\\/]", a))


def classify_server(name: str, command: str, args: list):
    """Infer capabilities from the server name and launch arguments. Inferred, not verified."""
    command = str(command or "")
    cmd_base = Path(command.replace("\\", "/")).name.lower() if command else ""
    cmd_parts = [] if (cmd_base in LAUNCHERS or cmd_base in SHELLS) else [command]
    arg_text = [str(a) for a in args if not _is_path_arg(str(a))]
    tokens = _tokens(name, *cmd_parts, *arg_text)
    sname = safe(name, 200)
    caps = []
    for words, cap, sev, untrusted in MCP_CLASSES:
        if any(w in tokens for w in words):
            caps.append(Capability(cap, sev, untrusted, via=f"mcp:{sname}"))
    if cmd_base in SHELLS and not any(c.name == "shell-execution" for c in caps):
        caps.append(Capability("shell-execution", 9, False, via=f"mcp:{sname}"))
    if not caps:
        caps.append(Capability("unknown-mcp-tool", 3, False, via=f"mcp:{sname}"))
    return caps


def server_credentials(host_src: str, name: str, spec: dict) -> List[Credential]:
    out = []
    loc = safe(f"{host_src}:{name}", 1000)
    env = spec.get("env")
    if env is not None and not isinstance(env, dict):
        _issue(f"env is not an object, ignored: {host_src}:{name}")
        env = {}
    for k, v in (env or {}).items():
        v = "" if v is None else str(v)
        k = safe(k, 120)
        if v.strip() == "":
            continue  # an empty value is not a credential
        kinds = literal_secret_kinds(v)
        if kinds:
            for kind, sev in kinds:
                out.append(Credential(kind, sev, loc, "literal-in-config", name=k))
        elif NAME_RE.search(k):
            how = "env-reference" if v.startswith("${") or v.startswith("$") else "literal-in-config"
            out.append(Credential("generic-secret", 4, loc, how, name=k))
    args = spec.get("args")
    if args is not None and not isinstance(args, (list, tuple)):
        _issue(f"args is not a list, ignored: {host_src}:{name}")
        args = []
    for a in args or []:
        for kind, sev in literal_secret_kinds(str(a)):
            out.append(Credential(kind, sev, loc, "literal-in-config", name="args"))
    url = spec.get("url")
    if url:
        for kind, sev in literal_secret_kinds(str(url)):
            out.append(Credential(kind, sev, loc, "literal-in-config", name="url"))
    headers = spec.get("headers")
    if headers is not None and not isinstance(headers, dict):
        _issue(f"headers is not an object, ignored: {host_src}:{name}")
        headers = {}
    for h in (headers or {}).values():
        for kind, sev in literal_secret_kinds(str(h)):
            out.append(Credential(kind, sev, loc, "literal-in-config", name="headers"))
    return out


# scheme and host[:port] only; userinfo, path and query (which may hold tokens) are dropped.
_URL_HOST = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://(?:[^@/?#]*@)?([^/?#@]+)")


def server_fingerprint(name: str, spec: dict) -> dict:
    """What an MCP server definition is, without any secret value: transport, endpoint host or launcher,
    a hash of its (redacted) arguments, and the NAMES of env vars and headers it receives."""
    url = spec.get("url") if isinstance(spec.get("url"), str) else ""
    cmd = spec.get("command") if isinstance(spec.get("command"), str) else ""
    args = spec.get("args") if isinstance(spec.get("args"), (list, tuple)) else []
    env = spec.get("env") if isinstance(spec.get("env"), dict) else {}
    headers = spec.get("headers") if isinstance(spec.get("headers"), dict) else {}
    if url:
        m = _URL_HOST.match(url.strip())
        endpoint = f"{m.group(1).lower()}://{m.group(2).lower()}" if m else "invalid-url"
        transport = "remote"
    else:
        endpoint = Path(cmd.replace("\\", "/")).name if cmd else ""
        transport = "local"
    # Hash redacted arguments only: a secret pasted into args never reaches the report, even hashed.
    arg_text = "\x1f".join(scrub(str(a)) for a in args)
    fp = {
        "name": safe(name, 200),
        "transport": transport,
        "endpoint": safe(endpoint, 200),
        "args_hash": hashlib.sha256(arg_text.encode("utf-8", "replace")).hexdigest()[:16],
        "env_names": sorted(safe(k, 120) for k in env.keys()),
        "header_names": sorted(safe(k, 120) for k in headers.keys()),
    }
    basis = json.dumps([fp["transport"], fp["endpoint"], fp["args_hash"], fp["env_names"], fp["header_names"]])
    fp["fingerprint"] = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
    return fp


def _mcp_servers(data, path) -> dict:
    if not isinstance(data, dict):
        _issue(f"top-level JSON is not an object, not analysed: {path}")
        return {}
    merged = {}
    for key in ("mcpServers", "servers", "mcp"):
        v = data.get(key)
        if v is None:
            continue
        if isinstance(v, dict):
            merged.update(v)
        else:
            _issue(f"'{key}' is not an object, ignored: {path}")
    projects = data.get("projects")  # ~/.claude.json keeps per-project servers
    if isinstance(projects, dict):
        for pp in projects.values():
            if isinstance(pp, dict) and isinstance(pp.get("mcpServers"), dict):
                merged.update(pp["mcpServers"])
    return merged


def _agent_from_mcp_config(path: Path, kind: str, name: str, ambient_runs_commands: bool, base: Optional[Path] = None) -> Optional[Agent]:
    data = _json(path, base)
    if data is None:
        return None
    servers = _mcp_servers(data, path)
    agent = Agent(id=f"{kind}:{safe(path, 1000)}", name=name, kind=kind, source=safe(path, 1000))
    for sname, spec in servers.items():
        if not isinstance(spec, dict):
            _issue(f"server '{safe(sname, 60)}' is not an object, ignored: {path}")
            continue
        args = spec.get("args")
        if args is not None and not isinstance(args, (list, tuple)):
            args = []
        cmd = spec.get("command")
        if cmd is not None and not isinstance(cmd, str):
            _issue(f"command is not a string, ignored: {path}")
            cmd = ""
        agent.capabilities += classify_server(str(sname), cmd or "", args or [])
        agent.credentials += server_credentials(str(path), str(sname), spec)
        fp = server_fingerprint(str(sname), spec)
        fp["config"] = safe(path, 1000)
        agent.servers.append(fp)
    agent.notes.append(f"{len(servers)} MCP server(s) configured")
    agent.runs_commands = ambient_runs_commands
    return agent


# ---------- Claude Code settings ----------
def _strs(value, label: str, path: Path) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        _issue(f"{label} is not a list, ignored: {path}")
        return []
    return [str(x) for x in value]


def _claude_code_settings(paths: List[Path], bases: List[Path]):
    mode, allow, deny, skip = "default", [], [], False
    for p, b in zip(paths, bases):
        d = _json(p, b)
        if d is None:
            continue
        if not isinstance(d, dict):
            _issue(f"settings file is not an object, ignored: {p}")
            continue
        perm = d.get("permissions")
        if perm is not None and not isinstance(perm, dict):
            _issue(f"permissions is not an object, ignored: {p}")
            perm = None
        if perm:
            if perm.get("defaultMode"):
                mode = str(perm["defaultMode"])
            allow += _strs(perm.get("allow"), "permissions.allow", p)
            deny += _strs(perm.get("deny"), "permissions.deny", p)
        if d.get("skipDangerousModePermissionPrompt"):
            skip = True
    return mode, allow, deny, skip


def _autonomy(mode, allow, skip):
    if mode == "bypassPermissions" or skip:
        return 1.0, f"permission mode {mode}, no prompts"
    if any(a.strip() in ("Bash", "Bash(*)", "Bash(*:*)") for a in allow):
        return 0.9, "unrestricted Bash allowed"
    if mode == "acceptEdits":
        return 0.7, "edits auto-accepted"
    if mode == "plan":
        return 0.2, "plan mode"
    return 0.4, "prompts for actions by default"


_READ_RULE = re.compile(r"^\s*Read\((.*)\)\s*$")


def _read_rule_blocks(rule: str, path: Path, home: Path, root: Path) -> bool:
    """True only for a Read(...) deny rule whose pattern matches this file. Other rule types never count."""
    m = _READ_RULE.match(rule)
    if not m:
        return False
    pat = m.group(1).strip()
    if not pat:
        return False
    candidates = [str(path)]
    for base, prefix in ((home, "~/"), (root, "./")):
        try:
            candidates.append(prefix + path.relative_to(base).as_posix())
            candidates.append(path.relative_to(base).as_posix())
        except ValueError:
            pass
    if pat.startswith("~/"):
        pats = [pat, str(home / pat[2:])]
    elif pat.startswith("./"):
        pats = [pat, pat[2:], str(root / pat[2:])]
    elif pat.startswith("/"):
        pats = [pat]
    else:
        pats = [pat, "*/" + pat if not pat.startswith("*") else pat]
    return any(fnmatchcase(c, p) for c in candidates for p in pats)


def claude_code_agents(home: Path, root: Path) -> List[Agent]:
    agents = []
    user_cfgs = [home / ".claude" / "settings.json", home / ".claude" / "settings.local.json"]
    proj_cfgs = [root / ".claude" / "settings.json", root / ".claude" / "settings.local.json"]
    present = [p for p in user_cfgs + proj_cfgs if p.exists() or p.is_symlink()]
    if not (present or any((p.exists() or p.is_symlink()) for p in (home / ".claude.json", root / ".mcp.json"))):
        return agents
    mode, allow, deny, skip = _claude_code_settings(user_cfgs + proj_cfgs, [home] * 2 + [root] * 2)
    a = Agent(id="claude-code", name="Claude Code", kind="claude-code", source=safe(present[0] if present else home / ".claude", 1000))
    a.autonomy, a.autonomy_note = _autonomy(mode, allow, skip)
    a.capabilities.append(Capability("shell-execution", 9, False, via="claude-code:Bash"))
    a.capabilities.append(Capability("filesystem", 6, False, via="claude-code:Read/Edit"))
    for cfg, base in ((home / ".claude.json", home), (root / ".mcp.json", root)):
        sub = _agent_from_mcp_config(cfg, "claude-code", "Claude Code", True, base)
        if sub:
            a.capabilities += sub.capabilities
            a.credentials += sub.credentials
            a.notes += sub.notes
            a.servers += sub.servers
    a.deny_rules = deny
    a.runs_commands = True
    agents.append(a)
    return agents


def other_host_agents(home: Path, root: Path) -> List[Agent]:
    specs = [
        (home / ".cursor" / "mcp.json", "cursor", "Cursor", True, home),
        (root / ".cursor" / "mcp.json", "cursor", "Cursor (project)", True, root),
        (home / ".codeium" / "windsurf" / "mcp_config.json", "windsurf", "Windsurf", True, home),
        (root / ".vscode" / "mcp.json", "vscode", "VS Code MCP", True, root),
        (home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json", "claude-desktop", "Claude Desktop", False, home),
        (home / ".config" / "Claude" / "claude_desktop_config.json", "claude-desktop", "Claude Desktop", False, home),
        (home / ".gemini" / "settings.json", "gemini-cli", "Gemini CLI", True, home),
        (home / ".codex" / "config.toml", "codex-cli", "Codex CLI", True, home),
    ]
    out = []
    for path, kind, name, runs, base in specs:
        if path.suffix == ".toml":
            if path.is_file():
                a = Agent(id=f"{kind}:{safe(path, 1000)}", name=name, kind=kind, source=safe(path, 1000), autonomy=0.6)
                a.capabilities.append(Capability("shell-execution", 9, False, via=f"{kind}"))
                a.notes.append("TOML config detected; MCP servers not parsed in v0.1")
                a.runs_commands = True
                out.append(a)
            continue
        a = _agent_from_mcp_config(path, kind, name, runs, base)
        if a:
            a.autonomy = 0.6 if runs else 0.4
            if runs:
                a.capabilities.append(Capability("shell-execution", 9, False, via=kind))
            out.append(a)
    return out


# ---------- GitHub Actions ----------
AGENT_ACTIONS = re.compile(r"(anthropics/claude-code-action|openai/codex|github/copilot|cursor|aider|sweep|devin|coderabbit|gemini-cli|claude-code)", re.I)
SECRET_REF = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}")


def workflow_agents(root: Path) -> List[Agent]:
    out = []
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return out
    if _symlinked(wf_dir, root):
        _issue(f"skipped symlinked workflow directory: {wf_dir}")
        return out
    files = sorted(wf_dir.glob("*.y*ml"))
    if len(files) > MAX_WORKFLOWS:
        _issue(f"only the first {MAX_WORKFLOWS} workflow files were checked")
        files = files[:MAX_WORKFLOWS]
    for p in files:
        text = _read(p, root)
        if not text:
            continue
        code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        m = AGENT_ACTIONS.search(code)
        if not m:
            continue
        a = Agent(id=f"workflow:{safe(p, 1000)}", name=f"CI agent ({safe(p.name, 60)})", kind="github-action", source=safe(p, 1000), autonomy=0.9,
                  autonomy_note="runs unattended in CI")
        a.capabilities.append(Capability("repo-write", 7, False, via=safe(p.name, 120)))
        untrusted = bool(re.search(r"issue_comment|pull_request_target|\bissues:|pull_request_review", code))
        if untrusted:
            a.capabilities.append(Capability("untrusted-trigger", 5, True, via="issue/PR text"))
        if re.search(r"permissions:\s*write-all|contents:\s*write", code):
            a.capabilities.append(Capability("elevated-token-permissions", 7, False, via="permissions block"))
        if re.search(r"id-token:\s*write|permissions:\s*write-all", code):
            # id-token: write only lets the job request an OIDC token; what that token can do depends on the cloud
            # role's trust policy, which a workflow file does not show. Higher severity only with untrusted triggers.
            a.capabilities.append(Capability("oidc-token-request", 7 if untrusted else 4, False, via="id-token: write"))
            a.notes.append("id-token: write lets this job request an OIDC token; its cloud reach depends on the trusted role "
                           "(check the role's trust conditions, or supply an IAM export with --aws-auth).")
        for sname in sorted(set(SECRET_REF.findall(code))):
            sev = 9 if re.search(r"AWS|GCP|AZURE|CLOUD|PROD|DEPLOY|KEY|TOKEN", sname, re.I) else 5
            a.credentials.append(Credential("ci-secret", sev, safe(p, 1000), "secrets-reference", name=safe(sname, 120)))
        a.notes.append(f"agent action matched: {safe(m.group(0).lower(), 60)}")
        a.runs_commands = False
        out.append(a)
    return out


# ---------- orchestration ----------
def _rel(text: str, root: Path, home: Path) -> str:
    """Express a path (or 'path:server') relative to the scan root, or ~/ for the home directory."""
    r, h = str(root).rstrip("/\\") + os.sep, str(home).rstrip("/\\") + os.sep
    if text.startswith(r):
        return text[len(r):].replace(os.sep, "/")
    if text.startswith(h):
        return "~/" + text[len(h):].replace(os.sep, "/")
    return text


def _resolve(p: Path, label: str) -> Path:
    try:
        return p.resolve()
    except (OSError, RuntimeError):
        _issue(f"cannot resolve {label} path (loop or error): {p}")
        return p


def scan(root: Path, home: Path) -> List[Agent]:
    reset_issues()
    root, home = _resolve(root, "project"), _resolve(home, "home")
    if not root.is_dir():
        _issue(f"project path is not a directory: {root}")
    agents = claude_code_agents(home, root) + other_host_agents(home, root) + workflow_agents(root)
    ambient = home_credentials(home) + (project_env_credentials(root) if root.is_dir() else [])
    for a in agents:
        if a.runs_commands:
            deny = a.deny_rules
            for c in ambient:
                denied = any(_read_rule_blocks(r, Path(c.location), home, root) for r in deny)
                # A file-read deny rule stops the Read tool, not a shell. Count it as a mitigation only while
                # commands need approval; with unrestricted Bash or bypass mode the file stays reachable.
                mit = denied and a.autonomy < 0.9
                a.credentials.append(Credential(c.kind, c.severity, c.location, "readable-file", c.name, mitigated=mit, read_denied=denied))
            if any(c.read_denied for c in a.credentials):
                a.notes.append("Read deny rules block the file-read tool, not shell commands; 'mitigated' is set only while shell commands need approval.")
        a.exposure = 1.0 if any(c.untrusted_input for c in a.capabilities) else 0.4
        a.source_rel = _rel(a.source, root, home)
        for c in a.credentials:
            c.loc_rel = _rel(c.location, root, home)
        for sv in a.servers:
            sv["config"] = _rel(sv.get("config", ""), root, home)
        sanitize_agent(a)
    return agents
