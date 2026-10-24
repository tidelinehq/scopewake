"""Heuristic blast-radius score. Documented, deterministic, no ML. T3 weights: tune with real data."""
from typing import List

from .model import Agent

IMPACT = {
    "aws-access-key": "take over cloud resources and data in the AWS account",
    "aws-credentials-file": "act as the user in AWS (data, compute, billing)",
    "gcp-adc": "act as the user in Google Cloud",
    "azure-token-cache": "act as the user in Azure",
    "kubeconfig": "control the Kubernetes clusters in that config",
    "ssh-private-key": "log in to every host that trusts this key",
    "github-token": "read or push code and secrets in the repos the token reaches",
    "github-cli-auth": "read or push code as the signed-in GitHub user",
    "gitlab-token": "read or push code in GitLab",
    "stripe-live-key": "move money or read customers in Stripe",
    "db-url-with-password": "read or alter the database behind that URL",
    "private-key-block": "sign or authenticate as the key owner",
    "npm-config": "publish packages as the user",
    "pypi-config": "publish packages as the user",
    "docker-auth": "push images to the registries signed in",
    "netrc": "authenticate to the hosts listed",
    "git-credentials": "push code to the hosts listed",
    "slack-token": "read and post in Slack",
    "generic-secret": "use the service behind that secret",
    "ci-secret": "use the secret the workflow exposes",
    "shell-execution": "run any command as the user",
    "filesystem": "read or overwrite files",
    "browser-control": "act in logged-in web sessions",
    "payments": "trigger payments",
    "database": "read or alter database contents",
    "email": "read and send email",
    "repo-write": "push code or open PRs",
    "elevated-token-permissions": "use a CI token with write rights",
    "oidc-token-request": "request a cloud OIDC token; reach depends on the role that trusts it",
}


def _impact(name: str) -> str:
    if name.startswith("aws:"):
        from .aws import CLASS_IMPACT
        return "in AWS: " + CLASS_IMPACT.get(name[4:], "use that access")
    return IMPACT.get(name, "use that access")


# "Lethal trifecta" (term: Simon Willison, 2025): untrusted input + private data + a way out.
# Config cannot prove permissions or data flow, so this reports a POTENTIAL trifecta from names and credentials.
EXFIL_CAPS = {"shell-execution", "web-content", "browser-control", "email", "slack", "github",
              "gitlab", "repo-write", "workspace-docs", "payments", "docker"}
# Data stores that are private by nature.
PRIVATE_CAPS = {"filesystem", "database", "email", "aws", "gcp", "azure", "kubernetes", "memory-store",
                "aws:full-admin", "aws:secrets-read", "aws:data-read", "aws:kms-decrypt"}
# Services that are private only when a credential for that service is present in the same agent.
CRED_GATED = {"github": "github", "gitlab": "gitlab", "slack": "slack"}


def trifecta(a: Agent) -> dict:
    live = [c for c in a.credentials if not c.mitigated]
    private = {c.kind for c in live} | {c.name for c in a.capabilities if c.name in PRIVATE_CAPS}
    for cap, prefix in CRED_GATED.items():
        if any(c.name == cap for c in a.capabilities) and any(c.kind.startswith(prefix) for c in live):
            private.add(cap)
    return {
        "untrusted_input": sorted({c.via for c in a.capabilities if c.untrusted_input}),
        "private_data": sorted(private),
        "exfiltration": sorted({c.name for c in a.capabilities if c.name in EXFIL_CAPS}),
    }


def score_agent(a: Agent) -> Agent:
    live = [c for c in a.credentials if not c.mitigated]
    seen = {}
    for c in live:
        seen[c.kind] = max(seen.get(c.kind, 0), c.severity)
    for cap in a.capabilities:
        seen[cap.name] = max(seen.get(cap.name, 0), cap.severity)
    prod = 1.0
    for sev in seen.values():
        prod *= 1 - 0.9 * sev / 10
    reach = 1 - prod
    a.score = round(100 * reach * (0.4 + 0.3 * a.autonomy + 0.3 * a.exposure))

    entries = [c for c in a.capabilities if c.untrusted_input]
    entry_txt = ("injection via " + ", ".join(sorted({e.via for e in entries}))) if entries else "injection in files or web pages the agent reads"
    targets = sorted(seen.items(), key=lambda kv: -kv[1])[:3]
    for name, sev in targets:
        a.chains.append(f"{entry_txt} → {a.name} → {name} (severity {sev}) → {_impact(name)}")

    literal = [c for c in live if c.how == "literal-in-config"]
    if literal:
        a.fixes.append(f"Move {len(literal)} literal secret(s) out of config files into environment references or a secret manager ({', '.join(sorted({c.name for c in literal}))}).")
    ambient = [c for c in live if c.how == "readable-file" and c.severity >= 7]
    if ambient:
        a.fixes.append("Deny the agent read access to high-value credential files (e.g. Claude Code permissions.deny: Read(~/.aws/**), Read(~/.ssh/**), Read(**/.env*)) or run it in a container without those mounts.")
    if a.cloud.get("max_severity", 0) >= 9:
        a.fixes.append(f"Give this agent its own IAM role with only the actions it needs instead of {a.cloud.get('type')} {a.cloud.get('name')} "
                      f"(reaches: {', '.join(c['class'] for c in a.cloud.get('classes', [])[:3])}).")
    if a.autonomy >= 0.9:
        a.fixes.append("Require approval for shell commands; remove unrestricted Bash allow rules and bypass modes.")
    if entries and any(c.name == "shell-execution" for c in a.capabilities):
        a.fixes.append("An agent that reads untrusted content can also run commands: separate the two (read-only research agent vs. command agent).")
    if a.kind == "github-action" and any(c.name == "untrusted-trigger" for c in a.capabilities) and live:
        a.fixes.append("Do not expose secrets to workflows triggered by issue or PR text; use environment protection and minimal `permissions:`.")
    if a.kind == "github-action" and any(c.name == "elevated-token-permissions" for c in a.capabilities):
        a.fixes.append("Set job-level `permissions:` to read-only unless a step truly needs write.")
    if a.kind == "github-action" and any(c.name == "oidc-token-request" and c.severity >= 7 for c in a.capabilities):
        a.fixes.append("This job can request an OIDC token and is triggered by issue or PR text: restrict the cloud role's trust "
                       "policy (subject, branch, environment) or remove `id-token: write` from this job.")
    a.trifecta_parts = trifecta(a)
    a.trifecta = all(a.trifecta_parts.values())
    if a.trifecta:
        a.fixes.insert(0, "Potential lethal trifecta (inferred from config; verify tool scopes): this agent reads untrusted input (" + ", ".join(a.trifecta_parts["untrusted_input"]) +
                       "), can reach private data and has a way to send it out (" + ", ".join(a.trifecta_parts["exfiltration"]) +
                       "). Remove one leg: drop the untrusted-input tool, deny the credentials, or require approval for outbound actions.")
    return a


def score_all(agents: List[Agent]) -> List[Agent]:
    for a in agents:
        score_agent(a)
    return sorted(agents, key=lambda x: -x.score)
