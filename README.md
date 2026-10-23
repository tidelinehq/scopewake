# Tideline

**If an AI agent on your machine were hijacked, what could it reach?** Tideline finds the AI agents and coding assistants configured on a machine or repo, lists the credentials and capabilities each one can reach, and ranks them by worst-case blast radius. For regulated firms it keeps AI approvals current: when an agent's reach changes, it shows which approval needs review.

- **Local and read-only.** It opens no network connection, writes no files, and is designed not to store or print secret values (names, kinds and locations only). Known secret shapes and every output field are redacted centrally, and tests plant synthetic secrets to check this. Redaction is pattern-based: an unrecognised secret format, or a secret split across fields, can still appear if a config puts one in a name or path. Tests and a source-policy check enforce the no-network, no-write design; they are not a proof.
- **Zero dependencies.** Python 3.9+ standard library only.
- **Heuristic, not a measurement.** Scores rank agents against each other; they are not probabilities.

## Install and run
```
pip install tideline        # once published
tideline scan .             # scan this project plus your home directory
tideline scan . --format md > report.md
tideline scan . --format json
tideline scan . --fail-above 70   # exit 1 in CI if any agent scores above 70
```
From source: `python -m tideline scan .`

## What it looks at
- **Agents:** Claude Code (settings, MCP), Cursor, Windsurf, VS Code MCP, Claude Desktop, Gemini CLI and Codex CLI (detected), and GitHub Actions workflows that run coding agents.
- **Credentials:** MCP server env and args, `.env*` files in the project, cloud and tool credential files in your home (AWS, GCP, Azure, kubeconfig, SSH keys, npm, PyPI, Docker, netrc, git, GitHub CLI), and `secrets.*` references in workflows.
- **Capabilities:** shell execution, filesystem, browser control, GitHub, Slack, email, databases, cloud, payments, and others inferred from MCP server names.
- **Score (0 to 100):** reach (how many high-severity credentials and capabilities, after deny rules) x autonomy (does it ask before acting?) x exposure (does it read untrusted content?).

## What it does not do (yet)
It never calls cloud APIs (AWS reach comes from an IAM export you supply; GCP and Azure are not analysed yet), does not verify credentials are live, does not parse every agent's config format (Codex TOML is detected only), and cannot see agents running outside the scanned locations. Pattern matching can miss unusual secrets and can flag harmless strings.

## AWS: what a key could do, according to your IAM export

A file path says an agent *can read* `~/.aws/credentials`. It does not say whether that key is read-only or admin.
Tideline answers that offline, from an IAM export you create yourself. Tideline never calls AWS and never reads the key.
The answer is only as complete and as current as the export: it covers what the export contains, as of when you ran it, not everything the credential can do in production now.

```bash
# 1. You run this with any IAM read-only identity (needs iam:GetAccountAuthorizationDetails)
aws iam get-account-authorization-details > iam.json

# 2. Rank every user and role by what it can reach
tideline aws iam.json

# 3. Tie the agents' AWS credentials to the IAM identity they belong to
tideline scan . --aws-auth iam.json --aws-as ci-deployer            # all agents
tideline scan . --aws-auth iam.json --aws-as claude-code=dev-agent  # per agent id or kind
```

Action classes reported: full admin, privilege escalation (including `iam:PassRole` plus a compute launch),
secrets read, data read, data destroy, KMS decrypt, role assumption, compute launch, audit-log tampering.
Role chains are followed up to three `sts:AssumeRole` hops where the role's trust policy allows it.
Inline, group and managed policies, explicit Deny and permission boundaries are evaluated.

Limits: service control policies, resource policies, session policies and most condition keys are not in the
export, so they are not evaluated. An Allow with a Condition is shown as `conditional`. Policies missing from the
export are listed as problems, never silently counted as zero. When a mapped identity has no high-impact actions,
the credential's severity drops accordingly, so read-only keys stop dominating the ranking.

## Security
See `SECURITY_REVIEW.md`. Report issues privately before publishing details.

## License
MIT.

## Output formats
`--format text|json|md|mermaid|sarif`. The Mermaid output is a graph you can paste into a GitHub README or issue: untrusted inputs, the agent, and what it can reach, coloured by severity. SARIF uploads to GitHub code scanning.

## GitHub Action
```yaml
- uses: tidelinehq/tideline@v0.2.0   # once published; pin a version
  with:
    fail-above: 70
```

## How it differs

Tideline answers one question: if this agent is compromised, what can it reach? It needs no account, makes no network calls and never runs your MCP servers. See [docs/COMPARISON.md](docs/COMPARISON.md) for how it relates to Snyk Agent Scan.

## Exit codes and incomplete scans

`--fail-above N` exits 1 when any agent scores above N. If some files could not be analysed (invalid JSON, unreadable, oversized, symlinked, wrong type), the output says the scan is incomplete and `--fail-above` exits 3 so a broken config cannot pass a CI gate. Use `--allow-incomplete` to opt out. JSON output carries `coverage`.

## What the privacy promise covers

Tideline stores credential kinds, names and locations, never values read from env blocks, headers or arguments. Names and paths that look like known secret formats are redacted in every output. A secret in an unknown format placed in a server name or path cannot be recognised, so metadata fields are length-limited and stripped of control characters but not guaranteed secret-free. Capabilities are inferred from config names and launch arguments, not verified.

## Lethal trifecta check

An agent is flagged `POTENTIAL-TRIFECTA` when it has all three of: a tool that reads untrusted input (web pages, issues, email, chat), reachable private data (credentials or data stores), and a way to send data out (shell, web, chat, git push). With all three, one prompt injection can read a secret and send it away. Tideline lists each leg so you can remove one. In SARIF this is rule `LM002`.

## Drift: what changed since last time

```
tideline scan --format json > before.json
# ...install a new MCP server, change settings...
tideline scan --format json > after.json
tideline diff before.json after.json --fail-on-increase
```

`diff` lists agents added or removed, credentials and tools gained or lost, score changes and trifectas that became complete. With `--fail-on-increase` it exits 1 when any agent's reach grew, so CI can block a pull request that quietly widens what an agent can touch. It compares two files; it does not scan or touch the network.


## Evidence pack for regulators (MAS, EU AI Act, NYDFS, APRA, HKMA)

```bash
tideline compliance --inventory-template > ai-inventory.json   # pre-filled from the scan; fill in owner, purpose, materiality...
tideline compliance --inventory ai-inventory.json --framework mas-airm --framework eu-ai-act > evidence.md
```

The pack lists every agent with the tools and systems it can reach and the guardrails found, joins your inventory (MAS paragraph 4.7 attributes), and marks each control evidenced, partial, gap or not covered. Declare AI inside SaaS products in the inventory: a local scan cannot see it. Indicative mapping, not legal advice.

## Approval review: keep AI approvals current

An approval says "this agent may read invoices". A month later its connector gains payment access, and the approval is stale without anyone noticing. MAS Guidelines on AI Risk Management para 5.25(a): significant changes should trigger review and re-approval before implementation.

```bash
# 1. Record an approval: freezes what the covered agents can reach today (prints the ledger; Tideline writes nothing).
#    Omit --ledger for the first approval.
tideline approve --ledger approvals.json --system "Invoice reader" --agent cursor \
  --by "Head of Ops" --owner "Finance Ops" --scope "read invoices, SG only" --valid-days 365 > approvals.new.json
mv approvals.new.json approvals.json

# 2. Later, or in CI: which approvals has a change made stale?
tideline review --ledger approvals.json                       # text
tideline review --ledger approvals.json --format csv > review.csv   # import into your GRC or ticketing tool
tideline review --ledger approvals.json --fail-on-review      # exit 1 if any approval needs re-review or has expired
```

Each approval gets one status: **re-review required** (a covered agent gained a credential, capability, MCP server, cloud permission, a changed server endpoint or arguments, or a complete trifecta; any addition counts, whatever its severity), **evidence expired**, **verify** (an agent is missing or the scan was incomplete), **expiring soon** (30 days) or **current**. Agents in use with no approval are listed. Re-approving with `tideline approve` keeps the earlier approval in the record's history. `tideline compliance --approvals approvals.json` adds MAS paras 5.24-5.25 to the evidence pack. The owner decides whether a change is significant; Tideline shows which approvals to look at.

## Fixes as managed settings

```bash
tideline fix   # prints Claude Code managed settings: Read deny rules for credential files, bypass mode disabled
```

Nothing is written; review the JSON and merge it into your managed settings.

## MCP change detection

Every MCP server is fingerprinted without secret values. `tideline diff old.json new.json --fail-on-increase` fails when a server is added, its endpoint or launch arguments change, or it receives a new env var or header.
