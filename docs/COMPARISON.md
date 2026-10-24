# Scopewake vs. the nearest tools

Checked 21 Oct 2026 against the public Snyk Agent Scan README (github.com/snyk/agent-scan: 3.2k stars, Apache-2.0).
Only claims taken from that README are listed for Snyk. Not benchmarked head to head: that needs Snyk's account and token, which we have not created.

| | Scopewake | Snyk Agent Scan |
|---|---|---|
| Account or token | None | Snyk account and `SNYK_TOKEN` required (per README) |
| Network | None, enforced by a test | README warns scans may make outbound requests |
| Runs MCP server commands | Never; reads config files only | Starts stdio MCP servers to read tool descriptions (consent prompt in interactive runs) |
| Main question answered | What can a compromised agent reach? Credentials by kind and location, blast radius 0-100, chains, fixes | Is this MCP server, tool description or skill malicious or vulnerable? |
| Scope | Agent configs on the machine and CI agent workflows | MCP servers, agent skills, agent configs |
| Lethal trifecta per agent, from config alone | Yes (LM002) | Detects "Toxic Flows" (per README); method and accuracy not compared |
| Drift between scans (`diff`, CI gate) | Yes | Not stated in README |
| Exits | text, json, md, mermaid, sarif, `--fail-above` | See their docs |

Honest read: they look for bad things in what the agent loads. Scopewake measures how much damage a compromised agent could do. These overlap but are not identical; either can be run alongside the other.
Where Snyk is stronger: threat intelligence, 3.2k stars of trust, a vendor behind it, tool-description analysis we do not do.
Open: the head-to-head on one realistic setup is still to do.

Update 22 Oct 2026 (Codex audit): Snyk Agent Scan documentation names "Toxic Flows" (v0.5) and, in v0.6, risk scores that include private-data and destructive-capability indicators. It is not limited to malicious-content detection. No head-to-head performance or superiority claim is made.
