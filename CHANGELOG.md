# Changelog

## 0.3.0

- Renamed from Tideline to Scopewake: package `scopewake`, command `scopewake`, repository `tidelinehq/scopewake`, website https://scopewake.com. JSON reports now say `"tool": "scopewake"`.
- `scopewake diff` still accepts reports written by `tideline` 0.2.x, so a stored baseline keeps working.
- No change to scanning, scoring, approval or review rules.

## 0.2.0 (first public release)

- `tideline approve` and `tideline review`: approval review. An approval freezes the reach of the agents it covers; `review` marks each approval re-review required, evidence expired, verify, expiring soon or current, cites MAS paras 5.24-5.25 / 4.11, lists agents with no approval, and exports CSV for GRC tools. Any addition to reach counts, whatever its severity. `--fail-on-review` gates CI. Nothing is written: `approve` prints the updated ledger, keeping earlier approvals in its history.
- `tideline compliance --approvals`: adds MAS paras 5.24-5.25 (change-triggered re-approval) to the evidence pack.
- `diff` reports now carry cloud (AWS) reach classes for comparison.
- `tideline compliance`: evidence pack that merges the scan with the firm's own AI inventory (JSON) and maps it to MAS Guidelines on AI Risk Management (paras 2.3-2.5, 4.2, 4.7, 4.8 fn 25, section 4, 5.11), EU AI Act deployer duties (Art. 26), NYDFS Part 500, APRA and HKMA. Each control is marked evidenced, partial, gap or not covered; an empty scan is never "evidenced". `--inventory-template` pre-fills an inventory from the scan.
- MCP change detection: each MCP server is fingerprinted (transport, endpoint scheme and host, hash of redacted arguments, env and header NAMES). `tideline diff` reports servers added, removed or changed (endpoint, arguments, new env vars or headers) and counts these as increased reach.
- `tideline fix`: prints Claude Code managed settings (Read deny rules for credential files and folders, disable bypass mode) plus notes; nothing is written.

Second audit (N01-N17): redaction of all fields and diff output, completeness for malformed/oversized/looping inputs, stable diff identity, SARIF URI encoding, and softened privacy claims; see docs/AUDIT_RESPONSE.md.

Fixes from the independent audit of 2026-10-22 (see docs/AUDIT_RESPONSE.md):
- Deny-rule mitigation now requires a matching `Read(...)` rule; invalid or unreadable configs make the scan incomplete (exit 3 with `--fail-above`); output redaction and escaping centralised; `diff` gates on added capabilities and matches agents by kind and name; ancestor symlinks are not followed; keyword matching is token-based; the trifecta is reported as potential; the Action pins the package version; SARIF keeps repository-relative paths.

- Lethal trifecta check per agent (untrusted input + private data + outbound channel); SARIF rule LM002.
- `tideline diff old.json new.json [--fail-on-increase]` for drift between scans.

## 0.1.0 (not published)
- First release: finds Claude Code, Cursor, Windsurf, VS Code MCP, Claude Desktop, Gemini CLI, Codex CLI and GitHub Actions agent workflows.
- Lists reachable credentials (kind and location only) and capabilities; scores 0-100; prints chains and fixes.
- Output: text, JSON, Markdown, Mermaid graph, SARIF 2.1.0. `--fail-above N` for CI.
- Local, read-only, no network, standard library only; enforced by tests.
- Hardened against hostile config files (deeply nested JSON, wrongly typed fields); covered by a test.
