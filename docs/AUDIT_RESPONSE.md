# Response to the independent audit of 2026-10-22

Auditor: OpenAI Codex (ChatGPT plan), given only the code snapshot and AUDIT_PACK.md. Not independent of the founder's choice of auditor, but independent of the author. Each finding below was reproduced against the code before being accepted. Regression tests: `tests/test_audit_regressions.py` (16 tests; 33 tests total pass).

| ID | Finding | Verdict | Fix |
|---|---|---|---|
| C1 | Unrelated deny rule (`Edit(**/.env.example)`) marked `.env` credentials mitigated | Confirmed | Only `Read(...)` deny rules whose pattern matches the file count; added note that Read denies do not stop shell commands |
| C2 | Secret-shaped server name appeared in all five formats | Confirmed | `safe.py`: names, keys, paths and notes are cleaned at the source; control characters and table breakers removed; known secret formats redacted; final output scrubbed again. The guarantee is narrowed in the README: unknown secret formats cannot be recognised |
| C3 | Unparseable config exited 0 as "no agents found" | Confirmed | Scan records issues (invalid JSON, oversized, unreadable, symlinked, wrong type); output says incomplete; JSON has `coverage`; with `--fail-above` an incomplete scan exits 3 unless `--allow-incomplete` |
| C4 | Added shell-capable server did not trip `diff --fail-on-increase` | Confirmed | Any added capability, added credential, higher score or completed trifecta counts as worse. Agents matched by kind and name, not checkout path |
| C5 | `allow: 123` crashed; `credentials: null` crashed diff | Confirmed | Types validated; bad fields become scan issues; bad reports exit 2 with a message |
| C6 | Symlinked ancestor directory (`~/.cursor`) was read | Confirmed | Every path component under the home or project root is checked. Existence checks for credential files still follow symlinks deliberately (an agent could read them too); contents are never read through a symlink. A race between check and read remains; the tool is read-only, so impact is limited to reading a file the user can already read |
| C7 | Keyword substring matching (`webpack` read as `web`; docker launcher read as Docker capability) | Confirmed | Token matching; launcher commands (npx, uvx, docker, ...) ignored as capability evidence. Output states capabilities are inferred. Still no labelled benchmark: detection accuracy is unmeasured |
| C8 | `github` label alone satisfied all three trifecta legs | Confirmed in part | github, gitlab, slack count as private data only with a matching credential. Renamed "potential" in all outputs. Config cannot prove scopes or data flow |
| C9 | Action installed latest package when version unset | Confirmed | Default pinned to 0.1.0; description separates scan (no network) from install (network). Provenance of the package is unverified until a release exists |
| C10 | SARIF reduced paths to basenames | Confirmed | Repository-relative URIs; home files shown as `~/...` |
| Limits | Unbounded traversal | Confirmed | Project walk stops at 50,000 entries and reports an issue. Output size and diff input size remain unbounded |

## Disputed or clarified
- R3 (company exit vs founder cash): the pack's round 39 row copied the report's short label "P(exit >= $100M)". Rounds 21-35 define the quantity as founder personal cash >= $100M. The pack label was loose; whether the model's definition holds is for the method audit.
- Auditor's statement that the signed release is inconsistent with "the one open gate": correct. Open gates: independent review of the fixes, signed release, build on CI. The pack overstated.
- Build on the Mac: the auditor built and installed the wheel on Python 3.12. This closes the local-build gap; CI still has to confirm the matrix.
- R1 (research artifacts absent): the auditor received only the code snapshot; the method bundle (71 files) was prepared for a separate method audit.

## Audit 2 (re-audit of the fixed snapshot)
Triaged N01-N17. Fixed in code, each with a regression test (tests/test_reaudit_regressions.py):
- Redaction: every report field, error and diff output is scrubbed; NFKC and zero-width normalisation; whole PEM blocks; prefixed tokens (N01, N02, N10).
- Completeness: wrong types, null or array roots, invalid UTF-8, directories in place of files, oversized files, missing project root, symlink loops and the depth limit all make the scan incomplete (N03, N09, N12). `diff` fails on an incomplete new scan (N04). Malformed reports exit 2 (N07).
- Identity: agents keyed by kind, name, relative source and occurrence; credentials by relative location; long names no longer collide; order and checkout path do not matter (N06, N08).
- Semantics: a Read deny is a mitigation only while autonomy < 0.9; bash/shell launchers classified as shell execution; path arguments no longer read as capabilities; empty env values ignored (N05, N11); SARIF URIs percent-encoded and home files given no repo location (N13); Mermaid shows incomplete scans (N15); `mcpServers` empty no longer hides `servers` (N17).

Documented limits, not fixed:
- A race between path checks and the read (ancestor directory swapped) remains; read-only tool, so impact is reading a file the user could already read.
- Redaction is pattern-based; unknown secret formats and secrets split across fields are not guaranteed to be caught. Docs no longer claim otherwise.
- Detector accuracy is unmeasured (no labelled corpus). Python 3.9 compatibility is syntax-checked only; the CI matrix has not run.
- SARIF results without a repo location may not display in GitHub code scanning; Markdown and Mermaid rendering untested in real viewers.
- Third-party action refs and build inputs must be pinned to commit SHAs when the real repository exists.
- Exit code 1 (threshold exceeded) takes precedence over 3 (incomplete).

## Not fixed yet
- Detector accuracy is unmeasured; need a labelled public config corpus.
- Codex TOML MCP servers are not parsed.
- Signed release, CI matrix and attestations unverified until the repository exists.
