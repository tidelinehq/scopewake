# tideline v0.1.0 security review (author's review, 2026-10-21; not an independent audit)

## Claims and how each is checked
| Claim | Check | Result |
| --- | --- | --- |
| Opens no network connection | Test replaces `socket.socket` with a function that raises, then runs scan and all three report formats | pass |
| Writes no files | Test snapshots path, size and mtime of every file under a fixture before and after a scan | pass |
| Never emits a secret value | Fixture holds fake GitHub, AWS, Stripe and database-password strings; test asserts none appear in JSON, Markdown or text output | pass |
| No dangerous constructs in the package | Source-policy test fails on socket, urllib, http, requests, subprocess, ssl, eval, exec, `__import__`, shutil, any file write, `open(` | pass |
| Does not follow symlinks | Test points `.mcp.json` at an outside file and asserts it is not read | pass |
| Bounded reads | Files over 256 KB are skipped; directory walk depth 4; heavy directories skipped | by construction |

## Known limits
- Values are read into memory to detect secret shapes, then discarded. They exist briefly in process memory.
- A path name and variable name can themselves be sensitive; they are in the output. Treat reports as confidential.
- Pattern matching gives false positives and false negatives.
- Python import checks are string matches, not a proof; an independent review is needed before enterprise claims.
- Supply chain: zero runtime dependencies. Release signing is not yet set up.

## Release gates still open
1. Independent read-through of the diff by a second reviewer (human or tool).
2. Signed release (PyPI trusted publishing or Sigstore).
3. Repository secret scan on first push.

## Addendum 2026-10-21 (author's checks, still not independent)
- Hostile-input fuzz: deeply nested JSON (5000 levels), wrongly typed MCP fields, binary and malformed workflow/env files, a symlinked credential file. Found and fixed two crashes (RecursionError on nested JSON; TypeError on non-list `args`). Covered by `test_hostile_inputs_do_not_crash`.
- Regex denial-of-service: every secret and name pattern run against ten adversarial 250 KB strings; worst single search 0.017 s.
- New output formats (Mermaid, SARIF) are included in the no-secret-value test.
- Release pipeline: PyPI trusted publishing with build attestations (no stored token). Requires the maintainer to register the trusted publisher on PyPI.
- Still open: independent read-through; first signed release.
