# Security policy

Tideline is read-only, local and makes no network calls (enforced by tests). See `SECURITY_REVIEW.md` for the claims, checks and open gates.

## Reporting a vulnerability
Use GitHub private vulnerability reporting (Security tab > Report a vulnerability). Do not open a public issue for a security problem. Include the version (`tideline --version` once available, or the commit), what you did and what happened.
Target: acknowledge within 7 days, fix or explain within 30 days. This is a one-person project; times are goals, not guarantees.

## In scope
Output of a secret value; any network access; any write to the scanned tree; reading outside the documented paths; crashes on hostile config files (hang, memory blow-up).
## Out of scope
Agents or credential formats the tool does not claim to detect; the heuristic score being "wrong" for your setup (open a normal issue).
