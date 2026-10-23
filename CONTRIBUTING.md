# Contributing

Thanks for helping. The rules protect the tool's trust properties:
1. Python standard library only. No new dependencies.
2. No network, subprocess, eval or file-writing code in `tideline/` (a test enforces this).
3. Never store or print a secret value. Add a test with a fake secret assembled at runtime (never commit anything that looks like a real key).
4. Every new agent or credential pattern needs a fixture and a test.
5. Run `python -m unittest discover -s tests` before opening a PR.

New agent support: open an issue with the config file path and a redacted example, or a PR adding a detector in `scanner.py` and patterns in `patterns.py`.
By contributing you agree your work is released under the MIT licence.
