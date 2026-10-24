"""Output hygiene. Untrusted metadata (server names, keys, paths, notes) is cleaned before it is stored or printed.

Limits (documented in the README): only known secret formats are recognised; a secret split across fields
or in an unknown format cannot be detected.
"""
import hashlib
import re
import unicodedata

from .patterns import VALUE_PATTERNS

_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_INVISIBLE = re.compile("[​-‏ - ⁠-⁤﻿]")
_PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S)
# Detection patterns use word boundaries; redaction must not, or "x<token>" would survive.
_SCRUB = [re.compile(rx.pattern.replace(r"\b", ""), rx.flags) for _, rx, _ in VALUE_PATTERNS]
MAX_LEN = 120


def has_secret_shape(text: str) -> bool:
    return any(rx.search(text) for _, rx, _ in VALUE_PATTERNS)


def _normalise(text: str) -> str:
    return _INVISIBLE.sub("", unicodedata.normalize("NFKC", str(text)))


def scrub(text: str) -> str:
    """Redact anything shaped like a known secret, including whole PEM blocks."""
    t = _PEM.sub("[redacted]", _normalise(text))
    for rx in _SCRUB:
        t = rx.sub("[redacted]", t)
    return t


def safe(text, limit: int = MAX_LEN) -> str:
    """Display-safe identifier. Truncation keeps a short hash of the original so different long names stay distinct."""
    original = str(text)
    t = _CTRL.sub(" ", _normalise(original))
    t = scrub(t)
    t = t.replace("|", "/").replace("`", "'").replace("<", "(").replace(">", ")")
    if len(t) > limit:
        digest = hashlib.sha1(original.encode("utf-8", "replace")).hexdigest()[:6]
        t = t[: max(limit - 10, 1)] + "..~" + digest
    return t


def scrub_tree(obj):
    """Redact every string inside nested dicts/lists (used before JSON serialisation, where escaping hides secrets)."""
    if isinstance(obj, str):
        return scrub(obj)
    if isinstance(obj, dict):
        return {scrub(str(k)): scrub_tree(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [scrub_tree(v) for v in obj]
    return obj


def sanitize_agent(a):
    """Clean every string field of an Agent in place (explicit fields, identity-length text)."""
    a.id, a.name, a.source, a.source_rel = (safe(x, 1000) for x in (a.id, a.name, a.source, a.source_rel))
    a.kind, a.autonomy_note = safe(a.kind, 200), safe(a.autonomy_note, 1000)
    a.notes = [safe(x, 1000) for x in a.notes]
    a.chains = [safe(x, 1000) for x in a.chains]
    a.fixes = [safe(x, 1000) for x in a.fixes]
    for c in a.capabilities:
        c.name, c.via = safe(c.name, 200), safe(c.via, 1000)
    for c in a.credentials:
        c.kind, c.location, c.how, c.name, c.loc_rel = (safe(x, 1000) for x in (c.kind, c.location, c.how, c.name, c.loc_rel))
    return a
