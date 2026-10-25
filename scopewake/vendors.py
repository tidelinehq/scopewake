"""Vendor AI identification: find AI features inside the SaaS an institution already uses, plus shadow AI.

MAS Guidelines on AI Risk Management:
  para 4.2 and fn 21  identification should minimally cover AI in services from material third-party providers,
                      including SaaS "not explicitly sold as AI, but [which] contains AI features";
  para 4.3            a designated control function is the final arbiter of what constitutes AI use, keeps
                      documentation of the identification process and outcomes, and reviews it as AI is
                      introduced into existing third-party services;
  para 4.4            residual risk from unidentified AI (inadequate vendor disclosure, shadow AI) must be
                      identified and mitigated.

Scopewake only PROPOSES matches. Each proposal is accepted or rejected by the institution's control function and the
decision is logged. Inputs are files exported by the institution; nothing is sent anywhere. Indicative mapping, not
legal advice. Catalogue facts come from vendor documentation and are marked "unverified" where not yet checked.
"""
import csv
import hashlib
import io
import json
import re
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import __version__
from .safe import safe, scrub_tree

MAX_INPUT_BYTES = 32 * 1024 * 1024
STALE_DAYS = 45
CATALOGUE = Path(__file__).with_name("data") / "saas_ai_catalogue.json"
DECISIONS_KIND = "vendor-ai-decisions"
FACT_FIELDS = ("default_on", "customer_data_training", "model_providers", "admin_can_disable")

REF_IDENTIFY = "MAS AIRM para 4.2, fn 21"
REF_ARBITER = "MAS AIRM para 4.3"
REF_RESIDUAL = "MAS AIRM para 4.4"

# Column names seen in Okta and Microsoft Entra exports, plus generic ones.
APP_COLUMNS = ("label", "app name", "application name", "application", "app", "name", "displayname", "display name",
               "appdisplayname", "app display name", "service", "product")
VENDOR_COLUMNS = ("vendor", "publisher", "publishername", "publisher name", "provider", "supplier", "company")
DOMAIN_COLUMNS = ("domain", "host", "hostname", "fqdn", "query", "url", "destination", "site")


# ---------------------------------------------------------------- loading

def _read(path, what: str) -> str:
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError as e:
        raise ValueError(f"cannot read {what} {safe(str(path), 200)}: {safe(e, 200)}")
    if size > MAX_INPUT_BYTES:
        raise ValueError(f"{what} is larger than {MAX_INPUT_BYTES // (1024 * 1024)} MB")
    return p.read_text(encoding="utf-8-sig", errors="replace")


def load_catalogue(path=None) -> dict:
    raw = _read(path or CATALOGUE, "catalogue")
    try:
        cat = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"catalogue is not valid JSON: {e.msg}")
    if not isinstance(cat, dict) or not isinstance(cat.get("products"), list):
        raise ValueError("catalogue must be an object with a 'products' list")
    seen = set()
    for pr in cat["products"]:
        if not isinstance(pr, dict) or not pr.get("id") or not pr.get("product"):
            raise ValueError("every catalogue product needs 'id' and 'product'")
        if pr["id"] in seen:
            raise ValueError(f"duplicate catalogue id {safe(pr['id'], 80)}")
        seen.add(pr["id"])
    return cat


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(s).lower()).strip()


def _tokens(s: str) -> List[str]:
    return _norm(s).split()


def _pick(header: List[str], names) -> Optional[int]:
    low = [_norm(h) for h in header]
    for n in names:
        if _norm(n) in low:
            return low.index(_norm(n))
    return None


def _rows(text: str) -> Tuple[Optional[List[str]], List[List[str]]]:
    """Parse CSV (with or without header) or JSON (list of strings/objects, or Graph-style {'value': [...]})."""
    s = text.strip()
    if s[:1] in "[{":
        try:
            data = json.loads(s)
        except json.JSONDecodeError as e:
            raise ValueError(f"input is not valid JSON: {e.msg}")
        if isinstance(data, dict):
            data = data.get("value") or data.get("apps") or data.get("items") or data.get("data") or []
        if not isinstance(data, list):
            raise ValueError("JSON input must be a list")
        if all(isinstance(x, str) for x in data):
            return None, [[x] for x in data]
        keys: List[str] = []
        for x in data:
            if isinstance(x, dict):
                for k in x:
                    if k not in keys and isinstance(x[k], (str, int, float)):
                        keys.append(k)
        return keys, [[str(x.get(k, "")) if isinstance(x, dict) else "" for k in keys] for x in data]
    rows = [r for r in csv.reader(io.StringIO(s)) if any(c.strip() for c in r)]
    if not rows:
        return None, []
    first = [_norm(c) for c in rows[0]]
    known = {_norm(c) for c in APP_COLUMNS + VENDOR_COLUMNS + DOMAIN_COLUMNS} | {"id", "status", "type", "count", "hits"}
    if any(c in known for c in first):
        return rows[0], rows[1:]
    return None, rows


def parse_apps(path) -> List[dict]:
    """Applications from an identity-provider export (Okta app list, Entra enterprise apps) or a plain list."""
    header, rows = _rows(_read(path, "application list"))
    ai = _pick(header, APP_COLUMNS) if header else 0
    vi = _pick(header, VENDOR_COLUMNS) if header else None
    if ai is None:
        raise ValueError("application list has no recognisable name column (expected e.g. 'label', 'displayName', 'name')")
    out, seen = [], set()
    for r in rows:
        name = r[ai].strip() if ai < len(r) else ""
        if not name or _norm(name) in seen:
            continue
        seen.add(_norm(name))
        out.append({"name": name[:200], "vendor": (r[vi].strip()[:200] if vi is not None and vi < len(r) else "")})
    return out


def _host(v: str) -> str:
    v = v.strip().lower()
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)
    v = v.split("/")[0].split("@")[-1].split(":")[0].rstrip(".")
    return v if re.fullmatch(r"[a-z0-9.-]+\.[a-z0-9-]+", v) else ""


def parse_domains(path) -> List[dict]:
    """Domains from a DNS or proxy log summary: one per line, or CSV with a domain/host column and optional count."""
    header, rows = _rows(_read(path, "domain list"))
    di = _pick(header, DOMAIN_COLUMNS) if header else 0
    ci = _pick(header, ("count", "hits", "requests", "queries")) if header else (1 if rows and len(rows[0]) > 1 else None)
    if di is None:
        raise ValueError("domain list has no recognisable domain column (expected e.g. 'domain', 'host', 'query')")
    agg: Dict[str, int] = {}
    for r in rows:
        h = _host(r[di]) if di < len(r) else ""
        if not h:
            continue
        n = 1
        if ci is not None and ci < len(r):
            try:
                n = max(1, int(float(r[ci])))
            except ValueError:
                n = 1
        agg[h] = agg.get(h, 0) + n
    return [{"domain": d, "count": c} for d, c in sorted(agg.items())]


def parse_extensions(path) -> List[dict]:
    """Browser extensions from an endpoint/MDM inventory: CSV with name (and optional id) or a plain list."""
    header, rows = _rows(_read(path, "extension list"))
    ni = _pick(header, ("extension name", "extension", "name", "displayname", "title")) if header else 0
    ii = _pick(header, ("extension id", "id", "extensionid")) if header else None
    if ni is None:
        raise ValueError("extension list has no recognisable name column")
    out, seen = [], set()
    for r in rows:
        name = r[ni].strip() if ni < len(r) else ""
        eid = r[ii].strip().lower() if ii is not None and ii < len(r) else ""
        if (not name and not eid) or (name, eid) in seen:
            continue
        seen.add((name, eid))
        out.append({"name": name[:200], "id": eid[:64]})
    return out


def parse_material(path) -> List[str]:
    """The institution's own list of material third-party service providers (vendor names, one per line or CSV)."""
    header, rows = _rows(_read(path, "material-provider list"))
    vi = (_pick(header, VENDOR_COLUMNS + ("name", "service provider", "third party")) if header else 0)
    if vi is None:
        vi = 0
    return sorted({r[vi].strip() for r in rows if vi < len(r) and r[vi].strip()})


# ---------------------------------------------------------------- matching

def _contains(hay: List[str], needle: List[str]) -> bool:
    n = len(needle)
    return n > 0 and any(hay[i:i + n] == needle for i in range(len(hay) - n + 1))


def _match_app(app: dict, products: List[dict]) -> Optional[dict]:
    toks = _tokens(app["name"])
    best, best_len = None, 0
    for pr in products:
        for alias in [pr["product"]] + pr.get("idp_names", []):
            at = _tokens(alias)
            if _contains(toks, at) and len(at) > best_len:
                best, best_len = pr, len(at)
    return best


def _match_domain(host: str, products: List[dict]) -> Optional[dict]:
    best, best_len = None, 0
    for pr in products:
        for d in pr.get("domains", []):
            d = d.lower()
            if (host == d or host.endswith("." + d)) and len(d) > best_len:
                best, best_len = pr, len(d)
    return best


def _match_ext(ext: dict, products: List[dict]) -> Optional[dict]:
    toks = _tokens(ext["name"])
    for pr in products:
        if ext["id"] and ext["id"] in [x.lower() for x in pr.get("extension_ids", [])]:
            return pr
    for pr in products:
        for alias in pr.get("extension_names", []):
            if _contains(toks, _tokens(alias)):
                return pr
    return None


def _is_material(pr: dict, app_vendor: str, material: List[str]) -> bool:
    names = {_norm(m) for m in material}
    cands = {_norm(pr.get("vendor", "")), _norm(app_vendor)} | {_norm(v) for v in pr.get("vendor_aliases", [])}
    cands.discard("")
    for m in names:
        for c in cands:
            if m and (m == c or _contains(c.split(), m.split()) or _contains(m.split(), c.split())):
                return True
    return False


def _pid(source: str, observed: str, product_id: str) -> str:
    return hashlib.sha256(f"{source}|{_norm(observed)}|{product_id}".encode()).hexdigest()[:12]


def _features(pr: dict) -> List[dict]:
    out = []
    for f in pr.get("features", []):
        row = {"name": f.get("name", ""), "checked": f.get("checked", ""), "sources": f.get("sources", []),
               "notes": f.get("notes", "")}
        for k in FACT_FIELDS:
            row[k] = f.get(k, "unverified")
        out.append(row)
    return out


def identify(catalogue: dict, apps=(), domains=(), extensions=(), material=(), decisions=None,
             today: Optional[date] = None) -> dict:
    today = today or date.today()
    products = catalogue["products"]
    material = list(material)
    proposals: Dict[str, dict] = {}
    unmatched_apps = []

    def add(source, observed, pr, vendor_hint="", count=None):
        pid = _pid(source, observed, pr["id"])
        if pid in proposals:
            return
        proposals[pid] = {
            "id": pid, "source": source, "observed": observed, "product_id": pr["id"], "product": pr["product"],
            "vendor": pr.get("vendor", ""), "category": pr.get("category", ""), "shadow": bool(pr.get("shadow_ai")),
            "material": _is_material(pr, vendor_hint, material) if material else None,
            "count": count, "features": _features(pr),
            "refs": [REF_RESIDUAL] if source != "idp" else [REF_IDENTIFY],
            "status": "proposed", "decision": None,
        }

    for a in apps:
        pr = _match_app(a, products)
        if pr:
            add("idp", a["name"], pr, a.get("vendor", ""))
        else:
            unmatched_apps.append(a["name"])
    for d in domains:
        pr = _match_domain(d["domain"], products)
        if pr:
            add("dns", d["domain"], pr, count=d["count"])
    for e in extensions:
        pr = _match_ext(e, products)
        if pr:
            add("extension", e["name"] or e["id"], pr)

    # Shadow AI = seen on the network or in the browser but not among sanctioned (identity-provider) apps.
    sanctioned = {p["product_id"] for p in proposals.values() if p["source"] == "idp"}
    for p in proposals.values():
        if p["source"] != "idp":
            p["shadow"] = p["product_id"] not in sanctioned

    dec = _decision_index(decisions)
    for p in proposals.values():
        d = dec.get(p["id"])
        if d:
            p["status"] = "accepted" if d["decision"] == "accept" else "rejected"
            p["decision"] = d

    def order(p):
        return (0 if p["material"] else 1 if p["material"] is None else 2, 0 if p["shadow"] else 1,
                {"proposed": 0, "accepted": 1, "rejected": 2}[p["status"]], p["product"].lower(), p["observed"].lower())

    rows = sorted(proposals.values(), key=order)
    checked = [f.get("checked") for pr in products for f in pr.get("features", []) if f.get("checked")]
    stale = 0
    for c in checked:
        try:
            if (today - date.fromisoformat(c)).days > STALE_DAYS:
                stale += 1
        except ValueError:
            stale += 1
    facts = [f.get(k, "unverified") for pr in products for f in pr.get("features", []) for k in FACT_FIELDS]
    coverage = {
        "idp_apps": len(apps), "idp_apps_matched": len(apps) - len(unmatched_apps), "unmatched_apps": unmatched_apps,
        "domains": len(domains), "extensions": len(extensions), "material_providers": len(material),
        "shadow_ai_assessed": bool(domains or extensions),
        "materiality_supplied": bool(material),
        "catalogue_products": len(products), "catalogue_version": catalogue.get("version", ""),
        "catalogue_facts": len(facts), "catalogue_facts_unverified": sum(1 for v in facts if v == "unverified"),
        "catalogue_entries_stale": stale,
    }
    gaps = []
    if not apps:
        gaps.append(f"No identity-provider app list supplied: sanctioned SaaS was not assessed ({REF_IDENTIFY}).")
    if not coverage["shadow_ai_assessed"]:
        gaps.append(f"Shadow AI NOT assessed: no DNS/proxy domain list or browser-extension list supplied ({REF_RESIDUAL}).")
    if not material:
        gaps.append(f"No material-provider list supplied: proposals are not ranked by materiality ({REF_IDENTIFY}). "
                    "Materiality is the institution's determination, not Scopewake's.")
    if unmatched_apps:
        gaps.append(f"{len(unmatched_apps)} app(s) are not in the catalogue and need manual review; absence from the "
                    "catalogue does not mean an app has no AI features.")
    if coverage["catalogue_facts_unverified"]:
        gaps.append(f"{coverage['catalogue_facts_unverified']} of {len(facts)} catalogue facts are unverified against vendor documentation.")
    if stale:
        gaps.append(f"{stale} catalogue feature entr(ies) were last checked more than {STALE_DAYS} days ago.")
    summary = {s: sum(1 for p in rows if p["status"] == s) for s in ("proposed", "accepted", "rejected")}
    summary["shadow"] = sum(1 for p in rows if p["shadow"])
    summary["material"] = sum(1 for p in rows if p["material"])
    return scrub_tree({
        "tool": "scopewake", "version": __version__, "kind": "vendor-ai-identification", "date": today.isoformat(),
        "note": ("Proposals only. The designated control function is the final arbiter of what constitutes AI use "
                 f"({REF_ARBITER}). Maintains identification evidence that could support {REF_IDENTIFY}, "
                 f"{REF_ARBITER} and {REF_RESIDUAL}. Indicative mapping, not legal advice."),
        "summary": summary, "coverage": coverage, "gaps": gaps, "proposals": rows,
    })


# ---------------------------------------------------------------- decisions (control-function sign-off)

def empty_decisions() -> dict:
    return {"kind": DECISIONS_KIND, "tool": "scopewake", "version": __version__, "decisions": []}


def load_decisions(path) -> dict:
    try:
        d = json.loads(_read(path, "decisions log"))
    except json.JSONDecodeError as e:
        raise ValueError(f"decisions log is not valid JSON: {e.msg}")
    if not isinstance(d, dict) or d.get("kind") != DECISIONS_KIND or not isinstance(d.get("decisions"), list):
        raise ValueError(f"not a Scopewake decisions log (expected kind '{DECISIONS_KIND}')")
    return d


def _decision_index(log) -> Dict[str, dict]:
    idx: Dict[str, dict] = {}
    for d in (log or {}).get("decisions", []):
        if isinstance(d, dict) and d.get("proposal"):
            idx[d["proposal"]] = d  # later entries supersede earlier ones; history stays in the log
    return idx


def decide(log: dict, result: dict, proposal_id: str, decision: str, by: str, today: date, reason: str = "") -> dict:
    if decision not in ("accept", "reject"):
        raise ValueError("decision must be 'accept' or 'reject'")
    if not by.strip():
        raise ValueError("--by (the control-function decision maker) is required")
    match = [p for p in result["proposals"] if p["id"] == proposal_id]
    if not match:
        raise ValueError(f"no proposal with id {safe(proposal_id, 40)} in this run")
    p = match[0]
    out = json.loads(json.dumps(log))
    out["decisions"].append({
        "proposal": proposal_id, "decision": decision, "by": by.strip()[:200], "date": today.isoformat(),
        "reason": reason.strip()[:1000], "observed": p["observed"], "source": p["source"], "product": p["product"],
        "catalogue_version": result["coverage"]["catalogue_version"], "ref": REF_ARBITER,
    })
    out["version"] = __version__
    return scrub_tree(out)


# ---------------------------------------------------------------- catalogue maintenance

def catalogue_diff(old: dict, new: dict) -> dict:
    """What changed between two catalogue versions (for the monthly re-check log, para 4.3)."""
    o = {p["id"]: p for p in old["products"]}
    n = {p["id"]: p for p in new["products"]}
    changed = []
    for pid in sorted(set(o) & set(n)):
        of = {f["name"]: f for f in o[pid].get("features", [])}
        nf = {f["name"]: f for f in n[pid].get("features", [])}
        diffs = [f"feature added: {k}" for k in sorted(set(nf) - set(of))]
        diffs += [f"feature removed: {k}" for k in sorted(set(of) - set(nf))]
        for k in sorted(set(of) & set(nf)):
            for fld in FACT_FIELDS:
                if of[k].get(fld, "unverified") != nf[k].get(fld, "unverified"):
                    diffs.append(f"{k}: {fld} {of[k].get(fld, 'unverified')!r} -> {nf[k].get(fld, 'unverified')!r}")
        if diffs:
            changed.append({"id": pid, "product": n[pid]["product"], "changes": diffs})
    return {"old_version": old.get("version", ""), "new_version": new.get("version", ""),
            "added": sorted(set(n) - set(o)), "removed": sorted(set(o) - set(n)), "changed": changed}


# ---------------------------------------------------------------- output

def _fv(v) -> str:
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, list):
        return ", ".join(v) if v else "none named"
    return str(v)


def to_text(res: dict, markdown: bool = False) -> str:
    h = "## " if markdown else ""
    L = [f"{'# ' if markdown else ''}Scopewake vendor AI identification ({res['date']})", "", res["note"], ""]
    s, c = res["summary"], res["coverage"]
    L += [f"{h}Summary", "",
          f"- Proposals: {s['proposed']} awaiting decision, {s['accepted']} accepted, {s['rejected']} rejected",
          f"- Shadow AI (seen on network/browser, not a sanctioned app): {s['shadow']}",
          f"- From material providers: {s['material']}" + ("" if c["materiality_supplied"] else " (no material-provider list supplied)"),
          f"- Inputs: {c['idp_apps']} apps ({c['idp_apps_matched']} matched), {c['domains']} domains, {c['extensions']} extensions",
          f"- Catalogue: {c['catalogue_products']} products, version {c['catalogue_version']}; "
          f"{c['catalogue_facts_unverified']}/{c['catalogue_facts']} facts unverified", ""]
    if res["gaps"]:
        L += [f"{h}Coverage gaps", ""] + [f"- {g}" for g in res["gaps"]] + [""]
    L += [f"{h}Proposals", ""]
    if not res["proposals"]:
        L += ["No AI features matched.", ""]
    for p in res["proposals"]:
        tags = [p["status"].upper()]
        if p["material"]:
            tags.append("MATERIAL")
        if p["shadow"]:
            tags.append("SHADOW AI")
        L.append(f"{'- **' if markdown else '* '}{p['product']}{'**' if markdown else ''} ({p['vendor']}) "
                 f"[{', '.join(tags)}] id {p['id']}")
        L.append(f"    seen via {p['source']}: {p['observed']}" + (f" ({p['count']} hits)" if p["count"] else "")
                 + f"; {', '.join(p['refs'])}")
        for f in p["features"]:
            L.append(f"    - {f['name']}: on by default {_fv(f['default_on'])}; trains on customer data "
                     f"{_fv(f['customer_data_training'])}; models {_fv(f['model_providers'])}; "
                     f"admin can disable {_fv(f['admin_can_disable'])}"
                     + (f"; checked {f['checked']}" if f["checked"] else ""))
            if f["notes"]:
                L.append(f"      note: {f['notes']}")
            for src in f["sources"][:3]:
                L.append(f"      source: {src}")
        if p["decision"]:
            d = p["decision"]
            L.append(f"    decision: {d['decision']} by {d['by']} on {d['date']}" + (f" ({d['reason']})" if d["reason"] else ""))
        L.append("")
    if c["unmatched_apps"]:
        L += [f"{h}Apps not in catalogue (review manually)", ""] + [f"- {a}" for a in c["unmatched_apps"][:500]]
        if len(c["unmatched_apps"]) > 500:
            L.append(f"- ... and {len(c['unmatched_apps']) - 500} more")
    return "\n".join(L).rstrip() + "\n"


def to_csv(res: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "status", "product", "vendor", "source", "observed", "material", "shadow_ai", "feature",
                "default_on", "customer_data_training", "model_providers", "admin_can_disable", "checked", "sources",
                "decided_by", "decided_on", "reason", "refs"])
    for p in res["proposals"]:
        d = p["decision"] or {}
        for f in p["features"] or [{"name": "", "sources": [], "checked": "", **{k: "" for k in FACT_FIELDS}}]:
            w.writerow([p["id"], p["status"], p["product"], p["vendor"], p["source"], p["observed"],
                        "" if p["material"] is None else _fv(p["material"]), _fv(p["shadow"]), f["name"],
                        _fv(f["default_on"]), _fv(f["customer_data_training"]), _fv(f["model_providers"]),
                        _fv(f["admin_can_disable"]), f["checked"], " ".join(f["sources"]),
                        d.get("by", ""), d.get("date", ""), d.get("reason", ""), "; ".join(p["refs"])])
    return buf.getvalue()
