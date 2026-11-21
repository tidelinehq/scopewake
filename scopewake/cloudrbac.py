"""Offline Azure and Google Cloud reach analysis, from exports the customer creates. Scopewake never calls either cloud.

Azure input:  `az role assignment list --all --output json`           (required)
              `az role definition list --output json`                 (optional; exact actions for every role)
GCP input:    `gcloud projects get-iam-policy PROJECT --format=json`  (one project), or
              `gcloud asset search-all-iam-policies --scope=... --format=json` (many resources)
              role definitions with `includedPermissions`, one object or a list (optional; needed for custom roles),
              for example from `gcloud iam roles describe ROLE --project PROJECT --format=json`

Output: for each principal, which high-impact classes of action it can reach. The classes match `scopewake aws`.

This is an approximation and says so in every report:
- Azure: deny assignments, Privileged Identity Management (eligible) assignments and Entra directory roles are not
  in the export. A condition on an assignment is reported as "conditional", never evaluated.
- GCP: deny policies, organisation policies and inherited bindings from parents that are not in the export are not
  seen. A binding condition is reported as "conditional", never evaluated.
- Both: group members are not in the export, so reach through a group is counted for the group, not its members.
- A role with no definition supplied is evaluated from a short built-in table and marked "approximated from its
  name"; a role in neither place is listed as not evaluated, never counted as zero.
"""
import json
import os
import re
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from .safe import safe

MAX_EXPORT_BYTES = 64 * 1024 * 1024
MAX_HOPS = 3
LEVEL_RANK = {"full": 3, "conditional": 2, "scoped": 1}

IMPACT = {
    "full-admin": "do anything in the subscription or project, including granting access",
    "privilege-escalation": "grant itself more access, up to full admin",
    "secrets-read": "read stored secrets",
    "data-destroy": "delete production data or infrastructure",
    "data-read": "read production data",
    "kms-decrypt": "decrypt data protected by managed keys",
    "role-assumption": "act as other identities",
    "compute-launch": "run code on new or existing compute (cost and pivot)",
    "audit-tamper": "turn off or redirect audit logging",
}
SEV = {"full-admin": 10, "privilege-escalation": 10, "secrets-read": 9, "data-destroy": 9, "data-read": 8,
       "kms-decrypt": 8, "role-assumption": 8, "compute-launch": 7, "audit-tamper": 7}

# Azure probes. A leading "data:" marks a data-plane action (dataActions); the rest are control-plane (actions).
AZURE_PROBES = {
    "privilege-escalation": ["Microsoft.Authorization/roleAssignments/write", "Microsoft.Authorization/roleDefinitions/write",
                             "Microsoft.Authorization/elevateAccess/Action"],
    "secrets-read": ["data:Microsoft.KeyVault/vaults/secrets/getSecret/action", "Microsoft.KeyVault/vaults/accessPolicies/write",
                     "Microsoft.Web/sites/config/list/action"],
    "data-destroy": ["Microsoft.Storage/storageAccounts/delete", "Microsoft.Sql/servers/databases/delete",
                     "Microsoft.Compute/virtualMachines/delete", "Microsoft.Resources/subscriptions/resourceGroups/delete",
                     "data:Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"],
    "data-read": ["data:Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
                  "Microsoft.Storage/storageAccounts/listKeys/action", "Microsoft.DocumentDB/databaseAccounts/listKeys/action",
                  "Microsoft.Sql/servers/databases/export/action"],
    "kms-decrypt": ["data:Microsoft.KeyVault/vaults/keys/decrypt/action", "data:Microsoft.KeyVault/vaults/keys/unwrap/action"],
    "role-assumption": ["Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"],
    "compute-launch": ["Microsoft.Compute/virtualMachines/write", "Microsoft.Compute/virtualMachines/runCommand/action",
                       "Microsoft.Web/sites/write", "Microsoft.ContainerInstance/containerGroups/write",
                       "Microsoft.Automation/automationAccounts/runbooks/write"],
    "audit-tamper": ["Microsoft.Insights/diagnosticSettings/delete", "Microsoft.Insights/diagnosticSettings/write",
                     "Microsoft.OperationalInsights/workspaces/delete"],
}
_KV = "Microsoft.KeyVault/vaults/"
_BLOB = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/"
# Used only when a role's definition is not supplied. Approximate; supply `az role definition list` for exact results.
AZURE_BUILTIN = {
    "owner": [{"actions": ["*"]}],
    "contributor": [{"actions": ["*"], "notActions": ["Microsoft.Authorization/*/Delete", "Microsoft.Authorization/*/Write",
                                                         "Microsoft.Authorization/elevateAccess/Action"]}],
    "reader": [{"actions": ["*/read"]}],
    "user access administrator": [{"actions": ["*/read", "Microsoft.Authorization/*"]}],
    "role based access control administrator": [{"actions": ["Microsoft.Authorization/roleAssignments/write",
                                                              "Microsoft.Authorization/roleAssignments/delete"]}],
    "key vault administrator": [{"dataActions": [_KV + "*"]}],
    "key vault secrets officer": [{"dataActions": [_KV + "secrets/*"]}],
    "key vault secrets user": [{"dataActions": [_KV + "secrets/getSecret/action", _KV + "secrets/readMetadata/action"]}],
    "key vault crypto user": [{"dataActions": [_KV + "keys/decrypt/action", _KV + "keys/unwrap/action", _KV + "keys/read"]}],
    "key vault crypto officer": [{"dataActions": [_KV + "keys/*"]}],
    "key vault contributor": [{"actions": ["Microsoft.KeyVault/*"]}],
    "storage blob data owner": [{"dataActions": [_BLOB + "*"]}],
    "storage blob data contributor": [{"dataActions": [_BLOB + "read", _BLOB + "write", _BLOB + "delete"]}],
    "storage blob data reader": [{"dataActions": [_BLOB + "read"]}],
    "storage account contributor": [{"actions": ["Microsoft.Storage/storageAccounts/*"]}],
    "virtual machine contributor": [{"actions": ["Microsoft.Compute/virtualMachines/*"]}],
    "website contributor": [{"actions": ["Microsoft.Web/sites/*"]}],
    "sql db contributor": [{"actions": ["Microsoft.Sql/servers/databases/*"]}],
    "managed identity operator": [{"actions": ["Microsoft.ManagedIdentity/userAssignedIdentities/*/read",
                                                "Microsoft.ManagedIdentity/userAssignedIdentities/*/assign/action"]}],
    "monitoring contributor": [{"actions": ["Microsoft.Insights/diagnosticSettings/*"]}],
    "automation contributor": [{"actions": ["Microsoft.Automation/automationAccounts/*"]}],
}

GCP_PROBES = {
    "privilege-escalation": ["resourcemanager.projects.setIamPolicy", "resourcemanager.folders.setIamPolicy",
                             "resourcemanager.organizations.setIamPolicy", "iam.serviceAccounts.setIamPolicy",
                             "iam.roles.update", "iam.serviceAccountKeys.create", "deploymentmanager.deployments.create"],
    "secrets-read": ["secretmanager.versions.access"],
    "data-destroy": ["storage.objects.delete", "storage.buckets.delete", "bigquery.tables.delete", "bigquery.datasets.delete",
                     "cloudsql.instances.delete", "compute.instances.delete", "resourcemanager.projects.delete"],
    "data-read": ["storage.objects.get", "bigquery.tables.getData", "datastore.entities.get", "spanner.databases.select",
                  "cloudsql.instances.export"],
    "kms-decrypt": ["cloudkms.cryptoKeyVersions.useToDecrypt"],
    "role-assumption": ["iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.actAs",
                        "iam.serviceAccounts.implicitDelegation", "iam.serviceAccounts.signBlob", "iam.serviceAccounts.signJwt"],
    "compute-launch": ["compute.instances.create", "compute.instances.setMetadata", "cloudfunctions.functions.create",
                       "cloudfunctions.functions.update", "run.services.create", "run.services.update"],
    "audit-tamper": ["logging.sinks.delete", "logging.sinks.update", "logging.logs.delete", "logging.exclusions.create"],
}
GCP_IMPERSONATE = ["iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.actAs", "iam.serviceAccounts.implicitDelegation",
                   "iam.serviceAccounts.signBlob", "iam.serviceAccounts.signJwt", "iam.serviceAccountKeys.create"]
# (allowed patterns, excluded patterns). Used only when a role's permissions are not supplied. Approximate.
GCP_BUILTIN = {
    "roles/owner": (["*"], []),
    "roles/editor": (["*"], ["*.setIamPolicy", "iam.roles.*", "secretmanager.versions.access", "resourcemanager.projects.delete",
                             "iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.signBlob",
                             "iam.serviceAccounts.signJwt", "iam.serviceAccounts.implicitDelegation"]),
    "roles/viewer": (["*.get", "*.list", "*.getData"], []),
    "roles/iam.securityAdmin": (["*.setIamPolicy", "*.getIamPolicy"], []),
    "roles/resourcemanager.projectIamAdmin": (["resourcemanager.projects.setIamPolicy"], []),
    "roles/resourcemanager.organizationAdmin": (["resourcemanager.organizations.setIamPolicy", "resourcemanager.folders.setIamPolicy",
                                                 "resourcemanager.projects.setIamPolicy"], []),
    "roles/resourcemanager.folderAdmin": (["resourcemanager.folders.setIamPolicy", "resourcemanager.projects.setIamPolicy"], []),
    "roles/iam.serviceAccountTokenCreator": (["iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.signBlob",
                                              "iam.serviceAccounts.signJwt", "iam.serviceAccounts.implicitDelegation"], []),
    "roles/iam.serviceAccountUser": (["iam.serviceAccounts.actAs"], []),
    "roles/iam.serviceAccountKeyAdmin": (["iam.serviceAccountKeys.*"], []),
    "roles/iam.serviceAccountAdmin": (["iam.serviceAccounts.setIamPolicy", "iam.serviceAccounts.create", "iam.serviceAccounts.delete"], []),
    "roles/iam.roleAdmin": (["iam.roles.*"], []),
    "roles/secretmanager.admin": (["secretmanager.*"], []),
    "roles/secretmanager.secretAccessor": (["secretmanager.versions.access"], []),
    "roles/storage.admin": (["storage.*"], []),
    "roles/storage.objectAdmin": (["storage.objects.*"], []),
    "roles/storage.objectViewer": (["storage.objects.get", "storage.objects.list"], []),
    "roles/bigquery.admin": (["bigquery.*"], []),
    "roles/bigquery.dataOwner": (["bigquery.tables.*", "bigquery.datasets.*"], []),
    "roles/bigquery.dataEditor": (["bigquery.tables.getData", "bigquery.tables.delete", "bigquery.tables.update"], []),
    "roles/bigquery.dataViewer": (["bigquery.tables.getData"], []),
    "roles/cloudkms.cryptoKeyDecrypter": (["cloudkms.cryptoKeyVersions.useToDecrypt"], []),
    "roles/cloudkms.cryptoKeyEncrypterDecrypter": (["cloudkms.cryptoKeyVersions.useToDecrypt", "cloudkms.cryptoKeyVersions.useToEncrypt"], []),
    "roles/compute.admin": (["compute.*"], []),
    "roles/compute.instanceAdmin.v1": (["compute.instances.*"], []),
    "roles/cloudfunctions.admin": (["cloudfunctions.*"], []),
    "roles/cloudfunctions.developer": (["cloudfunctions.functions.*"], []),
    "roles/run.admin": (["run.*"], []),
    "roles/run.developer": (["run.services.*"], []),
    "roles/logging.admin": (["logging.*"], []),
    "roles/logging.configWriter": (["logging.sinks.*", "logging.exclusions.*"], []),
    "roles/cloudsql.admin": (["cloudsql.*"], []),
    "roles/datastore.owner": (["datastore.*"], []),
    "roles/datastore.user": (["datastore.entities.*"], []),
    "roles/deploymentmanager.editor": (["deploymentmanager.deployments.*"], []),
}

LIMITS = {
    "azure": ("Offline approximation: deny assignments, eligible (PIM) assignments, Entra directory roles and group "
              "members are not in the export and are not evaluated. Conditional assignments are marked."),
    "gcp": ("Offline approximation: deny policies, organisation policies, bindings on parents outside the export and "
            "group members are not evaluated. Conditional bindings are marked."),
}


class CloudExportError(ValueError):
    pass


def read_json(path: str):
    """Bounded, no-follow read of an export file."""
    p = Path(path)
    if p.is_symlink():
        raise CloudExportError(f"refusing symlinked export: {safe(path, 200)}")
    if not p.is_file():
        raise CloudExportError(f"export file not found: {safe(path, 200)}")
    fd = os.open(str(p), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        chunks, total = [], 0
        while total <= MAX_EXPORT_BYTES:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(fd)
    if total > MAX_EXPORT_BYTES:
        raise CloudExportError(f"export larger than {MAX_EXPORT_BYTES // (1024 * 1024)} MB")
    try:
        return json.loads(b"".join(chunks).decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise CloudExportError(f"export is not valid JSON: {e.__class__.__name__}")


def _strs(v) -> List[str]:
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


class Rbac:
    """Principals, the grants they hold, and a per-provider test of what each grant allows."""

    def __init__(self, provider: str):
        self.provider = provider
        self.principals: Dict[str, dict] = {}       # key -> {"name", "type", "grants": [...]}
        self.issues: List[str] = []
        self.probes = AZURE_PROBES if provider == "azure" else GCP_PROBES

    def _grant(self, key: str, name: str, typ: str, allowed: Callable[[str], bool], level: str, role: str,
               admin: bool, target: str = "", known: bool = True):
        p = self.principals.setdefault(key, {"name": safe(name, 200), "type": safe(typ, 40), "grants": [], "unknown": []})
        p["grants"].append({"allowed": allowed, "level": level, "role": safe(role, 120), "admin": admin, "target": target})
        if not known and safe(role, 120) not in p["unknown"]:
            p["unknown"].append(safe(role, 120))

    def direct_classes(self, key: str) -> Dict[str, dict]:
        found: Dict[str, dict] = {}
        for g in self.principals[key]["grants"]:
            hits = {}
            if g["admin"]:
                hits["full-admin"] = ["*"]
            for cls, probes in self.probes.items():
                h = [a for a in probes if g["allowed"](a)]
                if h:
                    hits[cls] = h
            # Attaching another identity to compute it can create or change: the same shape as AWS iam:PassRole.
            attach_id = "iam.serviceAccounts.actAs" if self.provider == "gcp" else "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
            if "privilege-escalation" not in hits and g["allowed"](attach_id):
                pair = [a for a in self.probes["compute-launch"] if g["allowed"](a)]
                if pair:
                    hits["privilege-escalation"] = [attach_id] + pair
            for cls, h in hits.items():
                prev = found.get(cls)
                if prev is None or LEVEL_RANK[g["level"]] > LEVEL_RANK[prev["level"]]:
                    found[cls] = {"class": cls, "level": g["level"], "actions": [a.replace("data:", "") for a in h], "role": g["role"]}
        return found

    def assumable(self, key: str) -> List[str]:
        """GCP only: service accounts this principal can act as, from the bindings in the export."""
        if self.provider != "gcp":
            return []
        out = set()
        sas = [k for k, p in self.principals.items() if p["type"] == "serviceAccount"]
        for g in self.principals[key]["grants"]:
            if any(g["allowed"](a) for a in GCP_IMPERSONATE):
                out.update([g["target"]] if g["target"] else sas)
        return sorted(k for k in out if k in self.principals and k != key)

    def reach(self, key: str) -> dict:
        out: Dict[str, dict] = {}
        seen, frontier = {key}, [(key, [])]
        for depth in range(MAX_HOPS + 1):
            nxt = []
            for cur, path in frontier:
                for cls, info in self.direct_classes(cur).items():
                    via = f"role {info['role']}" if not path else "via " + " → ".join(self.principals[r]["name"] for r in path)
                    lvl = info["level"]
                    sev = SEV[cls] - (0 if lvl == "full" else 1 if lvl == "conditional" else 2)
                    prev = out.get(cls)
                    if prev is None or sev > prev["severity"] or (sev == prev["severity"] and len(path) < prev["_hops"]):
                        out[cls] = {"class": cls, "severity": sev, "level": lvl, "actions": info["actions"][:6], "via": via,
                                    "impact": IMPACT[cls], "_hops": len(path)}
                if depth < MAX_HOPS:
                    for r in self.assumable(cur):
                        if r not in seen:
                            seen.add(r)
                            nxt.append((r, path + [r]))
            frontier = nxt
        classes = sorted(out.values(), key=lambda c: (-c["severity"], c["class"]))
        for c in classes:
            c.pop("_hops", None)
        p = self.principals[key]
        return {"provider": self.provider, "principal": safe(key, 200), "name": p["name"], "type": p["type"],
                "max_severity": max((c["severity"] for c in classes), default=0), "classes": classes,
                "unevaluated_roles": sorted(p["unknown"]),
                "assumable_roles": [self.principals[r]["name"] for r in self.assumable(key)]}

    def find(self, key: str) -> Optional[str]:
        if key in self.principals:
            return key
        k = key.strip().lower()
        hits = [a for a, p in self.principals.items()
                if a.lower() == k or p["name"].lower() == k or a.lower().split(":", 1)[-1] == k]
        return hits[0] if len(hits) == 1 else None


# ---------------------------------------------------------------- Azure

def _az_match(action: str, pattern: str) -> bool:
    """Azure wildcards; a pattern such as a/*/assign/action also covers the operation a/assign/action."""
    return fnmatchcase(action, pattern) or ("/*/" in pattern and fnmatchcase(action, pattern.replace("/*/", "/")))


def _az_checker(perms: List[dict]) -> Callable[[str], bool]:
    blocks = []
    for p in perms:
        if isinstance(p, dict):
            blocks.append(tuple([x.lower() for x in _strs(p.get(f))] for f in ("actions", "notActions", "dataActions", "notDataActions")))

    def allowed(action: str) -> bool:
        data = action.startswith("data:")
        a = action[5:].lower() if data else action.lower()
        for acts, nots, dacts, dnots in blocks:
            yes, no = (dacts, dnots) if data else (acts, nots)
            if any(_az_match(a, x) for x in yes) and not any(_az_match(a, x) for x in no):
                return True
        return False
    return allowed


def _az_level(scope: str, condition) -> str:
    s = (scope or "").rstrip("/").lower()
    wide = s == "" or s.startswith("/providers/microsoft.management/managementgroups/") or re.fullmatch(r"/subscriptions/[^/]+", s)
    if not wide:
        return "scoped"
    return "conditional" if condition else "full"


def load_azure(assignments, definitions=None) -> Rbac:
    if not isinstance(assignments, list) or not all(isinstance(x, dict) for x in assignments):
        raise CloudExportError("not an `az role assignment list --output json` export (expected a JSON list)")
    if assignments and not any("roleDefinitionName" in x or "roleDefinitionId" in x for x in assignments):
        raise CloudExportError("not an `az role assignment list` export (no roleDefinitionName or roleDefinitionId)")
    defs_by_name, defs_by_id = {}, {}
    if definitions is not None:
        if not isinstance(definitions, list) or not all(isinstance(x, dict) for x in definitions):
            raise CloudExportError("not an `az role definition list --output json` export (expected a JSON list)")
        for d in definitions:
            perms = d.get("permissions") if isinstance(d.get("permissions"), list) else []
            if isinstance(d.get("roleName"), str):
                defs_by_name[d["roleName"].lower()] = perms
            for f in ("id", "name"):
                if isinstance(d.get(f), str):
                    defs_by_id[d[f].lower().rsplit("/", 1)[-1]] = perms
    acct = Rbac("azure")
    groups = 0
    for x in assignments:
        pid = str(x.get("principalId") or x.get("principalName") or "").strip()
        if not pid:
            acct.issues.append("an assignment has no principal and was skipped")
            continue
        role, known = str(x.get("roleDefinitionName") or "").strip(), True
        rid = str(x.get("roleDefinitionId") or "").lower().rsplit("/", 1)[-1]
        perms = defs_by_name.get(role.lower())
        if perms is None and rid:
            perms = defs_by_id.get(rid)
        if perms is None:
            perms = AZURE_BUILTIN.get(role.lower())
            if perms is None:
                acct.issues.append(f"role not evaluated (no definition supplied): {safe(role or rid, 80)}")
                perms, known = [], False
            else:
                acct.issues.append(f"built-in role approximated from its name: {safe(role, 80)}")
        allowed = _az_checker(perms)
        ptype = str(x.get("principalType") or "")
        groups += ptype.lower() in ("group", "foreigngroup")
        level = _az_level(str(x.get("scope") or ""), x.get("condition"))
        admin = allowed("Microsoft.Authorization/roleAssignments/write") and allowed("Microsoft.Compute/virtualMachines/write") \
            and allowed("Microsoft.Storage/storageAccounts/delete")
        acct._grant(pid, str(x.get("principalName") or pid), ptype or "principal", allowed, level, role or rid, admin, known=known)
    if groups:
        acct.issues.append(f"{groups} assignment(s) are to groups; group members are not in the export, so reach through a group is not counted for its members")
    return acct


# ---------------------------------------------------------------- GCP

def _gcp_checker(role: str, defs: Dict[str, List[str]], issues: List[str]) -> Tuple[Callable[[str], bool], bool]:
    if role in defs:
        have = set(defs[role])
        return (lambda perm: perm in have), True
    if role in GCP_BUILTIN:
        allow, deny = GCP_BUILTIN[role]
        issues.append(f"predefined role approximated from its name: {safe(role, 80)}")
        return (lambda perm: any(fnmatchcase(perm, a) for a in allow) and not any(fnmatchcase(perm, d) for d in deny)), True
    issues.append(f"role not evaluated (no permissions supplied): {safe(role, 120)}")
    return (lambda perm: False), False


_SA_RES = re.compile(r"//iam\.googleapis\.com/projects/[^/]+/serviceAccounts/([^/]+)$")
_WIDE_RES = re.compile(r"//cloudresourcemanager\.googleapis\.com/(projects|folders|organizations)/[^/]+$")


def _gcp_policies(data) -> List[Tuple[str, dict]]:
    """(resource, policy) pairs from a project policy, a list of policies, or asset-search results."""
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        data = data["results"]
    items = data if isinstance(data, list) else [data]
    out = []
    for it in items:
        if not isinstance(it, dict):
            raise CloudExportError("not a Google Cloud IAM policy export")
        if isinstance(it.get("policy"), dict):
            out.append((str(it.get("resource") or ""), it["policy"]))
        elif "bindings" in it or "etag" in it or "version" in it:
            out.append(("", it))
        else:
            raise CloudExportError("not a Google Cloud IAM policy export (no 'bindings' or 'policy')")
    return out


def load_gcp(policies, roles=None) -> Rbac:
    defs: Dict[str, List[str]] = {}
    if roles is not None:
        rl = roles if isinstance(roles, list) else [roles]
        if not all(isinstance(r, dict) for r in rl):
            raise CloudExportError("role definitions must be a JSON object or list of objects with 'name' and 'includedPermissions'")
        for r in rl:
            if isinstance(r.get("name"), str):
                defs[r["name"]] = _strs(r.get("includedPermissions"))
    acct = Rbac("gcp")
    groups, public = 0, 0
    for resource, pol in _gcp_policies(policies):
        bindings = pol.get("bindings") or []
        if not isinstance(bindings, list):
            raise CloudExportError("policy 'bindings' must be a list")
        sa = _SA_RES.search(resource)
        wide = resource == "" or bool(_WIDE_RES.search(resource))
        for b in bindings:
            if not isinstance(b, dict) or not isinstance(b.get("role"), str):
                continue
            role = b["role"]
            allowed, known = _gcp_checker(role, defs, acct.issues)
            level = "scoped" if not wide else "conditional" if b.get("condition") else "full"
            target = f"serviceAccount:{sa.group(1)}" if sa else ""
            for m in _strs(b.get("members")):
                if m.startswith("deleted:"):
                    continue
                typ = m.split(":", 1)[0] if ":" in m else m
                groups += typ in ("group", "domain")
                public += m in ("allUsers", "allAuthenticatedUsers")
                acct._grant(m, m, typ, allowed, level, role, role == "roles/owner", target, known)
    acct.issues = sorted(set(acct.issues))
    if groups:
        acct.issues.append(f"{groups} binding member(s) are groups or domains; their members are not in the export, so reach through them is not counted for the members")
    if public:
        acct.issues.append(f"{public} binding member(s) are allUsers or allAuthenticatedUsers: that access is open to anyone, and is listed under those names")
    return acct


# ---------------------------------------------------------------- shared output

def analyse(acct: Rbac) -> Tuple[List[dict], List[str]]:
    rows = [acct.reach(k) for k in acct.principals]
    rows.sort(key=lambda r: (-r["max_severity"], -len(r["classes"]), r["name"]))
    return rows, sorted(set(acct.issues))


def principals_text(provider: str, rows: List[dict], issues: List[str]) -> str:
    out = [f"scopewake {provider}: principals ranked by worst reachable action class", LIMITS[provider], ""]
    if issues:
        out += [f"WARNING {len(issues)} note(s) on what could not be evaluated exactly:"] + [f"  - {safe(i, 240)}" for i in issues] + [""]
    for i, r in enumerate(rows, 1):
        out.append(f"{i}. {safe(r['type'], 20):<16} {safe(r['name'], 70):<40} worst severity {r['max_severity']:>2}")
        for c in r["classes"][:4]:
            out.append(f"     - {c['class']} ({c['level']}, {safe(c['via'], 120)}): {c['impact']}")
        for role in r["unevaluated_roles"]:
            out.append(f"     ! role not evaluated, so this may understate reach: {safe(role, 120)}")
    return "\n".join(out)


CRED_KINDS = {"azure": {"azure-token-cache"}, "gcp": {"gcp-adc"}}
CRED_NAMES = {"azure": re.compile(r"AZURE|ARM_", re.I), "gcp": re.compile(r"GCP|GOOGLE|GCLOUD", re.I)}


def _holds(agent, provider: str) -> bool:
    return any(c.kind in CRED_KINDS[provider] or (c.kind == "ci-secret" and CRED_NAMES[provider].search(c.name or ""))
               for c in agent.credentials if not c.mitigated)


def attach(agents, acct: Rbac, mapping: Dict[str, str]) -> List[str]:
    """Add Azure or GCP reach to agents that hold that cloud's credentials. Returns issues to report."""
    from .model import Capability
    prov, label = acct.provider, {"azure": "Azure", "gcp": "Google Cloud"}[acct.provider]
    issues: List[str] = []
    for a in agents:
        if not _holds(a, prov):
            continue
        key = next((k for k in sorted(mapping, key=len, reverse=True) if k != "*" and (a.id.startswith(k) or a.kind == k)), None)
        target = mapping.get(key) if key else mapping.get("*")
        if not target:
            issues.append(f"{a.name} holds {label} credentials but no principal was mapped (use --{prov}-as)")
            continue
        pk = acct.find(target)
        if not pk:
            issues.append(f"{label} principal not found or ambiguous in export: {target}")
            continue
        r = acct.reach(pk)
        issues += [f"{a.name}: {label} role not evaluated, so its reach may be understated: {role}" for role in r["unevaluated_roles"]]
        a.clouds.append({"provider": prov, "principal": r["principal"], "name": r["name"], "type": r["type"],
                         "max_severity": r["max_severity"], "classes": r["classes"]})
        for c in r["classes"]:
            a.capabilities.append(Capability(f"{prov}:{c['class']}", c["severity"], False, via=f"{prov} {r['type']} {r['name']} ({c['via']})"))
        for c in a.credentials:
            if c.kind in CRED_KINDS[prov] or (c.kind == "ci-secret" and CRED_NAMES[prov].search(c.name or "")):
                c.severity = max(3, r["max_severity"]) if r["classes"] else 3
        a.notes.append(f"{label} reach from the export for {r['type']} {r['name']}: worst severity {r['max_severity']} "
                       f"({', '.join(c['class'] for c in r['classes']) or 'no high-impact actions'}). {LIMITS[prov]}")
    return sorted(set(issues + acct.issues))
