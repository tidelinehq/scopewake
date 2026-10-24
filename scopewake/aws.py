"""Offline AWS IAM blast-radius analysis.

Input: the JSON written by `aws iam get-account-authorization-details` (the customer runs that command;
Scopewake never calls AWS and never sees a key). Output: for each IAM user or role, which high-impact
classes of action it can reach, directly or by assuming other roles.

This is an approximation and says so in every report:
- Service control policies, resource policies, session policies and most condition keys are not in the
  export, so they are not evaluated. An Allow that carries a Condition is reported as "conditional".
- Only explicit, unconditional Deny statements that cover all resources remove an action.
- Permission boundaries in the export are applied; a boundary that is not in the export is reported.
"""
import json
import os
import re
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Dict, List, Optional, Tuple

MAX_EXPORT_BYTES = 64 * 1024 * 1024
MAX_HOPS = 3

# (class, severity, probe actions, plain-language impact)
RISK_CLASSES = [
    ("full-admin", 10, ["scopewake-probe:AnyAction"], "do anything in the AWS account"),
    ("privilege-escalation", 10, [
        "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:AttachUserPolicy", "iam:AttachRolePolicy",
        "iam:AttachGroupPolicy", "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy",
        "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile", "iam:UpdateAssumeRolePolicy",
        "iam:AddUserToGroup"], "grant itself more access, up to full admin"),
    ("secrets-read", 9, ["secretsmanager:GetSecretValue", "ssm:GetParameter", "ssm:GetParameters",
                         "ssm:GetParametersByPath"], "read stored secrets and parameters"),
    ("data-destroy", 9, ["s3:DeleteObject", "s3:DeleteBucket", "dynamodb:DeleteTable", "rds:DeleteDBInstance",
                         "rds:DeleteDBCluster", "ec2:TerminateInstances", "backup:DeleteRecoveryPoint"],
     "delete production data or infrastructure"),
    ("data-read", 8, ["s3:GetObject", "dynamodb:Scan", "dynamodb:Query", "dynamodb:GetItem",
                      "rds-data:ExecuteStatement", "rds:CreateDBSnapshot", "rds:ModifyDBInstance"],
     "read production data"),
    ("kms-decrypt", 8, ["kms:Decrypt"], "decrypt data protected by KMS keys"),
    ("role-assumption", 8, ["sts:AssumeRole"], "switch into other roles"),
    ("compute-launch", 7, ["ec2:RunInstances", "lambda:CreateFunction", "lambda:UpdateFunctionCode",
                           "ecs:RunTask"], "run code on new or existing compute (cost and pivot)"),
    ("audit-tamper", 7, ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
                         "guardduty:DeleteDetector"], "turn off audit logging"),
]
CLASS_SEV = {c: s for c, s, _, _ in RISK_CLASSES}
CLASS_IMPACT = {c: i for c, _, _, i in RISK_CLASSES}
# Passing a role to new compute is escalation only together with a way to launch compute.
PASSROLE_PAIRS = ["lambda:CreateFunction", "ec2:RunInstances", "ecs:RunTask", "glue:CreateDevEndpoint",
                  "cloudformation:CreateStack"]

# Used only when an attached AWS-managed policy is missing from the export (exports filtered by type).
MANAGED_FALLBACK = {
    "AdministratorAccess": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    "PowerUserAccess": [{"Effect": "Allow", "NotAction": ["iam:*", "organizations:*", "account:*"], "Resource": "*"}],
    "IAMFullAccess": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}],
    "AmazonS3FullAccess": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
    "AmazonS3ReadOnlyAccess": [{"Effect": "Allow", "Action": ["s3:Get*", "s3:List*"], "Resource": "*"}],
    "SecretsManagerReadWrite": [{"Effect": "Allow", "Action": "secretsmanager:*", "Resource": "*"}],
    "AmazonDynamoDBFullAccess": [{"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"}],
    "AmazonRDSFullAccess": [{"Effect": "Allow", "Action": "rds:*", "Resource": "*"}],
    "AmazonEC2FullAccess": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}],
    "AWSLambda_FullAccess": [{"Effect": "Allow", "Action": "lambda:*", "Resource": "*"},
                             {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}],
    "ReadOnlyAccess": [{"Effect": "Allow", "Action": ["s3:Get*", "dynamodb:Get*", "dynamodb:Scan", "dynamodb:Query",
                                                       "ssm:GetParameter*", "*:Describe*", "*:List*"], "Resource": "*"}],
}

LEVEL_RANK = {"full": 3, "conditional": 2, "scoped": 1}


_PCT = re.compile(rb"%([0-9A-Fa-f]{2})")


def unquote(s: str) -> str:
    """Percent-decode (local copy so the package imports nothing network-related)."""
    return _PCT.sub(lambda m: bytes([int(m.group(1), 16)]), s.encode("utf-8")).decode("utf-8", "replace")


class AwsExportError(ValueError):
    pass


# ---------- loading ----------
def load_export(path: str) -> dict:
    """Bounded, no-follow read of the authorization-details JSON."""
    p = Path(path)
    if p.is_symlink():
        raise AwsExportError(f"refusing symlinked export: {path}")
    if not p.is_file():
        raise AwsExportError(f"export file not found: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(str(p), flags)
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
        raise AwsExportError(f"export larger than {MAX_EXPORT_BYTES // (1024 * 1024)} MB")
    try:
        data = json.loads(b"".join(chunks).decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise AwsExportError(f"export is not valid JSON: {e.__class__.__name__}")
    if not isinstance(data, dict) or not any(k in data for k in ("UserDetailList", "RoleDetailList", "GroupDetailList")):
        raise AwsExportError("not an `aws iam get-account-authorization-details` export")
    return data


def _doc(raw) -> dict:
    """Policy documents are JSON objects in CLI output and URL-encoded strings in raw API output."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(unquote(raw))
        except json.JSONDecodeError:
            return {}
    return {}


def _list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _stmts(doc) -> List[dict]:
    return [s for s in _list(_doc(doc).get("Statement")) if isinstance(s, dict)]


# ---------- evaluation ----------
def _match(patterns, value: str) -> bool:
    v = value.lower()
    return any(isinstance(p, str) and fnmatchcase(v, p.lower()) for p in patterns)


def _covers_action(s: dict, action: str) -> bool:
    if "Action" in s:
        return _match(_list(s["Action"]), action)
    if "NotAction" in s:
        return not _match(_list(s["NotAction"]), action)
    return False


def _resource_level(s: dict, resource: Optional[str]) -> Optional[str]:
    if "Resource" in s:
        res = _list(s["Resource"])
        if resource is not None:
            return "full" if _match(res, resource) else None
        return "full" if "*" in res else "scoped"
    if "NotResource" in s:
        if resource is not None:
            return None if _match(_list(s["NotResource"]), resource) else "full"
        return "scoped"
    return None


def evaluate(stmts: List[dict], action: str, resource: Optional[str] = None) -> Optional[str]:
    """Best Allow level for an action ('full', 'conditional', 'scoped') or None. Unconditional Deny on all resources wins."""
    best = None
    for s in stmts:
        if not _covers_action(s, action):
            continue
        lvl = _resource_level(s, resource)
        if lvl is None:
            continue
        effect = str(s.get("Effect", "")).lower()
        if effect == "deny":
            if lvl == "full" and not s.get("Condition") and ("Resource" in s and "*" in _list(s["Resource"]) or resource is not None):
                return None
            continue
        if effect == "allow":
            if s.get("Condition") and lvl == "full":
                lvl = "conditional"
            if best is None or LEVEL_RANK[lvl] > LEVEL_RANK[best]:
                best = lvl
    return best


def _cap(a: Optional[str], b: Optional[str]) -> Optional[str]:
    if a is None or b is None:
        return None
    return a if LEVEL_RANK[a] <= LEVEL_RANK[b] else b


class Account:
    def __init__(self, data: dict):
        self.issues: List[str] = []
        self.policies: Dict[str, List[dict]] = {}
        for p in _list(data.get("Policies")):
            if not isinstance(p, dict):
                continue
            doc = None
            for v in _list(p.get("PolicyVersionList")):
                if isinstance(v, dict) and (v.get("IsDefaultVersion") or v.get("VersionId") == p.get("DefaultVersionId")):
                    doc = v.get("Document")
            if p.get("Arn"):
                self.policies[p["Arn"]] = _stmts(doc)
        self.groups = {g.get("GroupName"): g for g in _list(data.get("GroupDetailList")) if isinstance(g, dict)}
        self.principals: Dict[str, dict] = {}
        for u in _list(data.get("UserDetailList")):
            if isinstance(u, dict) and u.get("Arn"):
                self.principals[u["Arn"]] = {"type": "user", "name": u.get("UserName", ""), "raw": u}
        for r in _list(data.get("RoleDetailList")):
            if isinstance(r, dict) and r.get("Arn"):
                self.principals[r["Arn"]] = {"type": "role", "name": r.get("RoleName", ""), "raw": r}
        self._stmt_cache: Dict[str, Tuple[List[dict], Optional[List[dict]]]] = {}

    def _managed(self, att: dict) -> List[dict]:
        arn = att.get("PolicyArn", "")
        if arn in self.policies:
            return self.policies[arn]
        name = att.get("PolicyName") or arn.rsplit("/", 1)[-1]
        if arn.startswith("arn:aws:iam::aws:policy/") and name in MANAGED_FALLBACK:
            self.issues.append(f"AWS-managed policy {name} not in export; used a built-in summary")
            return MANAGED_FALLBACK[name]
        self.issues.append(f"attached policy not in export, not evaluated: {arn or name}")
        return []

    def statements(self, arn: str) -> Tuple[List[dict], Optional[List[dict]]]:
        if arn in self._stmt_cache:
            return self._stmt_cache[arn]
        p = self.principals[arn]
        raw = p["raw"]
        stmts: List[dict] = []
        inline_key = "UserPolicyList" if p["type"] == "user" else "RolePolicyList"
        for ip in _list(raw.get(inline_key)):
            if isinstance(ip, dict):
                stmts += _stmts(ip.get("PolicyDocument"))
        for att in _list(raw.get("AttachedManagedPolicies")):
            if isinstance(att, dict):
                stmts += self._managed(att)
        if p["type"] == "user":
            for gname in _list(raw.get("GroupList")):
                g = self.groups.get(gname)
                if not g:
                    self.issues.append(f"group {gname} not in export, not evaluated")
                    continue
                for ip in _list(g.get("GroupPolicyList")):
                    if isinstance(ip, dict):
                        stmts += _stmts(ip.get("PolicyDocument"))
                for att in _list(g.get("AttachedManagedPolicies")):
                    if isinstance(att, dict):
                        stmts += self._managed(att)
        boundary = None
        pb = raw.get("PermissionsBoundary")
        if isinstance(pb, dict) and pb.get("PermissionsBoundaryArn"):
            barn = pb["PermissionsBoundaryArn"]
            if barn in self.policies:
                boundary = self.policies[barn]
            else:
                bname = barn.rsplit("/", 1)[-1]
                if barn.startswith("arn:aws:iam::aws:policy/") and bname in MANAGED_FALLBACK:
                    boundary = MANAGED_FALLBACK[bname]
                else:
                    self.issues.append(f"permission boundary not in export, ignored for {p['name']}: {barn}")
        self._stmt_cache[arn] = (stmts, boundary)
        return stmts, boundary

    def allowed(self, arn: str, action: str, resource: Optional[str] = None) -> Optional[str]:
        stmts, boundary = self.statements(arn)
        lvl = evaluate(stmts, action, resource)
        if boundary is not None:
            lvl = _cap(lvl, evaluate(boundary, action, resource))
        return lvl

    def _trusts(self, role_arn: str, src_arn: str) -> bool:
        raw = self.principals[role_arn]["raw"]
        acct = src_arn.split(":")[4] if src_arn.count(":") >= 5 else ""
        ok = {src_arn, f"arn:aws:iam::{acct}:root", acct, "*"}
        for s in _stmts(raw.get("AssumeRolePolicyDocument")):
            if str(s.get("Effect", "")).lower() != "allow" or not _covers_action(s, "sts:AssumeRole"):
                continue
            pr = s.get("Principal")
            vals = _list(pr.get("AWS")) if isinstance(pr, dict) else _list(pr)
            if any(v in ok for v in vals if isinstance(v, str)):
                return True
        return False

    def assumable(self, arn: str) -> List[str]:
        out = []
        for r, p in self.principals.items():
            if p["type"] != "role" or r == arn:
                continue
            if self.allowed(arn, "sts:AssumeRole", r) and self._trusts(r, arn):
                out.append(r)
        return out

    def direct_classes(self, arn: str) -> Dict[str, dict]:
        found: Dict[str, dict] = {}
        for cls, sev, probes, _ in RISK_CLASSES:
            hits, best = [], None
            for a in probes:
                lvl = self.allowed(arn, a)
                if lvl:
                    hits.append(a)
                    if best is None or LEVEL_RANK[lvl] > LEVEL_RANK[best]:
                        best = lvl
            if hits:
                found[cls] = {"class": cls, "level": best, "actions": hits}
        pr = self.allowed(arn, "iam:PassRole")
        if pr and "privilege-escalation" not in found:
            pairs = [a for a in PASSROLE_PAIRS if self.allowed(arn, a)]
            if pairs:
                found["privilege-escalation"] = {"class": "privilege-escalation", "level": "scoped" if pr == "scoped" else pr,
                                                 "actions": ["iam:PassRole"] + pairs}
        if "full-admin" in found:
            # NotAction allows (e.g. PowerUserAccess) match the probe but exclude IAM: not full admin.
            if self.allowed(arn, "iam:AttachRolePolicy") and self.allowed(arn, "organizations:LeaveOrganization"):
                found["full-admin"]["actions"] = ["*"]
            else:
                del found["full-admin"]
        return found

    def reach(self, arn: str) -> dict:
        """Classes reachable directly and through up to MAX_HOPS role assumptions."""
        out: Dict[str, dict] = {}
        seen = {arn}
        frontier = [(arn, [])]
        for depth in range(MAX_HOPS + 1):
            nxt = []
            for cur, path in frontier:
                for cls, info in self.direct_classes(cur).items():
                    via = "direct" if not path else "via " + " → ".join(self.principals[r]["name"] for r in path)
                    lvl = info["level"]
                    sev = CLASS_SEV[cls] - (0 if lvl == "full" else 1 if lvl == "conditional" else 2)
                    prev = out.get(cls)
                    if prev is None or sev > prev["severity"] or (sev == prev["severity"] and len(path) < prev["_hops"]):
                        out[cls] = {"class": cls, "severity": sev, "level": lvl, "actions": info["actions"][:6],
                                    "via": via, "impact": CLASS_IMPACT[cls], "_hops": len(path)}
                if depth < MAX_HOPS:
                    for r in self.assumable(cur):
                        if r not in seen:
                            seen.add(r)
                            nxt.append((r, path + [r]))
            frontier = nxt
        classes = sorted(out.values(), key=lambda c: (-c["severity"], c["class"]))
        for c in classes:
            c.pop("_hops", None)
        p = self.principals[arn]
        return {"principal": arn, "name": p["name"], "type": p["type"],
                "max_severity": max((c["severity"] for c in classes), default=0),
                "classes": classes, "assumable_roles": [self.principals[r]["name"] for r in self.assumable(arn)]}

    def find(self, key: str) -> Optional[str]:
        """Resolve a principal by ARN, user/role name, or 'user/NAME' / 'role/NAME'."""
        if key in self.principals:
            return key
        typ, _, name = key.partition("/") if key.startswith(("user/", "role/")) else ("", "", key)
        hits = [a for a, p in self.principals.items() if p["name"] == name and (not typ or p["type"] == typ)]
        return hits[0] if len(hits) == 1 else None


def analyse(data: dict) -> Tuple[List[dict], List[str]]:
    acct = Account(data)
    rows = [acct.reach(a) for a in acct.principals]
    rows.sort(key=lambda r: (-r["max_severity"], -len(r["classes"]), r["name"]))
    return rows, sorted(set(acct.issues))


LIMITS = ("Offline approximation: service control policies, resource policies, session policies and most "
          "condition keys are not in the export and are not evaluated. Conditional allows are marked.")


def principals_text(rows: List[dict], issues: List[str]) -> str:
    from .safe import safe
    out = ["scopewake aws: IAM principals ranked by worst reachable action class", LIMITS, ""]
    if issues:
        out += [f"WARNING {len(issues)} part(s) of the export could not be evaluated:"] + [f"  - {safe(i, 200)}" for i in issues] + [""]
    for i, r in enumerate(rows, 1):
        out.append(f"{i}. {r['type']:<4} {safe(r['name'], 60):<32} worst severity {r['max_severity']:>2}")
        for c in r["classes"][:4]:
            out.append(f"     - {c['class']} ({c['level']}, {c['via']}): {c['impact']}")
    return "\n".join(out)


def parse_mapping(values: List[str]) -> Dict[str, str]:
    """--aws-as PRINCIPAL applies to every agent; --aws-as AGENT=PRINCIPAL to agents whose id or kind starts with AGENT."""
    m: Dict[str, str] = {}
    for v in values or []:
        if "=" in v and not v.startswith("arn:"):
            k, _, p = v.partition("=")
            m[k.strip()] = p.strip()
        else:
            m["*"] = v.strip()
    return m


AWS_CRED_KINDS = {"aws-access-key", "aws-credentials-file"}


def _has_aws(agent) -> bool:
    return any(c.kind in AWS_CRED_KINDS or (c.kind == "ci-secret" and re.search(r"AWS", c.name or "", re.I))
               for c in agent.credentials if not c.mitigated)


def attach(agents, data: dict, mapping: Dict[str, str]) -> List[str]:
    """Add AWS reach to agents that hold AWS credentials. Returns issues to report."""
    from .model import Capability
    acct = Account(data)
    issues: List[str] = []
    for a in agents:
        if not _has_aws(a):
            continue
        key = next((k for k in sorted(mapping, key=len, reverse=True) if k != "*" and (a.id.startswith(k) or a.kind == k)), None)
        target = mapping.get(key) if key else mapping.get("*")
        if not target:
            issues.append(f"{a.name} holds AWS credentials but no IAM principal was mapped (use --aws-as)")
            continue
        arn = acct.find(target)
        if not arn:
            issues.append(f"IAM principal not found or ambiguous in export: {target}")
            continue
        r = acct.reach(arn)
        a.cloud = {"provider": "aws", "principal": r["principal"], "name": r["name"], "type": r["type"],
                   "max_severity": r["max_severity"], "classes": r["classes"]}
        for c in r["classes"]:
            a.capabilities.append(Capability("aws:" + c["class"], c["severity"], False, via=f"iam {r['type']}/{r['name']} ({c['via']})"))
        # The credential's own severity was a guess; the IAM analysis replaces it.
        for c in a.credentials:
            if c.kind in AWS_CRED_KINDS or (c.kind == "ci-secret" and re.search(r"AWS", c.name or "", re.I)):
                c.severity = max(3, r["max_severity"]) if r["classes"] else 3
        a.notes.append(f"AWS reach from IAM export for {r['type']} {r['name']}: worst severity {r['max_severity']} "
                       f"({', '.join(c['class'] for c in r['classes']) or 'no high-impact actions'}). {LIMITS}")
    return sorted(set(issues + acct.issues))
