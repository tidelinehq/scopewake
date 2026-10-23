from dataclasses import dataclass, field, asdict
from typing import List, Optional


@dataclass
class Credential:
    kind: str
    severity: int
    location: str          # file path or "<config>:<server>"
    how: str               # literal-in-config | env-reference | readable-file | secrets-reference
    name: str = ""         # variable / key NAME only, never a value
    mitigated: bool = False
    read_denied: bool = False   # a Read(...) deny rule matches; the shell may still reach the file
    loc_rel: str = ""           # location relative to the scan root, for stable diffs


@dataclass
class Capability:
    name: str
    severity: int
    untrusted_input: bool
    via: str = ""


@dataclass
class Agent:
    id: str
    name: str
    kind: str
    source: str
    autonomy: float = 0.5
    autonomy_note: str = ""
    exposure: float = 0.4
    capabilities: List[Capability] = field(default_factory=list)
    credentials: List[Credential] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    score: int = 0
    chains: List[str] = field(default_factory=list)
    fixes: List[str] = field(default_factory=list)
    source_rel: str = ""
    runs_commands: bool = False            # internal: host runs commands as the user
    deny_rules: List[str] = field(default_factory=list)  # internal: not written to reports
    trifecta: bool = False
    trifecta_parts: dict = field(default_factory=dict)
    cloud: dict = field(default_factory=dict)  # IAM reach when an AWS export is supplied
    servers: List[dict] = field(default_factory=list)  # MCP server fingerprints for change detection (no values)

    def to_dict(self):
        d = asdict(self)
        d.pop("deny_rules", None)
        d.pop("runs_commands", None)
        return d
