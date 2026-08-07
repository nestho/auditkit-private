from dataclasses import dataclass, field, asdict
from typing import Dict, List


@dataclass
class ScanTarget:
    value: str
    target_type: str = "domain"


@dataclass
class Finding:
    id: str
    category: str
    severity: str
    title: str
    detail: str
    evidence: Dict = field(default_factory=dict)
    recommendation: str = ""
    impact: str = ""
    likelihood: str = ""
    score: float = 0.0


@dataclass
class ScanResult:
    target: ScanTarget
    started_at: str
    finished_at: str = ""
    facts: Dict = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)
