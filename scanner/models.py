from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    PASS  = "pass"
    WARN  = "warn"
    FAIL  = "fail"
    ERROR = "error"


@dataclass
class CheckResult:
    check_id:     str
    status:       Status
    title:        str
    detail:       str
    remediation:  str
    score_impact: int
    raw:          dict = field(default_factory=dict)
