from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class AlertCandidate:
    timestamp: datetime
    detection_name: str
    source_ip: str | None
    destination_ip: str | None
    description: str
    evidence: dict[str, object]
