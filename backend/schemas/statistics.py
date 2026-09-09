from datetime import datetime
from typing import Literal

from pydantic import BaseModel

HistoryRange = Literal["5m", "1h", "24h", "7d"]


class HistoricalMetricPoint(BaseModel):
    timestamp: datetime
    bytes_uploaded: int
    bytes_downloaded: int
    flow_count: int
    active_hosts: int
    alerts: int


class HistoricalStatsResponse(BaseModel):
    range: HistoryRange
    bucket_seconds: int
    start: datetime
    end: datetime
    items: list[HistoricalMetricPoint]
