from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class DetectionSettingsUpdate(BaseModel):
    port_scan_unique_ports: int = Field(ge=2, le=65_535)
    port_scan_window_seconds: int = Field(ge=1, le=3_600)
    bandwidth_spike_megabytes: int = Field(ge=1, le=1_000_000)
    bandwidth_spike_window_seconds: int = Field(ge=1, le=86_400)
    connection_spike_connections: int = Field(ge=2, le=1_000_000)
    connection_spike_window_seconds: int = Field(ge=1, le=3_600)


class DetectionSettingsRead(DetectionSettingsUpdate):
    model_config = ConfigDict(from_attributes=True)

    updated_at: datetime
