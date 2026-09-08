from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, Field, IPvAnyAddress, field_validator, model_validator


class FlowIngestItem(BaseModel):
    source_ip: IPvAnyAddress
    destination_ip: IPvAnyAddress
    source_port: int | None = Field(default=None, ge=0, le=65_535)
    destination_port: int | None = Field(default=None, ge=0, le=65_535)
    protocol: str = Field(min_length=1, max_length=20)
    bytes: int = Field(ge=0)
    packet_count: int = Field(gt=0)
    first_seen: datetime
    last_seen: datetime

    @field_validator("protocol")
    @classmethod
    def normalize_protocol(cls, value: str) -> str:
        return value.strip().upper()

    @model_validator(mode="after")
    def validate_time_range(self) -> "FlowIngestItem":
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must be on or after first_seen")
        return self


class FlowIngestRequest(BaseModel):
    batch_id: UUID
    flows: Annotated[list[FlowIngestItem], Field(min_length=1, max_length=500)]


class FlowIngestResponse(BaseModel):
    accepted: int
    duplicate: bool = False

