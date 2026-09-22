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
    process_id: int | None = Field(default=None, ge=0)
    process_name: str | None = Field(default=None, max_length=255)
    executable_name: str | None = Field(default=None, max_length=255)
    bytes: int = Field(ge=0)
    packet_count: int = Field(gt=0)
    first_seen: datetime
    last_seen: datetime

    @field_validator("protocol")
    @classmethod
    def normalize_protocol(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not normalized:
            raise ValueError("protocol must contain at least one non-whitespace character")
        return normalized

    @field_validator("process_name", "executable_name")
    @classmethod
    def normalize_optional_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

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
