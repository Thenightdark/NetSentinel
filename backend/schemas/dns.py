from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator


class DNSObservationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    requesting_host: str
    queried_domain: str
    timestamp: datetime
    query_type: str
    response_status: str | None
    is_response: bool


class DNSObservationPage(BaseModel):
    items: list[DNSObservationRead]
    total: int
    limit: int
    offset: int


class TopDomain(BaseModel):
    domain: str
    query_count: int
    unique_clients: int


class DNSIngestItem(BaseModel):
    requesting_host: IPvAnyAddress
    queried_domain: str = Field(min_length=1, max_length=253)
    timestamp: datetime
    query_type: str = Field(min_length=1, max_length=20)
    response_status: str | None = Field(default=None, max_length=30)
    is_response: bool = False

    @field_validator("queried_domain")
    @classmethod
    def normalize_domain(cls, value: str) -> str:
        return value.strip().rstrip(".").lower()

    @field_validator("query_type", "response_status")
    @classmethod
    def normalize_dns_label(cls, value: str | None) -> str | None:
        return value.strip().upper() if value is not None else None


class DNSIngestRequest(BaseModel):
    batch_id: UUID
    observations: Annotated[list[DNSIngestItem], Field(min_length=1, max_length=500)]


class DNSIngestResponse(BaseModel):
    accepted: int
    duplicate: bool = False
