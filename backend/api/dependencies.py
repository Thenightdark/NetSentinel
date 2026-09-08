import secrets

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from backend.config import get_settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_ingest_api_key(supplied_key: str | None = Security(api_key_header)) -> None:
    configured_secret = get_settings().ingest_api_key
    if configured_secret is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Flow ingestion is not configured",
        )
    configured_key = configured_secret.get_secret_value()
    if supplied_key is None or not secrets.compare_digest(supplied_key, configured_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )

