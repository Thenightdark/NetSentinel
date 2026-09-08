from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.database.session import get_db
from backend.schemas import AlertPage
from backend.services.queries import list_alerts

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=AlertPage)
def alerts(
    severity: str | None = None,
    status: str | None = None,
    alert_type: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    database: Session = Depends(get_db),
) -> AlertPage:
    items, total = list_alerts(
        database,
        limit=limit,
        offset=offset,
        severity=severity,
        status=status,
        alert_type=alert_type,
    )
    return AlertPage(items=items, total=total, limit=limit, offset=offset)

