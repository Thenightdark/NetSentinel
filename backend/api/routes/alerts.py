from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.database.session import get_db
from backend.models import SecurityAlert
from backend.schemas import AlertPage, AlertStatusUpdate, SecurityAlertRead, SecurityEventDetail
from backend.services.queries import list_alerts
from backend.services.security_events import get_security_event_detail

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=AlertPage)
def alerts(
    severity: str | None = None,
    alert_status: str | None = Query(None, alias="status"),
    alert_type: str | None = None,
    agent_id: str | None = None,
    host: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    database: Session = Depends(get_db),
) -> AlertPage:
    if date_from and date_to and date_from > date_to:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="date_from must be before date_to",
        )
    items, total = list_alerts(
        database,
        limit=limit,
        offset=offset,
        severity=severity,
        status=alert_status,
        alert_type=alert_type,
        agent_id=agent_id,
        host_ip=host,
        date_from=date_from,
        date_to=date_to,
    )
    return AlertPage(items=items, total=total, limit=limit, offset=offset)


@router.get("/{alert_id}", response_model=SecurityEventDetail)
def alert_detail(
    alert_id: int,
    database: Session = Depends(get_db),
) -> SecurityEventDetail:
    alert = database.get(SecurityAlert, alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security event not found",
        )
    return get_security_event_detail(database, alert)


@router.patch("/{alert_id}/status", response_model=SecurityAlertRead)
def update_alert_status(
    alert_id: int,
    update: AlertStatusUpdate,
    database: Session = Depends(get_db),
) -> SecurityAlert:
    alert = database.get(SecurityAlert, alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security alert not found",
        )
    alert.status = update.status.value
    database.commit()
    database.refresh(alert)
    return alert
