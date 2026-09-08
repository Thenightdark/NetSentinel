from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.database.session import get_db
from backend.schemas import HealthResponse

router = APIRouter(tags=["system"])


@router.get("/health", response_model=HealthResponse)
def health(database: Session = Depends(get_db)) -> HealthResponse:
    database.execute(text("SELECT 1"))
    return HealthResponse(status="ok", service="backend", database="connected")

