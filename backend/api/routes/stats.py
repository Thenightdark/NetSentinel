from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database.session import get_db
from backend.schemas import StatsSummary
from backend.services.queries import get_stats_summary

router = APIRouter(prefix="/stats", tags=["statistics"])


@router.get("/summary", response_model=StatsSummary)
def summary(database: Session = Depends(get_db)) -> StatsSummary:
    return StatsSummary.model_validate(get_stats_summary(database))

