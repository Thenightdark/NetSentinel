from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database.session import get_db
from backend.schemas import HistoricalStatsResponse, HistoryRange, StatsSummary
from backend.services.queries import get_stats_summary
from backend.services.statistics import get_historical_statistics

router = APIRouter(prefix="/stats", tags=["statistics"])


@router.get("/summary", response_model=StatsSummary)
def summary(database: Session = Depends(get_db)) -> StatsSummary:
    return StatsSummary.model_validate(get_stats_summary(database))


@router.get("/history", response_model=HistoricalStatsResponse)
def history(
    range: HistoryRange = "1h",
    database: Session = Depends(get_db),
) -> HistoricalStatsResponse:
    return get_historical_statistics(database, range)
