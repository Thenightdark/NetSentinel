from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database.session import get_db
from backend.schemas import DetectionSettingsRead, DetectionSettingsUpdate
from backend.services.detection_settings import (
    get_detection_settings,
    update_detection_settings,
)

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("/detection", response_model=DetectionSettingsRead)
def read_detection_settings(
    database: Session = Depends(get_db),
) -> DetectionSettingsRead:
    return DetectionSettingsRead.model_validate(get_detection_settings(database))


@router.put("/detection", response_model=DetectionSettingsRead)
def replace_detection_settings(
    update: DetectionSettingsUpdate,
    database: Session = Depends(get_db),
) -> DetectionSettingsRead:
    return DetectionSettingsRead.model_validate(
        update_detection_settings(database, update)
    )
