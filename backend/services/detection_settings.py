from datetime import datetime, timezone

from sqlalchemy.orm import Session

from backend.models import DetectionSettings
from backend.schemas import DetectionSettingsUpdate


def get_detection_settings(database: Session) -> DetectionSettings:
    settings = database.get(DetectionSettings, 1)
    if settings is None:
        settings = DetectionSettings(id=1)
        database.add(settings)
        database.commit()
        database.refresh(settings)
    return settings


def update_detection_settings(
    database: Session, update: DetectionSettingsUpdate
) -> DetectionSettings:
    settings = get_detection_settings(database)
    for field, value in update.model_dump().items():
        setattr(settings, field, value)
    settings.updated_at = datetime.now(timezone.utc)
    database.commit()
    database.refresh(settings)
    return settings
