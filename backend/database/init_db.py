from backend import models  # noqa: F401 - registers all mapped tables
from backend.database.base import Base
from sqlalchemy import inspect, text

from backend.database.session import engine


def create_database() -> None:
    Base.metadata.create_all(bind=engine)
    if engine.dialect.name == "sqlite":
        _upgrade_sqlite_host_columns()
        _upgrade_sqlite_alert_columns()


def _upgrade_sqlite_host_columns() -> None:
    """Keep existing development databases usable before migrations are introduced."""
    with engine.begin() as connection:
        columns = {
            column["name"] for column in inspect(connection).get_columns("hosts")
        }
        if "total_bytes" not in columns:
            connection.execute(
                text("ALTER TABLE hosts ADD COLUMN total_bytes BIGINT NOT NULL DEFAULT 0")
            )
        if "total_connections" not in columns:
            connection.execute(
                text(
                    "ALTER TABLE hosts ADD COLUMN total_connections BIGINT NOT NULL DEFAULT 0"
                )
            )


def _upgrade_sqlite_alert_columns() -> None:
    """Add detection evidence to existing early-development databases."""
    with engine.begin() as connection:
        columns = {
            column["name"]
            for column in inspect(connection).get_columns("security_alerts")
        }
        if "evidence" not in columns:
            connection.execute(
                text(
                    "ALTER TABLE security_alerts "
                    "ADD COLUMN evidence JSON NOT NULL DEFAULT '{}'"
                )
            )
