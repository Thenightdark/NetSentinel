from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from backend.database.base import Base
import backend.models  # noqa: F401 - registers all mapped tables


def test_alembic_builds_the_complete_schema(tmp_path: Path, monkeypatch) -> None:
    database_path = tmp_path / "migration-test.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setenv("DATABASE_URL", database_url)

    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    command.upgrade(config, "head")

    migrated_tables = set(inspect(create_engine(database_url)).get_table_names())
    assert migrated_tables == set(Base.metadata.tables) | {"alembic_version"}

    command.downgrade(config, "base")
    remaining_tables = set(inspect(create_engine(database_url)).get_table_names())
    assert remaining_tables == {"alembic_version"}
