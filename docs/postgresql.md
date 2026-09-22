# PostgreSQL and schema migrations

PostgreSQL is NetSentinel's application database. SQLAlchemy remains the data-access layer and Alembic is the only mechanism that creates or changes the schema.

## Development configuration

Copy `.env.example` to `.env`, then replace `POSTGRES_PASSWORD` and `NETSENTINEL_AGENT_ENROLLMENT_KEY`. The checked-in values are visible development placeholders, not credentials suitable for a shared or internet-accessible environment.

Docker Compose builds the SQLAlchemy connection URL from `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD`. When FastAPI runs directly on the host, it uses `DATABASE_URL` instead.

## Migration workflow

Apply pending migrations before starting a locally run API:

```shell
alembic upgrade head
uvicorn backend.main:app --reload --port 8000
```

The backend container automatically runs `alembic upgrade head` after PostgreSQL becomes healthy and before it starts FastAPI.

After changing a SQLAlchemy model, create and review a migration:

```shell
alembic revision --autogenerate -m "describe the schema change"
alembic upgrade head
```

Migration files are reviewed and committed; populated `.env` files and database backups are not.

## Existing SQLite development data

The baseline migration creates a fresh PostgreSQL schema. It does not silently import an existing `netsentinel.db` file. Preserve that file until any data you care about has been exported and deliberately migrated. SQLite remains useful for isolated automated tests, but it is no longer the application storage default.
