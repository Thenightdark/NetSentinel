# Database migrations

Alembic owns the NetSentinel database schema. Apply all pending migrations with:

```shell
alembic upgrade head
```

The backend container runs this command before starting FastAPI. Application startup never creates or alters tables directly.
