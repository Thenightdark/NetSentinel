# Dashboard authentication

NetSentinel uses two deliberately separate authentication mechanisms:

- Human dashboard users sign in with a username and password. Passwords are stored only as Argon2 hashes produced by `pwdlib`. Successful login creates an expiring JWT in an HTTP-only, same-site cookie and a corresponding database session. Logout revokes that database session.
- The passive collector continues to use only its `X-API-Key` ingestion credential. A dashboard session cannot authenticate an ingestion request, and a collector API key cannot access dashboard data.

## Initial administrator

Set `NETSENTINEL_ADMIN_USERNAME` and `NETSENTINEL_ADMIN_PASSWORD` before the first backend start. If the username does not exist, the backend creates it after Alembic has prepared the schema. Later restarts do not overwrite its password.

The `users` table includes an active flag and role, and sessions reference a user ID. This supports multiple users and future role-based authorization without changing password storage or the session format. No public user-registration endpoint is exposed in this version. Dashboard page requests are validated against `/api/auth/me` by the Next.js server before protected content is rendered; API and WebSocket access independently repeat the authorization check.

## Secrets and cookies

Generate different values for `NETSENTINEL_AUTH_SECRET` and `NETSENTINEL_API_KEY`:

```shell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

The values in `.env.example` are public development placeholders. Never use them for a shared deployment or commit a populated `.env` file. Set `NETSENTINEL_AUTH_COOKIE_SECURE=true` when the dashboard and API are served over HTTPS. The default `false` is only for local HTTP development.

Session duration is configured with `NETSENTINEL_AUTH_SESSION_MINUTES`. Disabling a user or revoking a session immediately prevents subsequent API and WebSocket authentication even if the signed token has not expired.
