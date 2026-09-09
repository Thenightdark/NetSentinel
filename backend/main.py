from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.router import api_router
from backend.config import get_settings
from backend.database.session import SessionLocal
from backend.services.auth import bootstrap_initial_admin
from backend.websocket.routes import router as websocket_router
from backend.websocket.manager import live_manager

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.initial_admin_username is not None or settings.initial_admin_password is not None:
        with SessionLocal() as database:
            bootstrap_initial_admin(database)
    yield
    await live_manager.close()


app = FastAPI(
    title=settings.app_name,
    description="Defensive network observability API for NetSentinel.",
    version="0.2.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["*"],
)
app.include_router(api_router)
app.include_router(websocket_router)


@app.get("/", tags=["system"])
def root() -> dict[str, str]:
    return {"name": settings.app_name, "health": "/api/health", "docs": "/docs"}
