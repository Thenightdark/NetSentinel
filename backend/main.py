from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.router import api_router
from backend.config import get_settings
from backend.database.init_db import create_database
from backend.websocket.routes import router as websocket_router
from backend.websocket.manager import live_manager

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    create_database()
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
    allow_methods=["GET"],
    allow_headers=["*"],
)
app.include_router(api_router)
app.include_router(websocket_router)


@app.get("/", tags=["system"])
def root() -> dict[str, str]:
    return {"name": settings.app_name, "health": "/api/health", "docs": "/docs"}
