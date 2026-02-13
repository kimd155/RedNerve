import socketio
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager

from config import Config
from database.db import init_db


# Socket.IO server (async mode)
sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()

    # Auto-discover and register agents
    from agents.registry import auto_discover
    auto_discover()

    # Give log_service access to sio for live log emission
    from services.log_service import log_service
    log_service.set_sio(sio)

    yield
    # Shutdown (cleanup if needed)


def create_app() -> FastAPI:
    app = FastAPI(title="RedNerve", lifespan=lifespan)

    # Static files
    app.mount("/static", StaticFiles(directory="static"), name="static")

    # Register REST routes
    from api.routes import router as api_router
    app.include_router(api_router)

    # Register Socket.IO events
    from api.socket_events import register_events
    register_events(sio)

    # Wrap FastAPI with Socket.IO ASGI app
    sio_app = socketio.ASGIApp(sio, other_asgi_app=app)

    return sio_app, app


# Create instances
asgi_app, fastapi_app = create_app()
templates = Jinja2Templates(directory="templates")
