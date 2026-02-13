from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, Request, HTTPException, Header
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from typing import Optional

from config import Config
from server.beacon_handler import beacon_handler

ENV_PATH = Path(__file__).parent.parent / ".env"

router = APIRouter()
templates = Jinja2Templates(directory="templates")


# ─── Pages ──────────────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("chat.html", {"request": request, "active_page": "chat"})


@router.get("/targets", response_class=HTMLResponse)
async def targets_page(request: Request):
    return templates.TemplateResponse("targets.html", {"request": request, "active_page": "targets"})


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request, "active_page": "dashboard"})


@router.get("/build", response_class=HTMLResponse)
async def build_page(request: Request):
    return templates.TemplateResponse("build.html", {
        "request": request,
        "active_page": "build",
        "beacon_secret": Config.BEACON_SECRET,
    })


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "active_page": "settings",
    })


# ─── API ────────────────────────────────────────────────────────

@router.get("/api/health")
async def health():
    return {"status": "ok", "service": "rednerve"}


@router.get("/api/beacons")
async def list_beacons():
    beacons = await beacon_handler.list_beacons()
    return {"beacons": beacons}


@router.get("/api/beacons/{beacon_id}")
async def get_beacon(beacon_id: str):
    beacon = await beacon_handler.get_beacon(beacon_id)
    if not beacon:
        raise HTTPException(status_code=404, detail="Beacon not found")
    return beacon


# ─── Beacon Communication ──────────────────────────────────────

def _verify_beacon_secret(x_beacon_secret: Optional[str] = Header(None)):
    if x_beacon_secret != Config.BEACON_SECRET:
        raise HTTPException(status_code=403, detail="Invalid beacon secret")


@router.post("/api/beacon/register")
async def beacon_register(request: Request, x_beacon_secret: Optional[str] = Header(None)):
    _verify_beacon_secret(x_beacon_secret)
    body = await request.json()
    result = await beacon_handler.register_beacon(body)

    from app import sio
    beacon_info = await beacon_handler.get_beacon(result["beacon_id"])
    await sio.emit("beacon_registered", beacon_info)

    return result


@router.post("/api/beacon/{beacon_id}/checkin")
async def beacon_checkin(beacon_id: str, x_beacon_secret: Optional[str] = Header(None)):
    _verify_beacon_secret(x_beacon_secret)
    # Check if beacon still exists (may have been deleted by operator)
    beacon = await beacon_handler.get_beacon(beacon_id)
    if not beacon:
        raise HTTPException(status_code=410, detail="Beacon has been deleted by operator")
    tasks = await beacon_handler.wait_for_tasks(beacon_id, timeout=30)
    return {"beacon_id": beacon_id, "tasks": tasks}


@router.post("/api/beacon/{beacon_id}/result")
async def beacon_result(beacon_id: str, request: Request, x_beacon_secret: Optional[str] = Header(None)):
    _verify_beacon_secret(x_beacon_secret)
    body = await request.json()
    task_id = body.get("task_id", "")
    result = await beacon_handler.submit_result(beacon_id, task_id, body)

    from app import sio
    await sio.emit("task_result", {"beacon_id": beacon_id, "task_id": task_id, "result": body})

    return result


# ─── Implant Builder ───────────────────────────────────────────

@router.post("/api/build")
async def build_implant(request: Request):
    from builder.builder import build_implant as do_build

    body = await request.json()
    try:
        result = do_build(body)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/api/builds")
async def list_builds():
    from builder.builder import list_builds
    return {"builds": list_builds()}


@router.get("/api/build/download/{filename}")
async def download_build(filename: str):
    from builder.builder import get_build_path

    # Sanitize filename to prevent path traversal
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    filepath = get_build_path(filename)
    if not filepath:
        raise HTTPException(status_code=404, detail="Build not found")

    media_type = "application/octet-stream"
    if filename.endswith(".py"):
        media_type = "text/x-python"
    elif filename.endswith(".ps1"):
        media_type = "text/plain"
    elif filename.endswith(".sh"):
        media_type = "text/x-shellscript"

    return FileResponse(filepath, filename=filename, media_type=media_type)


# ─── Reports ──────────────────────────────────────────────────

@router.get("/api/reports")
async def list_reports():
    from services.report_service import report_service
    reports = await report_service.list_reports()
    return {"reports": reports}


@router.get("/api/reports/{report_id}/download")
async def download_report(report_id: str):
    from services.report_service import report_service

    filepath = await report_service.get_report_file_path(report_id)
    if not filepath:
        raise HTTPException(status_code=404, detail="Report not found or not ready")

    filename = Path(filepath).name
    return FileResponse(filepath, filename=filename, media_type="text/html")


# ─── Settings ─────────────────────────────────────────────────

# Settings schema: key -> (label, type, description, default)
SETTINGS_SCHEMA = [
    {"key": "ANTHROPIC_API_KEY", "label": "Anthropic API Key", "type": "password",
     "desc": "Your Claude API key (sk-ant-...)", "default": ""},
    {"key": "ANTHROPIC_MODEL", "label": "AI Model", "type": "select",
     "desc": "Claude model to use for intent parsing",
     "options": ["claude-sonnet-4-5-20250929", "claude-haiku-4-5-20251001", "claude-opus-4-6"],
     "default": "claude-sonnet-4-5-20250929"},
    {"key": "BEACON_SECRET", "label": "Beacon Secret", "type": "password",
     "desc": "Shared secret between server and implants", "default": "rednerve-beacon-key"},
    {"key": "BEACON_CHECKIN_INTERVAL", "label": "Beacon Check-in Interval", "type": "number",
     "desc": "Default beacon check-in interval in seconds", "default": "5"},
    {"key": "BEACON_TASK_TIMEOUT", "label": "Beacon Task Timeout", "type": "number",
     "desc": "Max seconds to wait for beacon task result", "default": "300"},
    {"key": "HOST", "label": "Server Host", "type": "text",
     "desc": "Bind address for the server", "default": "0.0.0.0"},
    {"key": "PORT", "label": "Server Port", "type": "number",
     "desc": "Port the server listens on", "default": "9999"},
    {"key": "DATABASE_URL", "label": "Database URL", "type": "text",
     "desc": "SQLAlchemy database connection string", "default": "sqlite+aiosqlite:///rednerve.db"},
    {"key": "SECRET_KEY", "label": "App Secret Key", "type": "password",
     "desc": "Internal secret key for the application", "default": "rednerve-dev-key-change-in-prod"},
]


def _read_env() -> dict:
    """Read current .env file into a dict."""
    values = {}
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                values[k.strip()] = v.strip()
    return values


def _write_env(values: dict):
    """Write values to .env file, preserving comments."""
    lines = []
    existing_keys = set()

    # Preserve existing comments and update values
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text().splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                lines.append(line)
                continue
            if "=" in stripped:
                k = stripped.split("=", 1)[0].strip()
                existing_keys.add(k)
                if k in values:
                    lines.append(k + "=" + values[k])
                else:
                    lines.append(line)
            else:
                lines.append(line)

    # Add new keys that weren't in the file
    for k, v in values.items():
        if k not in existing_keys:
            lines.append(k + "=" + v)

    ENV_PATH.write_text("\n".join(lines) + "\n")


@router.get("/api/settings")
async def get_settings():
    env_values = _read_env()
    settings = []
    for s in SETTINGS_SCHEMA:
        val = env_values.get(s["key"], s["default"])
        entry = {**s, "value": val}
        # Mask passwords — show last 4 chars only
        if s["type"] == "password" and val and len(val) > 4:
            entry["masked"] = "*" * (len(val) - 4) + val[-4:]
        settings.append(entry)
    return {"settings": settings}


@router.post("/api/settings")
async def save_settings(request: Request):
    body = await request.json()
    updates = body.get("settings", {})

    # Validate keys — only allow known settings
    valid_keys = {s["key"] for s in SETTINGS_SCHEMA}
    filtered = {}
    for k, v in updates.items():
        if k in valid_keys:
            filtered[k] = str(v)

    if not filtered:
        raise HTTPException(status_code=400, detail="No valid settings provided")

    # Read existing, merge, write
    current = _read_env()
    current.update(filtered)
    _write_env(current)

    # Reload Config values in memory
    for k, v in filtered.items():
        os.environ[k] = v
        if hasattr(Config, k):
            # Cast ints
            if k in ("PORT", "BEACON_CHECKIN_INTERVAL", "BEACON_TASK_TIMEOUT"):
                try:
                    setattr(Config, k, int(v))
                except ValueError:
                    pass
            else:
                setattr(Config, k, v)

    # Reset the intent parser client so it picks up new key/model
    try:
        from orchestrator.intent_parser import intent_parser
        intent_parser.client = None
    except Exception:
        pass

    return {"status": "saved", "updated": list(filtered.keys())}
