from __future__ import annotations

from sqlalchemy import select

from database.db import async_session
from database.models import Log, gen_uuid


class LogService:
    def __init__(self):
        self._sio = None

    def set_sio(self, sio):
        """Set the socket.io server instance for live log emission."""
        self._sio = sio

    async def log(self, source: str, message: str, level: str = "info",
                  session_id: str = None, data: dict = None) -> dict:
        async with async_session() as db:
            entry = Log(
                id=gen_uuid(),
                session_id=session_id,
                level=level,
                source=source,
                message=message,
                data=data or {},
            )
            db.add(entry)
            await db.commit()
            await db.refresh(entry)
            d = self._to_dict(entry)

        # Push to connected clients
        if self._sio:
            try:
                await self._sio.emit("log_entry", d)
            except Exception:
                pass

        return d

    async def get_logs(self, session_id: str = None, level: str = None,
                       source: str = None, limit: int = 100) -> list[dict]:
        async with async_session() as db:
            query = select(Log).order_by(Log.created_at.desc()).limit(limit)
            if session_id:
                query = query.where(Log.session_id == session_id)
            if level:
                query = query.where(Log.level == level)
            if source:
                query = query.where(Log.source == source)
            result = await db.execute(query)
            return [self._to_dict(l) for l in result.scalars().all()]

    def _to_dict(self, log: Log) -> dict:
        return {
            "id": log.id,
            "session_id": log.session_id,
            "level": log.level,
            "source": log.source,
            "message": log.message,
            "data": log.data,
            "created_at": log.created_at.isoformat() if log.created_at else None,
        }


log_service = LogService()
