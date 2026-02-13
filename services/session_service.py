from __future__ import annotations

from sqlalchemy import select, func, desc

from database.db import async_session
from database.models import Session, Message, TaskRecord, Log, Finding, gen_uuid, utcnow


class SessionService:
    async def get_or_create_session(self, session_id: str = None,
                                    beacon_id: str = None) -> dict:
        async with async_session() as db:
            if session_id:
                session = await db.get(Session, session_id)
                if session:
                    return self._to_dict(session)

            # If beacon_id given, find existing session for that beacon
            if beacon_id:
                result = await db.execute(
                    select(Session)
                    .where(Session.beacon_id == beacon_id)
                    .where(Session.status == "active")
                    .order_by(desc(Session.updated_at))
                    .limit(1)
                )
                existing = result.scalars().first()
                if existing:
                    return self._to_dict(existing)

            # Create new session
            session = Session(id=gen_uuid(), beacon_id=beacon_id)
            db.add(session)
            await db.commit()
            await db.refresh(session)
            return self._to_dict(session)

    async def get_session(self, session_id: str) -> dict | None:
        async with async_session() as db:
            session = await db.get(Session, session_id)
            if not session:
                return None
            return self._to_dict(session)

    async def get_latest_active_session(self) -> dict | None:
        """Get the most recent general (non-beacon) session that has messages."""
        async with async_session() as db:
            result = await db.execute(
                select(Session)
                .where(Session.status == "active")
                .where(Session.beacon_id.is_(None))
                .where(
                    Session.id.in_(
                        select(Message.session_id).distinct()
                    )
                )
                .order_by(desc(Session.updated_at))
                .limit(1)
            )
            session = result.scalars().first()
            if session:
                return self._to_dict(session)
            return None

    async def list_sessions(self) -> list:
        """List sessions that have at least one message."""
        async with async_session() as db:
            sessions_with_msgs = select(Message.session_id).distinct().subquery()
            result = await db.execute(
                select(Session)
                .where(Session.id.in_(select(sessions_with_msgs.c.session_id)))
                .order_by(desc(Session.updated_at))
            )
            sessions = result.scalars().all()

            out = []
            for s in sessions:
                count_result = await db.execute(
                    select(func.count(Message.id)).where(Message.session_id == s.id)
                )
                msg_count = count_result.scalar() or 0

                preview_result = await db.execute(
                    select(Message.content)
                    .where(Message.session_id == s.id)
                    .where(Message.role == "user")
                    .order_by(Message.sequence)
                    .limit(1)
                )
                preview = preview_result.scalar() or ""
                if len(preview) > 60:
                    preview = preview[:60] + "..."

                out.append({
                    "id": s.id,
                    "beacon_id": s.beacon_id,
                    "status": s.status,
                    "created_at": s.created_at.isoformat() if s.created_at else None,
                    "updated_at": s.updated_at.isoformat() if s.updated_at else None,
                    "message_count": msg_count,
                    "preview": preview,
                })
            return out

    async def close_session(self, session_id: str) -> dict:
        async with async_session() as db:
            session = await db.get(Session, session_id)
            if session:
                session.status = "closed"
                session.updated_at = utcnow()
                await db.commit()
                return self._to_dict(session)
            return {"error": "not found"}

    async def delete_session(self, session_id: str) -> dict:
        async with async_session() as db:
            # Delete all related records first (FK constraints)
            for model in (Message, TaskRecord, Log, Finding):
                rows = (await db.execute(
                    select(model).where(model.session_id == session_id)
                )).scalars().all()
                for r in rows:
                    await db.delete(r)

            session = await db.get(Session, session_id)
            if session:
                await db.delete(session)
                await db.commit()
                return {"deleted": True}
            await db.commit()
            return {"error": "not found"}

    def _to_dict(self, session: Session) -> dict:
        return {
            "id": session.id,
            "beacon_id": session.beacon_id,
            "status": session.status,
            "created_at": session.created_at.isoformat() if session.created_at else None,
            "updated_at": session.updated_at.isoformat() if session.updated_at else None,
        }


session_service = SessionService()
