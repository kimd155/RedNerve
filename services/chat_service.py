from __future__ import annotations

from sqlalchemy import select, func

from database.db import async_session
from database.models import Message, gen_uuid


class ChatService:
    async def add_message(self, session_id: str, role: str, content: str,
                          metadata: dict = None) -> dict:
        async with async_session() as db:
            # Get next sequence number for this session
            result = await db.execute(
                select(func.coalesce(func.max(Message.sequence), 0))
                .where(Message.session_id == session_id)
            )
            next_seq = result.scalar() + 1

            msg = Message(
                id=gen_uuid(),
                session_id=session_id,
                sequence=next_seq,
                role=role,
                content=content,
                metadata_=metadata or {},
            )
            db.add(msg)
            await db.commit()
            await db.refresh(msg)
            return self._to_dict(msg)

    async def get_messages(self, session_id: str, since_sequence: int = 0,
                           limit: int = 200) -> list[dict]:
        async with async_session() as db:
            result = await db.execute(
                select(Message)
                .where(Message.session_id == session_id)
                .where(Message.sequence > since_sequence)
                .order_by(Message.sequence)
                .limit(limit)
            )
            messages = result.scalars().all()
            return [self._to_dict(m) for m in messages]

    async def get_conversation_context(self, session_id: str, max_messages: int = 50) -> list[dict]:
        """Get recent messages formatted for Claude API context."""
        async with async_session() as db:
            result = await db.execute(
                select(Message)
                .where(Message.session_id == session_id)
                .order_by(Message.sequence.desc())
                .limit(max_messages)
            )
            messages = list(reversed(result.scalars().all()))
            return [{"role": m.role, "content": m.content} for m in messages
                    if m.role in ("user", "assistant")]

    def _to_dict(self, msg: Message) -> dict:
        return {
            "id": msg.id,
            "session_id": msg.session_id,
            "sequence": msg.sequence,
            "role": msg.role,
            "content": msg.content,
            "metadata": msg.metadata_,
            "created_at": msg.created_at.isoformat() if msg.created_at else None,
        }


chat_service = ChatService()
