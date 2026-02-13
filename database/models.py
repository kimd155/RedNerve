import uuid
from datetime import datetime, timezone

from sqlalchemy import String, Integer, Text, DateTime, JSON, ForeignKey, Index, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.db import Base


def gen_uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    beacon_id: Mapped[str] = mapped_column(String(36), nullable=True)  # NULL = general chat
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    status: Mapped[str] = mapped_column(String(20), default="active")
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)

    messages: Mapped[list["Message"]] = relationship(back_populates="session")
    tasks: Mapped[list["TaskRecord"]] = relationship(back_populates="session")
    logs: Mapped[list["Log"]] = relationship(back_populates="session")


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"))
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    session: Mapped["Session"] = relationship(back_populates="messages")

    __table_args__ = (
        Index("ix_messages_session_sequence", "session_id", "sequence"),
    )


class Beacon(Base):
    __tablename__ = "beacons"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    os: Mapped[str] = mapped_column(String(100), default="Unknown")
    username: Mapped[str] = mapped_column(String(255), default="")
    domain: Mapped[str] = mapped_column(String(255), default="")
    pid: Mapped[int] = mapped_column(Integer, default=0)
    process_name: Mapped[str] = mapped_column(String(255), default="")
    integrity: Mapped[str] = mapped_column(String(50), default="medium")  # low/medium/high/system
    status: Mapped[str] = mapped_column(String(20), default="active")  # active / dormant / dead
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    registered_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    os: Mapped[str] = mapped_column(String(100), default="Unknown")
    status: Mapped[str] = mapped_column(String(20), default="pending")
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class TaskRecord(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"))
    beacon_id: Mapped[str] = mapped_column(String(36), nullable=True)
    agent_name: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="queued")
    priority: Mapped[int] = mapped_column(Integer, default=5)
    result: Mapped[dict] = mapped_column(JSON, nullable=True)
    error: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    session: Mapped["Session"] = relationship(back_populates="tasks")


class Log(Base):
    __tablename__ = "logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), nullable=True)
    level: Mapped[str] = mapped_column(String(10), default="info")
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    session: Mapped["Session"] = relationship(back_populates="logs")


# Stores findings from agent operations — the chain memory
class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"))
    task_id: Mapped[str] = mapped_column(String(36), nullable=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False)  # users, hosts, credentials, shares, services, vulnerabilities, etc.
    key: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g. "jsmith", "10.0.1.5", "NTLM:admin"
    data: Mapped[dict] = mapped_column(JSON, default=dict)  # full structured finding data
    source_agent: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (
        Index("ix_findings_session_category", "session_id", "category"),
    )


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    session_id: Mapped[str] = mapped_column(String(36), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="processing")  # processing / ready / failed
    title: Mapped[str] = mapped_column(String(255), default="RedNerve Assessment Report")
    file_path: Mapped[str] = mapped_column(String(500), nullable=True)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
