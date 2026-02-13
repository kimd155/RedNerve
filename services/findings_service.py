"""
Findings Service — The kill chain memory.

Stores structured findings from each agent operation so subsequent
stages can query real data from earlier stages. For example:
  - ReconAgent discovers AD users → stored as category="users"
  - CredentialAgent queries findings(category="users") to get real usernames
  - LateralMovementAgent queries findings(category="credentials") to get real creds
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import aliased

from database.db import async_session
from database.models import Finding, TaskRecord, Beacon, gen_uuid


# Severity mapping for finding categories
CATEGORY_SEVERITY = {
    "credentials": "critical",
    "hashes": "critical",
    "kerberoastable": "critical",
    "domain_admins": "critical",
    "vulnerabilities": "high",
    "escalation_paths": "high",
    "sessions": "high",
    "shares": "medium",
    "services": "medium",
    "users": "info",
    "groups": "info",
    "hosts": "info",
    "computers": "info",
    "network": "info",
    "ports": "low",
    "artifacts": "low",
}


class FindingsService:
    async def store(self, session_id: str, category: str, key: str,
                    data: dict, source_agent: str, task_id: str = None) -> dict:
        """Store a finding from an agent operation."""
        async with async_session() as db:
            finding = Finding(
                id=gen_uuid(),
                session_id=session_id,
                task_id=task_id,
                category=category,
                key=key,
                data=data,
                source_agent=source_agent,
            )
            db.add(finding)
            await db.commit()
            await db.refresh(finding)
            return self._to_dict(finding)

    async def store_many(self, session_id: str, category: str,
                         items: list[dict], source_agent: str,
                         task_id: str = None) -> int:
        """Bulk-store findings. Each item needs 'key' and 'data'."""
        count = 0
        async with async_session() as db:
            for item in items:
                finding = Finding(
                    id=gen_uuid(),
                    session_id=session_id,
                    task_id=task_id,
                    category=category,
                    key=item.get("key", ""),
                    data=item.get("data", item),
                    source_agent=source_agent,
                )
                db.add(finding)
                count += 1
            await db.commit()
        return count

    async def get_by_category(self, session_id: str, category: str) -> list[dict]:
        """Get all findings of a category for a session."""
        async with async_session() as db:
            result = await db.execute(
                select(Finding)
                .where(Finding.session_id == session_id)
                .where(Finding.category == category)
                .order_by(Finding.created_at)
            )
            return [self._to_dict(f) for f in result.scalars().all()]

    async def get_all(self, session_id: str) -> dict[str, list[dict]]:
        """Get all findings for a session, grouped by category."""
        async with async_session() as db:
            result = await db.execute(
                select(Finding)
                .where(Finding.session_id == session_id)
                .order_by(Finding.created_at)
            )
            findings = result.scalars().all()
            grouped: dict[str, list[dict]] = {}
            for f in findings:
                cat = f.category
                if cat not in grouped:
                    grouped[cat] = []
                grouped[cat].append(self._to_dict(f))
            return grouped

    async def get_summary(self, session_id: str) -> dict:
        """Get a summary of findings for context injection into Claude."""
        all_findings = await self.get_all(session_id)
        summary = {}
        for category, items in all_findings.items():
            summary[category] = {
                "count": len(items),
                "keys": [i["key"] for i in items],
                "latest": items[-1]["data"] if items else None,
            }
        return summary

    async def get_context_for_agent(self, session_id: str, agent_name: str) -> dict:
        """
        Get relevant findings context for a specific agent.
        Each agent needs different prior findings.
        """
        context = {}
        all_findings = await self.get_all(session_id)

        # Map of agent → what categories it needs from prior stages
        agent_context_map = {
            "recon": [],  # Recon is typically first
            "credential": ["users", "hosts", "services", "kerberoastable"],
            "execution": ["credentials", "hosts", "beacons"],
            "lateral_movement": ["credentials", "hosts", "beacons", "sessions"],
            "privilege_escalation": ["hosts", "beacons", "credentials", "services"],
            "persistence": ["hosts", "beacons", "credentials"],
            "exfiltration": ["hosts", "beacons", "shares", "files"],
            "intelligence": ["users", "hosts", "credentials", "services", "vulnerabilities", "shares"],
            "cleanup": ["hosts", "beacons", "artifacts"],
            "reporting": ["users", "hosts", "credentials", "vulnerabilities", "services", "shares"],
        }

        needed = agent_context_map.get(agent_name, list(all_findings.keys()))
        for category in needed:
            if category in all_findings:
                context[category] = all_findings[category]

        return context

    async def get_findings_summary_by_beacon(self) -> list[dict]:
        """Get findings grouped by beacon (target machine) with agent sub-groups."""
        async with async_session() as db:
            # Join findings → tasks → beacons to get beacon info
            result = await db.execute(
                select(Finding, TaskRecord.beacon_id)
                .outerjoin(TaskRecord, Finding.task_id == TaskRecord.id)
                .order_by(Finding.created_at.desc())
            )
            rows = result.all()

            # Get all beacon info
            beacon_result = await db.execute(select(Beacon))
            beacons_by_id = {b.id: b for b in beacon_result.scalars().all()}

        beacon_map: dict[str, dict] = {}
        for finding, beacon_id in rows:
            bid = beacon_id or "unknown"
            if bid not in beacon_map:
                b = beacons_by_id.get(bid)
                beacon_map[bid] = {
                    "beacon_id": bid,
                    "hostname": b.hostname if b else "Unknown",
                    "ip_address": b.ip_address if b else "N/A",
                    "os": b.os if b else "N/A",
                    "total": 0,
                    "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                    "agents": {},
                    "findings": [],
                }
            entry = beacon_map[bid]
            entry["total"] += 1
            sev = CATEGORY_SEVERITY.get(finding.category, "info")
            entry["severity_counts"][sev] += 1

            agent = finding.source_agent
            if agent not in entry["agents"]:
                entry["agents"][agent] = {"total": 0, "categories": {}}
            entry["agents"][agent]["total"] += 1
            if finding.category not in entry["agents"][agent]["categories"]:
                entry["agents"][agent]["categories"][finding.category] = 0
            entry["agents"][agent]["categories"][finding.category] += 1

            entry["findings"].append(self._to_dict(finding))

        return list(beacon_map.values())

    async def get_findings_summary_by_agent(self) -> list[dict]:
        """Get findings grouped by source_agent with severity breakdown. Cross-session."""
        async with async_session() as db:
            result = await db.execute(
                select(Finding).order_by(Finding.created_at.desc())
            )
            findings = result.scalars().all()

        agent_map: dict[str, dict] = {}
        for f in findings:
            agent = f.source_agent
            if agent not in agent_map:
                agent_map[agent] = {
                    "agent": agent,
                    "total": 0,
                    "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                    "categories": {},
                    "findings": [],
                }
            entry = agent_map[agent]
            entry["total"] += 1
            sev = CATEGORY_SEVERITY.get(f.category, "info")
            entry["severity_counts"][sev] += 1
            if f.category not in entry["categories"]:
                entry["categories"][f.category] = 0
            entry["categories"][f.category] += 1
            entry["findings"].append(self._to_dict(f))

        return list(agent_map.values())

    async def get_all_findings_flat(self) -> list[dict]:
        """Get all findings across all sessions for report generation."""
        async with async_session() as db:
            result = await db.execute(
                select(Finding).order_by(Finding.created_at)
            )
            return [self._to_dict(f) for f in result.scalars().all()]

    def _to_dict(self, f: Finding) -> dict:
        return {
            "id": f.id,
            "session_id": f.session_id,
            "task_id": f.task_id,
            "category": f.category,
            "key": f.key,
            "data": f.data,
            "source_agent": f.source_agent,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }


findings_service = FindingsService()
