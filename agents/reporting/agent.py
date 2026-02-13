"""
ReportingAgent -- Penetration testing report generation from real findings.

Like IntelligenceAgent, ReportingAgent does NOT send commands to beacons.
It reads all findings stored by prior kill-chain stages via findings_service
and generates structured penetration testing reports, exports data in
various formats, and computes engagement statistics.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import Any

from agents.base import AbstractAgent
from orchestrator.task import Task, TaskResult
from services.findings_service import findings_service

logger = logging.getLogger(__name__)

# Severity classification for different finding categories
CATEGORY_SEVERITY = {
    "credentials": "critical",
    "hashes": "critical",
    "kerberoastable": "high",
    "exfiltrated": "critical",
    "persistence_mechanisms": "high",
    "privilege_escalations": "high",
    "lateral_moves": "high",
    "users": "medium",
    "hosts": "medium",
    "shares": "medium",
    "services": "low",
    "groups": "low",
    "network": "info",
    "cleanup_actions": "info",
    "staged_files": "medium",
    "files": "medium",
    "archives": "medium",
    "sessions": "medium",
    "beacons": "medium",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class ReportingAgent(AbstractAgent):
    name = "reporting"
    description = (
        "Generates structured penetration testing reports from real session "
        "findings — executive summaries, technical details, and remediation "
        "recommendations"
    )
    capabilities = [
        "generate_report",
        "export_findings",
        "get_statistics",
    ]

    # ------------------------------------------------------------------
    # execute()
    # ------------------------------------------------------------------

    async def execute(self, task: Task) -> TaskResult:
        action = task.action
        params = task.params

        if action not in self.capabilities:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": f"Unknown action: {action}"},
                summary=f"Reporting agent does not support action '{action}'",
            )

        session_id = params.get("session_id", task.session_id)
        if not session_id:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "Missing required parameter: session_id"},
                summary="Report generation failed: no session_id provided",
            )

        try:
            handler = getattr(self, f"_handle_{action}")
            return await handler(task, session_id, params)
        except Exception as exc:
            logger.exception("Reporting %s failed for session %s", action, session_id)
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": str(exc)},
                summary=f"Reporting {action} failed: {exc}",
            )

    # ==================================================================
    #  Generate report
    # ==================================================================

    async def _handle_generate_report(
        self, task: Task, session_id: str, params: dict
    ) -> TaskResult:
        report_type: str = params.get("report_type", "executive")
        all_findings = await findings_service.get_all(session_id)

        if not all_findings:
            return TaskResult(
                task_id=task.id,
                status="partial",
                data={
                    "findings": {},
                    "report": {"status": "no_data"},
                },
                summary="Report generation: no findings available for this session",
            )

        report = self._build_report(session_id, all_findings, report_type)

        total_findings = sum(len(v) for v in all_findings.values())
        severity_counts = report.get("severity_breakdown", {})

        summary_parts = [
            f"Generated {report_type} report for session {session_id[:8]}...: "
            f"{total_findings} findings across {len(all_findings)} categories"
        ]
        if severity_counts:
            sev_str = ", ".join(
                f"{count} {sev}" for sev, count in severity_counts.items()
            )
            summary_parts.append(f" [{sev_str}]")

        return TaskResult(
            task_id=task.id,
            status="success",
            data={
                "findings": {
                    "reports": [
                        {
                            "key": f"report_{report_type}",
                            "type": report_type,
                            "session_id": session_id,
                            "generated_at": datetime.now(timezone.utc).isoformat(),
                            "data": report,
                        }
                    ]
                },
                "report": report,
            },
            summary="".join(summary_parts),
        )

    # ==================================================================
    #  Export findings
    # ==================================================================

    async def _handle_export_findings(
        self, task: Task, session_id: str, params: dict
    ) -> TaskResult:
        export_format: str = params.get("format", "json")
        all_findings = await findings_service.get_all(session_id)

        if not all_findings:
            return TaskResult(
                task_id=task.id,
                status="partial",
                data={"findings": {}, "export": {"status": "no_data"}},
                summary="Export: no findings available for this session",
            )

        total_count = sum(len(v) for v in all_findings.values())

        if export_format == "json":
            exported = self._export_json(all_findings, session_id)
        elif export_format == "csv":
            exported = self._export_csv(all_findings)
        elif export_format == "markdown":
            exported = self._export_markdown(all_findings, session_id)
        else:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": f"Unsupported export format: {export_format}"},
                summary=f"Export failed: unsupported format '{export_format}'",
            )

        return TaskResult(
            task_id=task.id,
            status="success",
            data={
                "findings": {
                    "exports": [
                        {
                            "key": f"export_{export_format}",
                            "format": export_format,
                            "session_id": session_id,
                            "finding_count": total_count,
                            "data": exported,
                        }
                    ]
                },
                "export": {
                    "format": export_format,
                    "finding_count": total_count,
                    "content": exported,
                },
            },
            summary=(
                f"Exported {total_count} findings in {export_format} format "
                f"for session {session_id[:8]}..."
            ),
        )

    # ==================================================================
    #  Get statistics
    # ==================================================================

    async def _handle_get_statistics(
        self, task: Task, session_id: str, params: dict
    ) -> TaskResult:
        all_findings = await findings_service.get_all(session_id)
        stats = self._build_statistics(all_findings, session_id)

        return TaskResult(
            task_id=task.id,
            status="success",
            data={
                "findings": {
                    "statistics": [
                        {
                            "key": "session_statistics",
                            "session_id": session_id,
                            "generated_at": datetime.now(timezone.utc).isoformat(),
                            "data": stats,
                        }
                    ]
                },
                "statistics": stats,
            },
            summary=(
                f"Session statistics for {session_id[:8]}...: "
                f"{stats['total_findings']} total findings, "
                f"{stats['categories_count']} categories, "
                f"{stats['severity_breakdown'].get('critical', 0)} critical, "
                f"{stats['severity_breakdown'].get('high', 0)} high"
            ),
        )

    # ==================================================================
    #  Report builder
    # ==================================================================

    def _build_report(
        self, session_id: str, all_findings: dict[str, list[dict]],
        report_type: str,
    ) -> dict:
        """Build a structured penetration testing report."""
        total_findings = sum(len(v) for v in all_findings.values())

        # Severity breakdown
        severity_breakdown: dict[str, int] = {}
        for category, items in all_findings.items():
            sev = CATEGORY_SEVERITY.get(category, "info")
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + len(items)

        # Executive summary
        executive_summary = self._build_executive_summary(
            all_findings, severity_breakdown
        )

        report: dict[str, Any] = {
            "report_type": report_type,
            "session_id": session_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings_count": total_findings,
            "severity_breakdown": severity_breakdown,
            "executive_summary": executive_summary,
        }

        # For technical and full reports, include detailed findings
        if report_type in ("technical", "full"):
            report["detailed_findings"] = self._build_detailed_findings(
                all_findings
            )

        # For full reports, add remediation roadmap
        if report_type == "full":
            report["remediation_roadmap"] = self._build_remediation_roadmap(
                all_findings
            )

        return report

    def _build_executive_summary(
        self, all_findings: dict[str, list[dict]],
        severity_breakdown: dict[str, int],
    ) -> dict:
        """Build executive-level summary."""
        # Overall risk assessment
        critical_count = severity_breakdown.get("critical", 0)
        high_count = severity_breakdown.get("high", 0)

        if critical_count > 0:
            overall_risk = "Critical"
            risk_score = min(10, 7 + critical_count)
        elif high_count > 0:
            overall_risk = "High"
            risk_score = min(8, 4 + high_count)
        else:
            overall_risk = "Medium"
            risk_score = 3

        # Key outcomes
        key_outcomes: list[str] = []
        if "credentials" in all_findings:
            count = len(all_findings["credentials"])
            key_outcomes.append(
                f"Compromised {count} credential(s) through various attack vectors"
            )
        if "hosts" in all_findings:
            count = len(all_findings["hosts"])
            key_outcomes.append(
                f"Discovered and enumerated {count} host(s) in the domain"
            )
        if "exfiltrated" in all_findings:
            count = len(all_findings["exfiltrated"])
            key_outcomes.append(
                f"Successfully exfiltrated {count} file(s) containing sensitive data"
            )
        if "persistence_mechanisms" in all_findings:
            count = len(all_findings["persistence_mechanisms"])
            key_outcomes.append(
                f"Established {count} persistence mechanism(s) for maintained access"
            )
        if "lateral_moves" in all_findings:
            count = len(all_findings["lateral_moves"])
            key_outcomes.append(
                f"Performed {count} lateral movement(s) across the network"
            )
        if "kerberoastable" in all_findings:
            count = len(all_findings["kerberoastable"])
            key_outcomes.append(
                f"Identified {count} Kerberoastable service account(s)"
            )

        return {
            "overall_risk_rating": overall_risk,
            "overall_risk_score": risk_score,
            "total_categories": len(all_findings),
            "key_outcomes": key_outcomes,
            "critical_findings": critical_count,
            "high_findings": high_count,
        }

    def _build_detailed_findings(
        self, all_findings: dict[str, list[dict]]
    ) -> list[dict]:
        """Build detailed finding entries sorted by severity."""
        detailed: list[dict] = []

        for category, items in all_findings.items():
            severity = CATEGORY_SEVERITY.get(category, "info")
            detailed.append({
                "category": category,
                "severity": severity,
                "count": len(items),
                "items": [
                    {
                        "key": item.get("key", ""),
                        "data": item.get("data", {}),
                        "source_agent": item.get("source_agent", "unknown"),
                        "timestamp": item.get("created_at", ""),
                    }
                    for item in items
                ],
            })

        # Sort by severity
        detailed.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
        return detailed

    def _build_remediation_roadmap(
        self, all_findings: dict[str, list[dict]]
    ) -> list[dict]:
        """Build a prioritized remediation roadmap."""
        roadmap: list[dict] = []

        if "credentials" in all_findings:
            roadmap.append({
                "priority": 1,
                "phase": "immediate",
                "action": "Reset compromised credentials",
                "detail": (
                    f"Immediately reset passwords for {len(all_findings['credentials'])} "
                    f"compromised account(s). Enforce MFA across all accounts."
                ),
                "effort": "low",
                "impact": "critical",
            })

        if "kerberoastable" in all_findings:
            roadmap.append({
                "priority": 2,
                "phase": "immediate",
                "action": "Secure service accounts",
                "detail": (
                    f"Rotate passwords for {len(all_findings['kerberoastable'])} "
                    f"Kerberoastable service account(s). Use Group Managed Service "
                    f"Accounts (gMSA) where possible. Set minimum 25-character "
                    f"randomized passwords."
                ),
                "effort": "medium",
                "impact": "high",
            })

        if "persistence_mechanisms" in all_findings:
            roadmap.append({
                "priority": 1,
                "phase": "immediate",
                "action": "Remove persistence mechanisms",
                "detail": (
                    f"Remove all {len(all_findings['persistence_mechanisms'])} "
                    f"persistence mechanism(s) identified during the engagement."
                ),
                "effort": "low",
                "impact": "critical",
            })

        if "shares" in all_findings:
            roadmap.append({
                "priority": 3,
                "phase": "short_term",
                "action": "Review network share permissions",
                "detail": (
                    f"Audit permissions on {len(all_findings['shares'])} "
                    f"discovered share(s). Remove anonymous access, apply "
                    f"least-privilege principles."
                ),
                "effort": "medium",
                "impact": "medium",
            })

        if "hosts" in all_findings:
            roadmap.append({
                "priority": 4,
                "phase": "short_term",
                "action": "Improve network segmentation",
                "detail": (
                    "Implement network segmentation to limit lateral movement. "
                    "Restrict workstation-to-workstation communication. "
                    "Use jump servers for administrative access."
                ),
                "effort": "high",
                "impact": "high",
            })

        roadmap.append({
            "priority": 5,
            "phase": "long_term",
            "action": "Deploy endpoint detection and response (EDR)",
            "detail": (
                "Deploy and tune EDR across all endpoints to detect and "
                "prevent credential dumping, lateral movement, and "
                "persistence techniques."
            ),
            "effort": "high",
            "impact": "high",
        })

        roadmap.sort(key=lambda x: x["priority"])
        return roadmap

    # ==================================================================
    #  Export helpers
    # ==================================================================

    def _export_json(
        self, all_findings: dict[str, list[dict]], session_id: str
    ) -> str:
        """Export findings as formatted JSON."""
        export_data = {
            "session_id": session_id,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": sum(len(v) for v in all_findings.values()),
            "categories": {},
        }

        for category, items in all_findings.items():
            export_data["categories"][category] = {
                "severity": CATEGORY_SEVERITY.get(category, "info"),
                "count": len(items),
                "items": [
                    {
                        "key": item.get("key", ""),
                        "data": item.get("data", {}),
                        "source": item.get("source_agent", ""),
                        "timestamp": item.get("created_at", ""),
                    }
                    for item in items
                ],
            }

        return json.dumps(export_data, indent=2, default=str)

    def _export_csv(self, all_findings: dict[str, list[dict]]) -> str:
        """Export findings as CSV."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "category", "severity", "key", "source_agent", "timestamp", "data"
        ])

        for category, items in all_findings.items():
            severity = CATEGORY_SEVERITY.get(category, "info")
            for item in items:
                writer.writerow([
                    category,
                    severity,
                    item.get("key", ""),
                    item.get("source_agent", ""),
                    item.get("created_at", ""),
                    json.dumps(item.get("data", {}), default=str),
                ])

        return output.getvalue()

    def _export_markdown(
        self, all_findings: dict[str, list[dict]], session_id: str
    ) -> str:
        """Export findings as Markdown."""
        lines: list[str] = []
        lines.append(f"# Penetration Test Findings - Session {session_id[:8]}")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}")
        lines.append(
            f"**Total Findings:** "
            f"{sum(len(v) for v in all_findings.values())}"
        )
        lines.append("")

        # Sort categories by severity
        sorted_cats = sorted(
            all_findings.items(),
            key=lambda x: SEVERITY_ORDER.get(
                CATEGORY_SEVERITY.get(x[0], "info"), 99
            ),
        )

        for category, items in sorted_cats:
            severity = CATEGORY_SEVERITY.get(category, "info")
            lines.append(f"## {category.replace('_', ' ').title()} [{severity.upper()}]")
            lines.append("")
            lines.append(f"**Count:** {len(items)}")
            lines.append("")

            for item in items[:20]:  # Cap at 20 items per category
                key = item.get("key", "unknown")
                lines.append(f"- **{key}**")
                data = item.get("data", {})
                if isinstance(data, dict):
                    for k, v in list(data.items())[:5]:
                        lines.append(f"  - {k}: {v}")

            if len(items) > 20:
                lines.append(f"- ... and {len(items) - 20} more")
            lines.append("")

        return "\n".join(lines)

    # ==================================================================
    #  Statistics builder
    # ==================================================================

    def _build_statistics(
        self, all_findings: dict[str, list[dict]], session_id: str
    ) -> dict:
        """Build comprehensive engagement statistics."""
        total_findings = sum(len(v) for v in all_findings.values())

        # Severity breakdown
        severity_breakdown: dict[str, int] = {}
        for category, items in all_findings.items():
            sev = CATEGORY_SEVERITY.get(category, "info")
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + len(items)

        # Per-category stats
        category_stats: dict[str, dict] = {}
        for category, items in all_findings.items():
            source_agents = list(set(
                item.get("source_agent", "unknown") for item in items
            ))
            category_stats[category] = {
                "count": len(items),
                "severity": CATEGORY_SEVERITY.get(category, "info"),
                "source_agents": source_agents,
            }

        # Agent contribution
        agent_stats: dict[str, int] = {}
        for items in all_findings.values():
            for item in items:
                agent = item.get("source_agent", "unknown")
                agent_stats[agent] = agent_stats.get(agent, 0) + 1

        # Timeline — earliest and latest finding timestamps
        timestamps: list[str] = []
        for items in all_findings.values():
            for item in items:
                ts = item.get("created_at", "")
                if ts:
                    timestamps.append(ts)

        timestamps.sort()
        first_finding = timestamps[0] if timestamps else None
        last_finding = timestamps[-1] if timestamps else None

        return {
            "session_id": session_id,
            "total_findings": total_findings,
            "categories_count": len(all_findings),
            "severity_breakdown": severity_breakdown,
            "category_stats": category_stats,
            "agent_contribution": agent_stats,
            "timeline": {
                "first_finding": first_finding,
                "last_finding": last_finding,
                "total_events": len(timestamps),
            },
        }

    # ==================================================================
    #  Capabilities manifest (Anthropic tool-use format)
    # ==================================================================

    def get_capabilities_manifest(self) -> dict:
        session_id_prop = {
            "type": "string",
            "description": "Session ID to generate the report for",
        }

        return {
            "name": self.name,
            "description": self.description,
            "tools": [
                {
                    "name": "reporting_generate_report",
                    "description": (
                        "Generate a structured penetration testing report from "
                        "real session findings. Supports three report types: "
                        "'executive' (high-level summary with risk ratings and "
                        "key outcomes), 'technical' (detailed findings sorted "
                        "by severity with evidence), and 'full' (comprehensive "
                        "report with executive summary, technical details, and "
                        "a prioritized remediation roadmap)."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "session_id": session_id_prop,
                            "report_type": {
                                "type": "string",
                                "enum": ["executive", "technical", "full"],
                                "description": (
                                    "Report detail level. 'executive' for "
                                    "management summary. 'technical' for "
                                    "detailed findings. 'full' for comprehensive "
                                    "report with remediation roadmap."
                                ),
                            },
                        },
                        "required": ["session_id"],
                    },
                },
                {
                    "name": "reporting_export_findings",
                    "description": (
                        "Export all session findings in a specified format. "
                        "'json' produces structured data with severity labels. "
                        "'csv' produces a flat table suitable for spreadsheets. "
                        "'markdown' produces a formatted document with severity "
                        "headers and finding details."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "session_id": session_id_prop,
                            "format": {
                                "type": "string",
                                "enum": ["json", "csv", "markdown"],
                                "description": (
                                    "Export format. 'json' for structured data, "
                                    "'csv' for spreadsheet import, 'markdown' "
                                    "for documentation."
                                ),
                            },
                        },
                        "required": ["session_id"],
                    },
                },
                {
                    "name": "reporting_get_statistics",
                    "description": (
                        "Retrieve comprehensive engagement statistics including "
                        "total findings count, severity breakdown, per-category "
                        "stats, agent contribution metrics, and a timeline of "
                        "when findings were captured. Useful for understanding "
                        "engagement scope and agent effectiveness."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "session_id": session_id_prop,
                        },
                        "required": ["session_id"],
                    },
                },
            ],
        }
