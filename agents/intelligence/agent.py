"""
IntelligenceAgent -- Strategic analysis from real operational data.

Unlike beacon-based agents, IntelligenceAgent does NOT send commands to
targets.  Instead it reads all findings stored by prior kill-chain stages
via the findings_service, synthesizes intelligence, and produces structured
analysis, next-step recommendations, and risk assessments.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from agents.base import AbstractAgent
from orchestrator.task import Task, TaskResult
from services.findings_service import findings_service

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Kill-chain phase ordering for progress analysis
# ------------------------------------------------------------------
KILL_CHAIN_PHASES = [
    ("recon", "Reconnaissance"),
    ("credential", "Credential Access"),
    ("execution", "Execution"),
    ("privilege_escalation", "Privilege Escalation"),
    ("lateral_movement", "Lateral Movement"),
    ("persistence", "Persistence"),
    ("exfiltration", "Exfiltration"),
    ("cleanup", "Cleanup"),
]

# Maps finding categories to the kill-chain phase that produces them
CATEGORY_TO_PHASE = {
    "users": "recon",
    "groups": "recon",
    "hosts": "recon",
    "shares": "recon",
    "services": "recon",
    "network": "recon",
    "kerberoastable": "recon",
    "credentials": "credential",
    "hashes": "credential",
    "sessions": "execution",
    "beacons": "execution",
    "privilege_escalations": "privilege_escalation",
    "lateral_moves": "lateral_movement",
    "persistence_mechanisms": "persistence",
    "files": "exfiltration",
    "staged_files": "exfiltration",
    "exfiltrated": "exfiltration",
    "archives": "exfiltration",
    "cleanup_actions": "cleanup",
}


class IntelligenceAgent(AbstractAgent):
    name = "intelligence"
    description = (
        "Analyzes findings from all kill chain stages, correlates data, "
        "and provides strategic recommendations — uses the AI to synthesize "
        "intelligence from real operational data"
    )
    capabilities = [
        "analyze_findings",
        "suggest_next_steps",
        "assess_risk",
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
                summary=f"Intelligence agent does not support action '{action}'",
            )

        session_id = params.get("session_id", task.session_id)
        if not session_id:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "Missing required parameter: session_id"},
                summary="Intelligence analysis failed: no session_id provided",
            )

        try:
            handler = getattr(self, f"_handle_{action}")
            return await handler(task, session_id, params)
        except Exception as exc:
            logger.exception("Intelligence %s failed for session %s", action, session_id)
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": str(exc)},
                summary=f"Intelligence {action} failed: {exc}",
            )

    # ==================================================================
    #  Analyze findings
    # ==================================================================

    async def _handle_analyze_findings(
        self, task: Task, session_id: str, params: dict
    ) -> TaskResult:
        all_findings = await findings_service.get_all(session_id)

        if not all_findings:
            return TaskResult(
                task_id=task.id,
                status="partial",
                data={
                    "findings": {},
                    "analysis": {"status": "no_data"},
                },
                summary="Intelligence analysis: no findings available for this session",
            )

        # Build a structured analysis
        analysis = self._build_analysis(all_findings)

        return TaskResult(
            task_id=task.id,
            status="success",
            data={
                "findings": {
                    "intelligence": [
                        {
                            "key": "analysis_report",
                            "type": "analysis",
                            "session_id": session_id,
                            "generated_at": datetime.now(timezone.utc).isoformat(),
                            "data": analysis,
                        }
                    ]
                },
                "analysis": analysis,
            },
            summary=(
                f"Intelligence analysis for session {session_id[:8]}...: "
                f"{analysis['total_findings']} findings across "
                f"{len(analysis['categories'])} categories, "
                f"{analysis['phases_completed']}/{len(KILL_CHAIN_PHASES)} "
                f"kill chain phases completed"
            ),
        )

    # ==================================================================
    #  Suggest next steps
    # ==================================================================

    async def _handle_suggest_next_steps(
        self, task: Task, session_id: str, params: dict
    ) -> TaskResult:
        all_findings = await findings_service.get_all(session_id)
        suggestions = self._build_suggestions(all_findings)

        return TaskResult(
            task_id=task.id,
            status="success",
            data={
                "findings": {
                    "intelligence": [
                        {
                            "key": "next_steps",
                            "type": "suggestions",
                            "session_id": session_id,
                            "generated_at": datetime.now(timezone.utc).isoformat(),
                            "data": suggestions,
                        }
                    ]
                },
                "suggestions": suggestions,
            },
            summary=(
                f"Next steps for session {session_id[:8]}...: "
                f"{len(suggestions['recommended_actions'])} action(s) suggested, "
                f"current phase: {suggestions['current_phase']}, "
                f"next phase: {suggestions['next_phase']}"
            ),
        )

    # ==================================================================
    #  Assess risk
    # ==================================================================

    async def _handle_assess_risk(
        self, task: Task, session_id: str, params: dict
    ) -> TaskResult:
        all_findings = await findings_service.get_all(session_id)
        risk_assessment = self._build_risk_assessment(all_findings)

        return TaskResult(
            task_id=task.id,
            status="success",
            data={
                "findings": {
                    "intelligence": [
                        {
                            "key": "risk_assessment",
                            "type": "risk",
                            "session_id": session_id,
                            "generated_at": datetime.now(timezone.utc).isoformat(),
                            "data": risk_assessment,
                        }
                    ]
                },
                "risk_assessment": risk_assessment,
            },
            summary=(
                f"Risk assessment for session {session_id[:8]}...: "
                f"overall risk {risk_assessment['overall_risk_level']} "
                f"({risk_assessment['overall_risk_score']}/10), "
                f"{len(risk_assessment['risk_factors'])} risk factor(s) identified"
            ),
        )

    # ==================================================================
    #  Analysis builders
    # ==================================================================

    def _build_analysis(self, all_findings: dict[str, list[dict]]) -> dict:
        """Build a comprehensive analysis from all session findings."""
        categories = {}
        total_count = 0

        for category, items in all_findings.items():
            count = len(items)
            total_count += count
            keys = [item.get("key", "") for item in items]
            source_agents = list(set(
                item.get("source_agent", "unknown") for item in items
            ))
            categories[category] = {
                "count": count,
                "keys": keys[:50],  # Cap for readability
                "source_agents": source_agents,
                "latest": items[-1].get("data", {}) if items else None,
            }

        # Determine which kill-chain phases have findings
        completed_phases = set()
        for category in all_findings:
            phase = CATEGORY_TO_PHASE.get(category)
            if phase:
                completed_phases.add(phase)

        phase_status = []
        for phase_id, phase_name in KILL_CHAIN_PHASES:
            phase_status.append({
                "phase": phase_id,
                "name": phase_name,
                "completed": phase_id in completed_phases,
                "finding_categories": [
                    cat for cat, ph in CATEGORY_TO_PHASE.items()
                    if ph == phase_id and cat in all_findings
                ],
            })

        # Key findings summary
        key_findings = []
        if "credentials" in all_findings:
            cred_count = len(all_findings["credentials"])
            key_findings.append(
                f"{cred_count} credential(s) harvested"
            )
        if "hosts" in all_findings:
            host_count = len(all_findings["hosts"])
            key_findings.append(
                f"{host_count} host(s) discovered"
            )
        if "users" in all_findings:
            user_count = len(all_findings["users"])
            key_findings.append(
                f"{user_count} user account(s) enumerated"
            )
        if "kerberoastable" in all_findings:
            kerb_count = len(all_findings["kerberoastable"])
            key_findings.append(
                f"{kerb_count} Kerberoastable account(s) found"
            )
        if "shares" in all_findings:
            share_count = len(all_findings["shares"])
            key_findings.append(
                f"{share_count} network share(s) discovered"
            )
        if "exfiltrated" in all_findings:
            exfil_count = len(all_findings["exfiltrated"])
            key_findings.append(
                f"{exfil_count} file(s) exfiltrated"
            )

        return {
            "total_findings": total_count,
            "categories": categories,
            "phases_completed": len(completed_phases),
            "phase_status": phase_status,
            "key_findings": key_findings,
        }

    def _build_suggestions(self, all_findings: dict[str, list[dict]]) -> dict:
        """Suggest next kill-chain actions based on current findings."""
        existing_categories = set(all_findings.keys())
        completed_phases = set()
        for category in existing_categories:
            phase = CATEGORY_TO_PHASE.get(category)
            if phase:
                completed_phases.add(phase)

        # Determine current and next phase
        current_phase = "recon"
        next_phase = "recon"
        for i, (phase_id, _) in enumerate(KILL_CHAIN_PHASES):
            if phase_id in completed_phases:
                current_phase = phase_id
                if i + 1 < len(KILL_CHAIN_PHASES):
                    next_phase = KILL_CHAIN_PHASES[i + 1][0]
                else:
                    next_phase = "complete"

        # Build recommended actions based on what data is available
        recommended_actions: list[dict] = []

        # If no findings at all, start with recon
        if not all_findings:
            recommended_actions.append({
                "priority": 1,
                "agent": "recon",
                "action": "ad_enum_users",
                "rationale": "No findings yet -- start with AD user enumeration",
            })
            recommended_actions.append({
                "priority": 2,
                "agent": "recon",
                "action": "ad_enum_computers",
                "rationale": "Discover domain computers for targeting",
            })
            return {
                "current_phase": current_phase,
                "next_phase": next_phase,
                "completed_phases": sorted(completed_phases),
                "recommended_actions": recommended_actions,
            }

        # Users found but no credentials -> credential attacks
        if "users" in existing_categories and "credentials" not in existing_categories:
            user_count = len(all_findings["users"])
            recommended_actions.append({
                "priority": 1,
                "agent": "credential",
                "action": "password_spray",
                "rationale": f"{user_count} users discovered -- attempt password spray",
                "requires": {"usernames": [u.get("key", "") for u in all_findings["users"][:20]]},
            })
        if "kerberoastable" in existing_categories and "credentials" not in existing_categories:
            recommended_actions.append({
                "priority": 1,
                "agent": "credential",
                "action": "kerberoast",
                "rationale": "Kerberoastable accounts found -- request TGS tickets for offline cracking",
            })

        # Credentials found but no lateral movement
        if "credentials" in existing_categories and "lateral_moves" not in existing_categories:
            if "hosts" in existing_categories:
                recommended_actions.append({
                    "priority": 2,
                    "agent": "lateral_movement",
                    "action": "wmi_exec",
                    "rationale": "Credentials and hosts available -- attempt lateral movement",
                })

        # Hosts discovered but no privilege escalation
        if "hosts" in existing_categories and "privilege_escalations" not in existing_categories:
            recommended_actions.append({
                "priority": 3,
                "agent": "privilege_escalation",
                "action": "check_privesc",
                "rationale": "Check compromised hosts for privilege escalation vectors",
            })

        # If we have access but no persistence
        if ("credentials" in existing_categories or "sessions" in existing_categories) and \
                "persistence_mechanisms" not in existing_categories:
            recommended_actions.append({
                "priority": 4,
                "agent": "persistence",
                "action": "install_persistence",
                "rationale": "Establish persistence to maintain access",
            })

        # If we have access but haven't looked for files
        if "hosts" in existing_categories and "files" not in existing_categories:
            recommended_actions.append({
                "priority": 4,
                "agent": "exfiltration",
                "action": "find_sensitive_files",
                "rationale": "Search compromised hosts for sensitive data",
            })

        # Shares found -> look for sensitive files on shares
        if "shares" in existing_categories and "files" not in existing_categories:
            recommended_actions.append({
                "priority": 3,
                "agent": "exfiltration",
                "action": "find_sensitive_files",
                "rationale": "Network shares discovered -- search for sensitive files",
            })

        # Files staged but not exfiltrated
        if "staged_files" in existing_categories and "exfiltrated" not in existing_categories:
            recommended_actions.append({
                "priority": 2,
                "agent": "exfiltration",
                "action": "exfiltrate",
                "rationale": "Staged files ready for exfiltration",
            })

        # If most phases are done, suggest cleanup
        if len(completed_phases) >= 4 and "cleanup" not in completed_phases:
            recommended_actions.append({
                "priority": 5,
                "agent": "cleanup",
                "action": "clear_logs",
                "rationale": "Multiple phases completed -- consider cleaning tracks",
            })

        # Sort by priority
        recommended_actions.sort(key=lambda x: x["priority"])

        return {
            "current_phase": current_phase,
            "next_phase": next_phase,
            "completed_phases": sorted(completed_phases),
            "recommended_actions": recommended_actions,
        }

    def _build_risk_assessment(self, all_findings: dict[str, list[dict]]) -> dict:
        """Assess the risk profile of what's been found."""
        risk_score = 0
        risk_factors: list[dict] = []

        # --- Credential risk ---
        if "credentials" in all_findings:
            cred_count = len(all_findings["credentials"])
            cred_risk = min(10, 3 + cred_count)
            risk_score = max(risk_score, cred_risk)
            risk_factors.append({
                "factor": "credential_exposure",
                "severity": "critical" if cred_count >= 5 else "high",
                "score": cred_risk,
                "detail": f"{cred_count} credential(s) compromised",
                "remediation": "Reset all compromised passwords, enforce MFA",
            })

        # --- Kerberoastable accounts ---
        if "kerberoastable" in all_findings:
            kerb_count = len(all_findings["kerberoastable"])
            kerb_risk = min(9, 4 + kerb_count)
            risk_score = max(risk_score, kerb_risk)
            risk_factors.append({
                "factor": "kerberoastable_accounts",
                "severity": "high",
                "score": kerb_risk,
                "detail": f"{kerb_count} service account(s) with SPNs vulnerable to offline cracking",
                "remediation": "Use managed service accounts, set complex passwords for service accounts",
            })

        # --- Host compromise ---
        if "hosts" in all_findings:
            host_count = len(all_findings["hosts"])
            host_risk = min(8, 2 + host_count)
            risk_score = max(risk_score, host_risk)
            risk_factors.append({
                "factor": "host_exposure",
                "severity": "high" if host_count >= 5 else "medium",
                "score": host_risk,
                "detail": f"{host_count} host(s) enumerated/accessible",
                "remediation": "Review network segmentation, restrict lateral movement",
            })

        # --- Data exfiltration ---
        if "exfiltrated" in all_findings:
            exfil_count = len(all_findings["exfiltrated"])
            exfil_risk = min(10, 7 + exfil_count)
            risk_score = max(risk_score, exfil_risk)
            risk_factors.append({
                "factor": "data_exfiltration",
                "severity": "critical",
                "score": exfil_risk,
                "detail": f"{exfil_count} file(s) successfully exfiltrated",
                "remediation": "Implement DLP, review egress filtering, classify sensitive data",
            })

        # --- Persistence ---
        if "persistence_mechanisms" in all_findings:
            persist_count = len(all_findings["persistence_mechanisms"])
            persist_risk = min(9, 5 + persist_count)
            risk_score = max(risk_score, persist_risk)
            risk_factors.append({
                "factor": "persistence_installed",
                "severity": "critical" if persist_count >= 3 else "high",
                "score": persist_risk,
                "detail": f"{persist_count} persistence mechanism(s) installed",
                "remediation": "Audit startup items, scheduled tasks, registry Run keys, services",
            })

        # --- User accounts ---
        if "users" in all_findings:
            user_count = len(all_findings["users"])
            risk_factors.append({
                "factor": "user_enumeration",
                "severity": "medium",
                "score": min(5, 1 + user_count // 10),
                "detail": f"{user_count} user account(s) enumerated",
                "remediation": "Review account policies, disable unused accounts",
            })

        # --- Network shares ---
        if "shares" in all_findings:
            share_count = len(all_findings["shares"])
            share_risk = min(7, 2 + share_count)
            risk_score = max(risk_score, share_risk)
            risk_factors.append({
                "factor": "exposed_shares",
                "severity": "medium" if share_count < 5 else "high",
                "score": share_risk,
                "detail": f"{share_count} network share(s) accessible",
                "remediation": "Review share permissions, restrict anonymous access",
            })

        # If no findings at all, baseline risk is low
        if not risk_factors:
            risk_score = 1
            risk_factors.append({
                "factor": "no_findings",
                "severity": "info",
                "score": 1,
                "detail": "No operational findings yet",
                "remediation": "N/A",
            })

        # Determine overall risk level
        if risk_score >= 8:
            risk_level = "critical"
        elif risk_score >= 6:
            risk_level = "high"
        elif risk_score >= 4:
            risk_level = "medium"
        elif risk_score >= 2:
            risk_level = "low"
        else:
            risk_level = "info"

        # Sort factors by score descending
        risk_factors.sort(key=lambda x: x["score"], reverse=True)

        return {
            "overall_risk_score": risk_score,
            "overall_risk_level": risk_level,
            "risk_factors": risk_factors,
            "total_categories_assessed": len(all_findings),
            "total_findings_assessed": sum(len(v) for v in all_findings.values()),
        }

    # ==================================================================
    #  Capabilities manifest (Anthropic tool-use format)
    # ==================================================================

    def get_capabilities_manifest(self) -> dict:
        session_id_prop = {
            "type": "string",
            "description": "Session ID to analyze findings for",
        }

        return {
            "name": self.name,
            "description": self.description,
            "tools": [
                {
                    "name": "intelligence_analyze_findings",
                    "description": (
                        "Analyze all findings collected during the engagement "
                        "session. Reads findings from every kill-chain stage "
                        "(recon, credential, execution, lateral movement, "
                        "persistence, exfiltration) and produces a structured "
                        "analysis including category breakdowns, kill-chain "
                        "phase completion status, and key findings summary."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "session_id": session_id_prop,
                        },
                        "required": ["session_id"],
                    },
                },
                {
                    "name": "intelligence_suggest_next_steps",
                    "description": (
                        "Suggest the next actions to take based on current "
                        "session findings. Analyzes what data is available from "
                        "prior stages and recommends logical next steps in the "
                        "kill chain with priorities, target agents, specific "
                        "actions, and rationale for each recommendation."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "session_id": session_id_prop,
                        },
                        "required": ["session_id"],
                    },
                },
                {
                    "name": "intelligence_assess_risk",
                    "description": (
                        "Assess the risk profile of the current engagement "
                        "based on all findings. Evaluates credential exposure, "
                        "host compromise depth, data exfiltration scope, "
                        "persistence footprint, and network exposure. Returns "
                        "an overall risk score (1-10), severity level, "
                        "individual risk factors, and remediation guidance."
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
