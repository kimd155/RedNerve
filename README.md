<p align="center">
  <img src="RedNerve.png" width="300" height="auto" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/RedNerve-AI%20Red%20Team-b00020?style=for-the-badge&labelColor=0f0f0f" />
  <img src="https://img.shields.io/badge/Kill%20Chain-Autonomous-ff1744?style=for-the-badge&labelColor=0f0f0f" />
  <img src="https://img.shields.io/badge/Powered%20By-Claude%20AI-7c3aed?style=for-the-badge&labelColor=0f0f0f" />
</p>

<h1 align="center">RedNerve</h1>

<p align="center">
  <b>The first AI-native red team operator that thinks, adapts, and executes — autonomously.</b>
</p>

<p align="center">
  <i>Tell it what you want in plain English. It handles the rest.</i>
</p>

---

## What is RedNerve?

RedNerve is an **AI-driven offensive security platform** that transforms natural language commands into fully chained attack sequences across Active Directory environments. Instead of memorizing tool syntax, writing scripts, or manually pivoting between hosts — you speak to an AI operator that orchestrates the entire kill chain from reconnaissance to domain takeover.

One prompt. Ten specialized agents. Zero manual tooling.

```
> Enumerate all domain users and find Kerberoastable accounts

[ReconAgent] Executing AD user enumeration via beacon on DC01...
[ReconAgent] Found 847 domain users across 23 OUs
[CredentialAgent] Identified 12 accounts with SPNs — launching Kerberoast...
[CredentialAgent] Extracted 12 TGS tickets, 3 cracked: svc_backup, svc_sql, admin_legacy
[IntelligenceAgent] svc_sql has local admin on SQL01, SQL02 — recommend lateral movement
```

Every action uses **real output from prior stages**. Nothing is fabricated. The AI remembers what it found, reasons about what to do next, and chains operations together — exactly like an experienced penetration tester would.

---

## Installation

### Prerequisites

- **Python 3.9+**
- **pip** (Python package manager)
- An **Anthropic API key** (get one at [console.anthropic.com](https://console.anthropic.com))

### Step 1 — Clone & Install Dependencies

```bash
git clone <your-repo-url>
cd rednerve
pip install -r requirements.txt
```

### Step 2 — Configure Your API Key

Create a `.env` file in the `rednerve/` directory:

```bash
touch .env
```

Add the following to your `.env` file:

```env
# Required — your Anthropic API key
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here

# AI model (default: claude-sonnet-4-5-20250929)
ANTHROPIC_MODEL=claude-sonnet-4-5-20250929

# Beacon secret (shared between server and implants)
BEACON_SECRET=change-this-to-a-strong-secret

# Server configuration
HOST=0.0.0.0
PORT=9999
BEACON_CHECKIN_INTERVAL=5
BEACON_TASK_TIMEOUT=300
DATABASE_URL=sqlite+aiosqlite:///rednerve.db
SECRET_KEY=change-this-to-a-random-string
```

** NOTE: You can do all of this from the /settings page **

> **Important:** The `ANTHROPIC_API_KEY` is required. Without it, RedNerve will show a configuration error when you try to send commands. You can also configure the API key from the **Settings** page in the UI after launching.

### Step 3 — Launch the Server

```bash
python3 run.py
```

Open **http://localhost:9999** in your browser — you're in.

### Step 4 — Deploy a Beacon

Navigate to the **Build** page (`/build`), configure your implant format (Python, PowerShell, Bash, or compiled binary), and deploy it on a target in your lab:

```bash
# On the target machine
python3 beacon_abc123.py
```

The beacon will check in and appear on the **Targets** page.

### Step 5 — Operate

Open the **Command** page, select a beacon, and start issuing commands in natural language:

```
> Scan the network and enumerate Active Directory
> Find all Kerberoastable accounts and attempt to crack them
> Move laterally to SQL01 using the credentials we found
> Establish persistence and generate a report
```

---

## Architecture

```
                    ┌─────────────────────────────────┐
                    │         Operator (You)          │
                    │      Natural Language Input     │
                    └───────────────┬─────────────────┘
                                    │ WebSocket
                    ┌───────────────▼─────────────────┐
                    │          Orchestrator           │
                    │    Claude AI + Tool-Use API     │
                    │   Intent Parsing → Dispatching  │
                    └───┬───┬───┬───┬───┬───┬───┬───┬─┘
                        │   │   │   │   │   │   │   │
              ┌─────────▼───▼───▼───▼───▼───▼───▼───▼──────────┐
              │              10 Specialized Agents             │
              │                                                │
              │  Recon · Credential · Execution · Lateral Move │
              │  PrivEsc · Persistence · Exfiltration · Intel  │
              │  Cleanup · Reporting                           │
              └────────────────────┬───────────────────────────┘
                                   │ Real Commands
              ┌────────────────────▼───────────────────────────┐
              │              Beacon Network                    │
              │                                                │
              │    ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐      │
              │    │ DC01 │  │ WS01 │  │ SQL01│  │ WEB01│      │
              │    └──────┘  └──────┘  └──────┘  └──────┘      │
              │         Active Directory Lab Environment       │
              └────────────────────────────────────────────────┘
```

### Core Components

| Component | Purpose |
|-----------|---------|
| **Orchestrator** | The brain — parses intent via Claude, dispatches to agents, aggregates results |
| **Kill Chain Memory** | Every finding (users, hosts, credentials, shares) is stored and fed back into subsequent decisions |
| **10 AI Agents** | Specialized operators for each phase of the attack lifecycle |
| **Beacon System** | Lightweight C2 implants deployed on targets — Python, PowerShell, Bash, or compiled binaries |
| **Real-Time UI** | WebSocket-powered dark-themed command center with live agent status, findings dashboard, and chat history |

---

## The Kill Chain — Fully Autonomous

What makes RedNerve fundamentally different: **every stage feeds the next**. The AI doesn't guess usernames or fabricate IPs. It uses exactly what it discovered.

```
Stage 1: RECON
  └─ "Enumerate the domain"
     └─ Discovers 847 users, 156 computers, 34 groups, 8 SPNs
         │
Stage 2: CREDENTIAL ACCESS
  └─ AI automatically selects discovered SPN accounts for Kerberoasting
     └─ Cracks svc_sql password from the TGS ticket
         │
Stage 3: LATERAL MOVEMENT
  └─ AI knows svc_sql has local admin on SQL01 (from recon data)
     └─ Executes PsExec to SQL01 using the cracked credential
         │
Stage 4: PRIVILEGE ESCALATION
  └─ Finds SQL01 has unconstrained delegation
     └─ Escalates to Domain Admin via delegation abuse
         │
Stage 5: PERSISTENCE
  └─ Installs golden ticket, scheduled task on DC01
         │
Stage 6: REPORTING
  └─ Generates full pentest report with findings, evidence, and remediation
```

No scripts. No copy-paste. No manual pivoting. The operator says what they want, and the AI executes the full chain with real commands on real targets.

---

## Features

### Command Center (`/chat`)
- **Natural language interface** — talk to RedNerve like a colleague, not a CLI
- **Beacon-scoped sessions** — select a target beacon before chatting; the AI gets focused context about that specific machine
- **General sessions** — chat without a beacon for cross-environment questions and planning
- **Real-time WebSocket** — live streaming of agent activity, task progress, and results
- **Chat history** — persistent sessions with sidebar navigation grouped by beacon vs. general
- **Session management** — create, switch, and delete chat sessions
- **Cancel operations** — stop a running agent mid-execution
- **Typing effects** — cinematic AI response rendering with markdown support

### Dashboard (`/dashboard`)
- **Beacon findings cards** — each target machine gets a card showing its hostname, IP, total findings, and severity breakdown (Critical / High / Medium / Low / Info)
- **Findings detail modal** — click a beacon card to see all findings organized by agent, with severity badges and data tables
- **Reports table** — view all generated reports with status (Processing / Ready / Failed) and download links
- **Report generation** — generate HTML assessment reports scoped to specific beacons or all findings, with AI-generated mitigations
- **Live activity feed** — real-time log stream from all agents with level filtering (All / Info / Warn / Error)

### Targets (`/targets`)
- **Beacon overview** — live grid of all connected beacons with hostname, IP, OS, username, domain, PID, integrity level
- **Status tracking** — active (green), dormant (yellow), dead (red) indicators with last-seen timestamps
- **Search & filter** — filter beacons by status or search by hostname/IP
- **Beacon management** — delete beacons from the UI

### Build (`/build`)
- **Multi-format builder** — generate implants as `.py`, `.ps1`, `.sh`, `.exe`, or `ELF` binaries
- **Configurable C2** — server URL, check-in interval, jitter, sleep delay, kill date
- **Auto-persistence** — optional registry keys, cron jobs, or scheduled tasks
- **One-click download** — build and download beacons directly from the browser

### Settings (`/settings`)
- **API key configuration** — set your Anthropic API key without editing files
- **Model selection** — choose between Claude models
- **Beacon secret** — configure the shared authentication key
- **Server options** — check-in interval, task timeout, and more

### Agent Framework
- **10 purpose-built agents** covering the complete MITRE ATT&CK kill chain
- **45 tool definitions** registered with Claude for precise intent routing
- **Chain memory** — findings from every stage stored in a structured database, injected into AI context for informed decision-making
- **Parallel execution** — multiple agents can operate simultaneously across different targets
- **Severity classification** — findings automatically classified as Critical, High, Medium, Low, or Info based on category

### Beacon Stability
- **Extended staleness thresholds** — beacons stay active during long task execution (active < 120s, dormant < 600s)
- **Check-in on result submission** — beacon status refreshes when it posts task results, not just on polling
- **Long-poll as heartbeat** — the wait-for-tasks connection itself counts as a check-in
- **Cross-platform** — Windows, Linux, macOS targets

---

## The 10 Agents

| Agent | Capabilities | Real Commands |
|-------|-------------|---------------|
| **Recon** | AD users, groups, computers, shares, SPNs, ports, services | `net user /domain`, `nltest`, `Get-ADUser`, nmap |
| **Credential** | Password spray, Kerberoast, hash dump, LSASS extraction | `Invoke-Kerberoast`, `sekurlsa::logonpasswords` |
| **Execution** | Run commands, PowerShell, file upload/download | Direct beacon tasking |
| **Lateral Movement** | PsExec, WMI, WinRM, Pass-the-Hash, SSH | `schtasks`, `wmic`, `Enter-PSSession` |
| **Privilege Escalation** | Token privs, escalation paths, UAC bypass | `whoami /all`, `fodhelper`, `eventvwr` |
| **Persistence** | Registry run keys, scheduled tasks, services, WMI subs | `reg add`, `schtasks /create` |
| **Exfiltration** | Find sensitive files, stage, compress, exfiltrate | `dir /s`, `Compress-Archive` |
| **Intelligence** | Analyze findings, suggest next steps, assess risk | Claude AI analysis of all gathered data |
| **Cleanup** | Clear event logs, remove artifacts, timestomp | `wevtutil cl`, artifact removal |
| **Reporting** | Generate pentest reports, export findings, statistics | Structured HTML reports with AI mitigations |

---

## Report Generation

RedNerve generates professional HTML assessment reports with:

- **Executive summary** — overall risk level, risk score, and total findings
- **Severity breakdown** — visual bars showing Critical / High / Medium / Low / Info distribution
- **Findings table** — each finding with severity, title, description, evidence, and AI-generated mitigation
- **Beacon scoping** — generate reports for a specific target machine or all beacons
- **Background processing** — reports generate asynchronously; download when ready from the dashboard
- **Dark-themed HTML** — styled reports matching the RedNerve aesthetic

---

## Project Structure

```
rednerve/
├── agents/                 # 10 specialized AI agents
│   ├── recon/
│   ├── credential/
│   ├── execution/
│   ├── lateral_movement/
│   ├── privilege_escalation/
│   ├── persistence/
│   ├── exfiltration/
│   ├── intelligence/
│   ├── cleanup/
│   └── reporting/
├── api/
│   ├── routes.py           # REST API endpoints
│   └── socket_events.py    # WebSocket event handlers
├── database/
│   ├── db.py               # Async SQLAlchemy engine + migrations
│   └── models.py           # Session, Message, Beacon, Task, Finding, Report models
├── orchestrator/
│   ├── orchestrator.py     # Core brain — intent dispatch + agent execution
│   ├── intent_parser.py    # Claude API integration with tool-use
│   ├── memory.py           # System prompt builder with findings context
│   └── task.py             # Task/TaskResult data structures
├── server/
│   └── beacon_handler.py   # Beacon registration, tasking, and result collection
├── services/
│   ├── chat_service.py     # Chat message persistence
│   ├── session_service.py  # Session management (beacon-scoped + general)
│   ├── findings_service.py # Kill chain memory — store/query findings
│   ├── log_service.py      # Activity logging with live WebSocket emission
│   └── report_service.py   # Background HTML report generation with AI mitigations
├── static/
│   ├── css/                # Dark-themed stylesheets
│   └── js/                 # Frontend logic (chat, dashboard, targets, build, settings)
├── templates/              # Jinja2 HTML templates
├── config.py               # Environment variable configuration
├── app.py                  # FastAPI + Socket.IO application factory
├── run.py                  # Server entry point
├── requirements.txt        # Python dependencies
└── .env                    # Your configuration (API key, secrets)
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI, python-socketio, SQLAlchemy (async) |
| AI | Claude API (tool-use), Anthropic SDK |
| Database | SQLite + aiosqlite (zero-config, auto-migrating) |
| Frontend | Vanilla JS, Socket.IO, Jinja2 templates |
| C2 Protocol | HTTP long-polling with shared secret auth |
| Implants | Python, PowerShell, Bash, PyInstaller binaries |

---

## Industry Impact

### The Problem

Penetration testing today is **manual, slow, and inconsistent**. A senior pentester spends hours typing commands, copy-pasting output between tools, and mentally tracking what they've found. The industry faces:

- **Talent shortage** — there aren't enough skilled red teamers to meet demand
- **Inconsistency** — results vary wildly between testers and engagements
- **Speed** — manual testing takes days or weeks for what should take hours
- **Knowledge loss** — institutional knowledge leaves when people leave

### The RedNerve Approach

RedNerve doesn't replace pentesters — it **amplifies them 10x**. An operator with RedNerve can:

- **Execute in minutes** what previously took hours of manual work
- **Never forget a finding** — the chain memory ensures every discovered user, host, and credential is used optimally
- **Maintain consistency** — the same quality of execution every time, regardless of who's operating
- **Focus on strategy** — spend time on high-level decisions, not command syntax

### What This Changes

| Before RedNerve | After RedNerve |
|-----------------|----------------|
| Memorize tool syntax for dozens of tools | Speak naturally, AI handles execution |
| Manually copy output between attack stages | Chain memory automatically connects stages |
| Lose track of discovered assets mid-engagement | Every finding persisted and available to all agents |
| Write custom scripts for each environment | AI adapts commands to the target environment |
| Spend days on a single AD assessment | Complete kill chains in hours |
| Junior testers limited by experience | AI provides expert-level execution to any operator |

---

## Disclaimer

RedNerve is designed **exclusively for authorized penetration testing and security research** in controlled lab environments. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical. The authors assume no liability for misuse.

Always obtain proper authorization before conducting any security testing.

---

<p align="center">
  <b>RedNerve</b> — The AI that hacks so you don't have to.<br>
  <sub>Built with precision. Powered by intelligence. Designed for operators.</sub>
</p>
