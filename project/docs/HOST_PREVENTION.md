# Host Prevention Methodology — Insider Threat Response System

> **Last Updated**: April 9, 2026

## Overview

The Host-based Intrusion Prevention System (HIPS) monitors device behavior in real-time using AI models (XGBoost primary + Random Forest secondary) trained on the **CERT r4.2 Insider Threat Dataset**. Each monitored device runs a lightweight Python agent that collects 15 behavioral features, sends them to the backend for prediction, and executes prevention commands (lock screen, USB disable, process kill, fullscreen alert dialog) when threats are detected.

---

## How It Works

### 1. Data Collection (Host Agent)

**File**: `project/agents/host_agent/host_agent.py`

Each monitored device runs a host agent that collects **15 CERT r4.2 behavioral features** every 5–10 seconds:

| # | Feature | Description | Collection Method |
|---|---------|-------------|-------------------|
| 0 | `total_logons` | New TCP connections per window (scaled) | Network delta / 10, noise threshold = 50 |
| 1 | `avg_logon_hour` | Hour of day (0–23) | System clock |
| 2 | `std_logon_hour` | Login stddev (0.5 if activity exists) | Calculated |
| 3 | `weekend_logons` | Logons × weekend flag | Time check (Sat/Sun) |
| 4 | `after_hours_logons` | Logons × after-hours flag | After-hours = 18:00–08:00 |
| 5 | `unique_pcs_logon` | Always 1.0 (single PC) | Hardcoded |
| 6 | `total_device_activities` | USB events + file operations | USB monitor + file scan |
| 7 | `unique_pcs_device` | 1 if USB active, else 0 | USB detection |
| 8 | `avg_device_hour` | Hour of device activity | System clock |
| 9 | `after_hours_device` | Device ops × after-hours flag | Device × time |
| 10 | `total_file_activities` | Recent file count × 10 | File scan (45s window) |
| 11 | `unique_files` | File count × 7.5 | File scan (45s window, 0.75 scaling) |
| 12 | `unique_pcs_file` | 1 if files detected, else 0 | File count > 0 |
| 13 | `avg_file_hour` | Hour of file activity | System clock |
| 14 | `after_hours_files` | File ops × after-hours flag | File ops × time |

**Key Algorithms:**
- **Network delta**: TCP connection count changes (noise threshold = 50 to filter background)
- **File activity**: Modified files in `~/Desktop`, `~/Downloads`, `~/Documents` within last 45 seconds (max scan time: 5s)
- **USB detection**: Windows API `GetLogicalDrives()` + `GetDriveTypeW()` to detect removable media (type 2)
- **After-hours**: 18:00–08:00 (6 PM – 8 AM)

### 2. AI Analysis (Backend)

**File**: `project/backend/src/infra/model_loader.py`

The backend runs **two models** on the collected 15 features:

| Model | File | Role | Threshold |
|-------|------|------|-----------|
| **XGBoost** | `ai_models/host_cnn/xgb_complete_pipeline.pkl` | Primary decision maker | **0.65** (raised from 0.5 to reduce false positives) |
| **Random Forest** | `ai_models/host_cnn/rf_complete_pipeline.pkl` | Secondary confirmation | N/A (does not override XGBoost) |

**Prediction Logic:**
- XGBoost probability ≥ 0.65 → `"Attack"`
- XGBoost probability < 0.65 → `"Normal"`
- Random Forest provides secondary data for ensemble reporting
- If XGBoost is unavailable, Random Forest becomes primary

**Response Format:**
```json
{
  "prediction": "Attack",
  "probability": 0.87,
  "models": {
    "XGBoost": {"prediction": "Attack", "probability": 0.87},
    "RandomForest": {"prediction": "Attack", "probability": 0.82}
  }
}
```

### 3. Threat Evaluation (Response Orchestrator)

**File**: `project/backend/utils/response_orchestrator.py`

The orchestrator evaluates threat probability against **3 configurable thresholds**:

| Level | Default Threshold | Response Actions |
|-------|------------------|------------------|
| **LOW** | ≥ 0.50 | Log and monitor activity |
| **MEDIUM** | ≥ 0.70 | Lock screen verification |
| **CRITICAL** | ≥ 0.90 | Lock screen + kill suspicious processes + disable USB + alert dialog |

**Feature-Based Intelligent Actions:**

| Condition | Triggered Action |
|-----------|-----------------|
| `total_device_activities > 300` AND `after_hours_device > 150` | `disable_usb` |
| `total_file_activities > 5000` OR `unique_files > 3000` | `kill_suspicious_processes` |
| `after_hours_logons > 10` OR `after_hours_files > 1000` | `lock_screen` |
| Any CRITICAL level detection | `lock_screen` (always added) |
| Any detection above LOW | `alert_user` (always added) |

### 4. Prevention Actions

**File**: `project/agents/host_agent/host_agent.py`

#### Action 1: Lock Screen
- **Command**: `lock_screen`
- **Implementation**: `ctypes.windll.user32.LockWorkStation()` (Win+L)
- **Effect**: Immediately locks the workstation, requires Windows re-authentication

#### Action 2: Disable USB Storage
- **Command**: `disable_usb`
- **Registry Key**: `HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR`
- **Value**: `Start = 4` (disabled) / `Start = 3` (re-enabled)
- **Effect**: Prevents all USB storage device access

#### Action 3: Kill Suspicious Processes
- **Command**: `kill_suspicious_processes`
- **Whitelist**: 25+ safe system processes (explorer.exe, svchost.exe, python.exe, etc.)
- **Kill List**: Known hacking tools (Netcat, Mimikatz, PSExec, WMI tools, script hosts — 12 patterns)
- **Implementation**: `psutil.process_iter()` → match against patterns → `proc.kill()`

#### Action 4: Alert User (Fullscreen Dialog)
- **Command**: `alert_user`
- **Primary UI**: Modern HTML dialog via pywebview (dark cybersecurity theme)
- **Fallback 1**: Tkinter window
- **Fallback 2**: Windows MessageBox via ctypes
- **Features**:
  - Fullscreen dark overlay with animated threat indicators
  - Pulsing shield icon + scanning line animation
  - **Admin password required to dismiss** (default: `admin123`)
  - Always-on-top, cannot be closed without authentication
  - Reports dialog events to backend (shown/password_success/password_failed)

#### Action 5: Reset Prevention
- **Command**: `reset_prevention`
- **Triggered when**: Admin successfully authenticates via alert dialog
- **Effect**: Re-enables USB, clears prevention state, resets cooldown timers

**Cooldown**: 120 seconds between same action types to prevent action spam.

---

## USB Monitoring System

**File**: `project/agents/host_agent/host_agent.py`

### Detection Method
1. **Windows API**: `GetLogicalDrives()` returns bitmask of available drives
2. **Drive Classification**: `GetDriveTypeW()` — Type 2 = Removable (USB/SD cards)
3. **Change Detection**: Compare current drives with previous state each cycle
4. **File Counting**: Scan newly detected drive for files (max 2s, 5000 files cap)

### Feature Calculation
- **USB Device Weight**: `new_drives_count × 200` (each USB adds 200 to `total_device_activities`)
- **Persistence Window**: 15 seconds after detection (bridges detection-to-counting gap)
- **On USB Removal**: All persistence state immediately cleared (prevents false positives)

### Attack Signature
```
USB inserted → high total_device_activities → model predicts "Attack"
→ CRITICAL threat level → disable_usb + lock_screen + alert_user
```

---

## Alert Dialog Architecture

**File**: `project/agents/host_agent/alert_ui.py`

```
1. Host Agent detects threat → queues alert_user command
2. Spawns subprocess running alert_ui.py
3. pywebview renders fullscreen HTML dialog:
   ├── Dark overlay (#0B1121 background)
   ├── Centered 480×560 card with red (#EF4444) accents
   ├── Animated scanning line (3.5s cycle)
   ├── Pulsing shield icon with radial gradient
   ├── Threat reason text
   ├── Admin password input field
   └── Fade-up entry animation with staggered delays
4. User enters admin password
   ├── CORRECT → green "Authenticated" → dialog closes → prevention resets
   └── WRONG → "Incorrect password" → focus returns to input
5. Events reported to backend via HTTP POST
```

---

## Communication Protocol

**File**: `project/agents/host_agent/host_agent.py`

### Report Endpoint
```
POST /api/agent/host-report

Headers:
  X-Agent-Key: <agent_key>
  X-Agent-ID: <unique_uuid>
  X-Hardware-ID: <hmac_sha256(cpu+mac+hostname+disk_serial)>

Body:
{
  "agent_id": "<uuid>",
  "host_name": "<machine_name>",
  "ip": "<local_ip>",
  "features": [15 floats],
  "os_info": "Windows 10 Build 19043 (AMD64)"
}

Response:
{
  "prediction": "Attack",
  "probability": 0.87,
  "prevention": {
    "test_mode": false,
    "prevention_commands": [
      {"type": "lock_screen", "reason": "..."},
      {"type": "disable_usb", "reason": "..."},
      {"type": "alert_user", "reason": "..."}
    ]
  }
}
```

### Connection Management
- **Persistent Session**: `requests.Session()` with keep-alive
- **Auto-Discovery**: UDP broadcast on port 5001
- **Fallback**: Gateway IP → subnet scan → common router IPs
- **Registration**: POST `/register` with agent_id, hostname, hardware_id
- **Retry Logic**: Exponential backoff (interval + consecutive_errors × 5, max 60s)

---

## Operating Modes

### Test Mode (Default: ON)
- All actions are **logged only** — no real OS-level changes
- Safe for evaluation and demonstration
- Toggle from: **Controls page → Host Prevention → Test/Live Mode**

### Live Mode
- Prevention commands are **executed on the real OS**
- Lock screen, USB disable, process kill all take effect
- **Requires backend running with appropriate privileges**

---

## Manual Controls & API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/prevention/status` | GET | Current prevention system status |
| `/api/prevention/thresholds` | GET/POST | Get or update threshold values |
| `/api/prevention/mode` | POST | Switch between TEST and LIVE mode |
| `/api/prevention/logs` | GET | Recent prevention action logs (filtered) |
| `/api/prevention/host/block` | POST | Manually block a host IP via firewall |
| `/api/prevention/host/unblock` | POST | Remove a host IP block |
| `/api/prevention/host/blocked` | GET | List all currently blocked hosts |
| `/api/prevention/host/verify` | GET | Verify firewall rules exist in OS |
| `/api/prevention/host/clear-all` | POST | Remove all `IPS_HOST_BLOCK_*` firewall rules |

### Firewall Rule Naming
- Pattern: `IPS_HOST_BLOCK_{ip}_IN` / `IPS_HOST_BLOCK_{ip}_OUT`
- Dots replaced with underscores: `192.168.1.100` → `192_168_1_100`
- Requires Administrator privileges (`netsh advfirewall`)

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         MONITORED DEVICE                            │
│                                                                     │
│  ┌──────────────────────────┐     ┌──────────────────────────────┐  │
│  │      Host Agent          │     │     Prevention Actions       │  │
│  │  ┌────────────────────┐  │     │  • Lock Screen (Win+L)       │  │
│  │  │ Feature Collector   │  │◄────│  • Disable USB (Registry)    │  │
│  │  │ • TCP connections   │  │     │  • Kill Processes (psutil)   │  │
│  │  │ • File activity     │  │     │  • Alert Dialog (pywebview)  │  │
│  │  │ • USB monitoring    │  │     └──────────────────────────────┘  │
│  │  │ • Time analysis     │  │                                      │
│  │  └────────┬───────────┘  │                                      │
│  │           │ 15 features   │                                      │
│  └───────────┼──────────────┘                                      │
│              │ HTTP POST                                            │
└──────────────┼──────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         BACKEND SERVER                               │
│                                                                      │
│  ┌───────────────────┐    ┌──────────────────────┐                   │
│  │  /api/agent/       │    │    AI Models          │                   │
│  │  host-report       │───►│  XGBoost (primary)    │                   │
│  │  (receives 15      │    │  threshold = 0.65     │                   │
│  │   features)        │    │  RandomForest (sec.)  │                   │
│  └───────────────────┘    └──────────┬───────────┘                   │
│                                      │                               │
│                           ┌──────────▼───────────┐                   │
│                           │ Response Orchestrator │                   │
│                           │  LOW    ≥ 0.50       │                   │
│                           │  MEDIUM ≥ 0.70       │                   │
│                           │  CRITICAL ≥ 0.90     │                   │
│                           └──────────┬───────────┘                   │
│                                      │ prevention_commands            │
│                                      ▼                               │
│                           ┌──────────────────────┐                   │
│                           │   Response to Agent   │                   │
│                           │   + DB Logging        │                   │
│                           │   + Socket.IO Event   │                   │
│                           └──────────────────────┘                   │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Security Notes

- **Hardware Fingerprint**: Each device generates a unique HMAC-SHA256 from CPU, MAC, hostname, and disk serial. Copying the agent to another machine triggers automatic rejection.
- **Admin Approval**: New devices start as "pending" and must be approved by admin before reporting.
- **Clone Detection**: Mismatched hardware fingerprint → registration rejected.
- **Alert Password**: Admin must authenticate (default: `admin123`) to dismiss the threat alert dialog.
- **Prevention Cooldown**: 120-second cooldown between same action types prevents action spam.
- **USB Persistence Fix**: On USB removal, all detection state is immediately cleared to prevent false positives.
