# Host Prevention Methodology — Insider Threat Response System

## Overview

The Host-based Intrusion Prevention System (HIPS) monitors device behavior in real-time using AI models (XGBoost + Random Forest) to detect insider threats. When suspicious activity is detected, the system evaluates the threat level and takes automated response actions.

---

## How It Works

### 1. Data Collection (Host Agent)
Each monitored device runs a lightweight agent that collects **15 behavioral features** every 10 seconds:

| Feature | Description |
|---------|-------------|
| `cpu_percent` | Current CPU usage % |
| `memory_percent` | RAM usage % |
| `disk_read_bytes` | Disk read since last check |
| `disk_write_bytes` | Disk write since last check |
| `net_bytes_sent` | Network bytes sent |
| `net_bytes_recv` | Network bytes received |
| `num_processes` | Total running processes |
| `num_connections` | Active network connections |
| `num_open_files` | Open file handles |
| `num_threads` | Total active threads |
| `num_users` | Logged-in users |
| `failed_logins` | Failed login count (from event log) |
| `num_high_cpu_procs` | Processes using >50% CPU |
| `num_listening_ports` | Open listening network ports |
| `num_established_conns` | Established TCP connections |

### 2. AI Analysis (Backend)
The backend runs **two models** on the collected features:

- **XGBoost Model**: Primary prediction — outputs threat probability (0.0 to 1.0)
- **Random Forest Model**: Secondary validation — provides comparison prediction

If both models agree on a threat, confidence is higher.

### 3. Threat Evaluation (Response Orchestrator)
The `InsiderThreatResponseOrchestrator` evaluates the threat probability against **3 configurable thresholds**:

| Level | Default Threshold | Response |
|-------|------------------|----------|
| **LOW** | >= 0.50 | Log the event, increase monitoring frequency |
| **MEDIUM** | >= 0.70 | Restrict file access, quarantine suspicious emails, alert admin |
| **CRITICAL** | >= 0.90 | Kill suspicious processes, block network access, isolate device |

### 4. Response Actions by Activity Type

| Activity Type | LOW Response | MEDIUM Response | CRITICAL Response |
|--------------|-------------|-----------------|-------------------|
| **FILE** | Log access | Set read-only | Block and quarantine |
| **EMAIL** | Flag for review | Quarantine email | Block email client |
| **HTTP** | Log traffic | Rate limit | Connection reset |
| **PROCESS** | Monitor | Suspend process | Kill process |
| **NETWORK** | Log connection | Throttle bandwidth | Firewall block |

---

## Operating Modes

### Test Mode (Default: ON)
- All actions are **logged only** — no real OS-level changes
- Safe for testing and evaluation
- Toggle from: **Controls page -> Host Prevention -> Test Mode / Live Mode**

### Live Mode
- Real OS-level actions are executed (process kill, firewall rules, etc.)
- **Requires running backend as Administrator on Windows**
- Enable carefully — confirm with the warning dialog

---

## Configuration

### Adjusting Thresholds
From the Controls page -> Host Threat Thresholds section:

1. **Low Risk slider**: Minimum probability to start logging (default: 0.50)
2. **Medium Risk slider**: Probability to start restricting (default: 0.70)
3. **Critical Risk slider**: Probability to fully block (default: 0.90)

**Rule**: Low < Medium < Critical (enforced by UI)

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/prevention/status` | GET | Current prevention system status |
| `/api/prevention/thresholds` | GET | Current threshold values |
| `/api/prevention/thresholds` | POST | Update thresholds and test_mode |
| `/api/prevention/logs` | GET | Recent prevention action logs |

---

## Verification and Proof

When prevention actions are taken, they are logged with:
- **Timestamp** — when the action occurred
- **Device name** — which device triggered it
- **Risk level** — LOW / MEDIUM / CRITICAL
- **Activity type** — what kind of activity was detected
- **Action taken** — specific response executed
- **Test mode flag** — whether it was a real action or simulated

These logs are visible in:
1. **Controls page** -> "Recent Host Prevention Actions" table
2. **Device Detail page** -> individual device's prevention history
3. **Backend API** -> `/api/prevention/logs` endpoint

---

## Architecture Diagram

```
[Host Agent] -> collects 15 features every 10s
      |
[Backend API] -> /api/agents/host-report
      |
[AI Models] -> XGBoost + RandomForest predict threat probability
      |
[Response Orchestrator] -> evaluates against thresholds
      |
[Action Engine] -> executes response (or logs in test mode)
      |
[Prevention Logs] -> stored in database, shown in UI
```

---

## Security Notes

- **Hardware Fingerprint**: Each device generates a unique HMAC-SHA256 fingerprint from hardware identifiers. Copying the agent to another machine will be detected and rejected.
- **Admin Approval**: New devices must be approved by admin before they can report data.
- **Clone Detection**: If someone clones an agent, the different hardware fingerprint triggers automatic rejection.
