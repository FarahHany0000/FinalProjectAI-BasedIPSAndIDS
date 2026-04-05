# Host Prevention Methodology — Insider Threat Response System

## Overview

The Host-based Intrusion Prevention System (HIPS) monitors device behavior in real-time using AI models (XGBoost + Random Forest) to detect insider threats. When suspicious activity is detected, the system evaluates the threat level and takes automated response actions — including **real OS-level firewall blocking** in Live mode.

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
| **MEDIUM** | >= 0.70 | Temporary network restriction via firewall (LIVE mode) |
| **CRITICAL** | >= 0.90 | Full host network isolation via firewall (LIVE mode) |

### 4. Response Actions by Activity Type

| Activity Type | LOW Response | MEDIUM Response | CRITICAL Response |
|--------------|-------------|-----------------|-------------------|
| **FILE** | Log access | Read-only Enforcement + Firewall | Network Isolation + Firewall |
| **EMAIL** | Flag for review | Quarantine + Firewall | Network Isolation + Firewall |
| **HTTP** | Log traffic | Connection Reset + Firewall | Network Isolation + Firewall |

---

## Operating Modes

### Test Mode (Default: ON)
- All actions are **logged only** — no real OS-level changes
- Safe for testing and evaluation
- Toggle from: **Controls page -> Host Prevention -> Test Mode / Live Mode**

### Live Mode — Real Firewall Blocking
- When threat level reaches **MEDIUM or CRITICAL**, the system executes **real Windows Firewall rules** to block the host's network access
- Uses `netsh advfirewall firewall` to add inbound block rules
- Rule naming pattern: `IPS_HOST_BLOCK_{ip_address}`
- **Requires running backend as Administrator on Windows**

---

## How to Verify Prevention Actually Works

### 1. Check Firewall Rules (Command Line Proof)
```cmd
netsh advfirewall firewall show rule name=all | findstr IPS_HOST_BLOCK
```
This shows all firewall rules created by the host prevention system.

### 2. Check via API
```
GET /api/prevention/host/verify
```
Returns a list of all `IPS_HOST_BLOCK_*` rules currently active in Windows Firewall.

### 3. Check Blocked Hosts
```
GET /api/prevention/host/blocked
```
Returns in-memory list of blocked host IPs with timestamps.

### 4. Prevention Log File
Located at: `project/backend/instance/prevention_actions.log`
Each line is a JSON record with:
- `event`: "firewall_block_applied" / "firewall_block_removed"
- `host_ip`: the blocked IP
- `rule_name`: the exact Windows Firewall rule name
- `proof`: command to verify the rule exists

---

## Manual Controls

### Block a Host IP
```
POST /api/prevention/host/block
Body: {"ip": "192.168.1.100", "host_name": "laptop-01"}
```

### Unblock a Host IP
```
POST /api/prevention/host/unblock
Body: {"ip": "192.168.1.100"}
```

### Clear All Blocks
```
POST /api/prevention/host/clear-all
```

### Switch Mode
```
POST /api/prevention/mode
Body: {"test_mode": false}  // switches to LIVE mode
```

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
| `/api/prevention/thresholds` | GET/POST | Get or update threshold values |
| `/api/prevention/mode` | POST | Switch between TEST and LIVE mode |
| `/api/prevention/logs` | GET | Recent prevention action logs |
| `/api/prevention/host/block` | POST | Manually block a host IP |
| `/api/prevention/host/unblock` | POST | Remove a host IP block |
| `/api/prevention/host/blocked` | GET | List all currently blocked hosts |
| `/api/prevention/host/verify` | GET | Verify firewall rules exist in OS |
| `/api/prevention/host/clear-all` | POST | Remove all host firewall rules |

---

## Architecture Diagram

```
[Host Agent] -> collects 15 features every 10s
      |
[Backend API] -> /api/agent/host-report
      |
[AI Models] -> XGBoost + RandomForest predict threat probability
      |
[Response Orchestrator] -> evaluates against thresholds
      |
[TEST mode] -> Log only (no OS changes)
[LIVE mode] -> Execute Windows Firewall rules
      |
[Firewall] -> netsh advfirewall: IPS_HOST_BLOCK_{ip}
      |
[Prevention Logs] -> JSON log file + API + UI
```

---

## Security Notes

- **Hardware Fingerprint**: Each device generates a unique HMAC-SHA256 fingerprint from hardware identifiers. Copying the agent to another machine will be detected and rejected.
- **Admin Approval**: New devices must be approved by admin before they can report data.
- **Clone Detection**: If someone clones an agent, the different hardware fingerprint triggers automatic rejection.
- **Administrator Required**: Firewall blocking only works when backend runs as Administrator.
