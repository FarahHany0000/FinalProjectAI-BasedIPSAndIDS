# 🔒 Complete Setup & Run Guide — AI-Based IDS/IPS System

This guide covers the **complete end-to-end setup** for the integrated IDS/IPS system with both **host-based** and **network-based** attack detection.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                     YOUR WINDOWS PC                              │
│                                                                  │
│  ┌─ HOST AGENT ─────────────────────── NETWORK SENSOR ─────┐   │
│  │  Collects 15 host features    Sniffs packets on VMnet1  │   │
│  │  (logins, files, devices)     Extracts 48 features      │   │
│  │  Every 10 seconds             Sliding 10-packet windows │   │
│  │  (sampled @ 5s resolution)    Real-time (or PCAP)       │   │
│  └────────────┬──────────────────────────┬─────────────────┘   │
│               │                          │                       │
│               │ POST features            │ Detects:             │
│               │ (encrypted)              │ - PortScan           │
│               │                          │ - SSHBrute           │
│               ▼                          │ - FTPBrute           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │          BACKEND (Flask + SQLite + Socket.IO)            │   │
│  │                  :5000                                   │   │
│  │                                                          │   │
│  │  ✅ XGBoost (15 features) → Detect host intrusions      │   │
│  │  ✅ XGBoost (48 features) → Detect network attacks      │   │
│  │  ✅ Alert database (mixed host + network)               │   │
│  │  ✅ Real-time Socket.IO events to frontend              │   │
│  │  ✅ Auto-start network sensor on startup                │   │
│  └────────────────────┬─────────────────────────────────────┘   │
│                       │ Alerts + Stats                           │
│                       │ (JSON)                                   │
│                       ▼                                           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │       FRONTEND (React + Vite) :5173                      │   │
│  │                                                          │   │
│  │  🎨 Dashboard: Live host + network alerts               │   │
│  │  📊 Alert log: Filter by source (host/network)          │   │
│  │  📈 Charts: Attack statistics by type                   │   │
│  │  👥 Agents: Registry of host & network sensors          │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    KALI VM (on VMnet1)                          │
│                                                                │
│  Launch attacks & verify detection:                           │
│  - nmap -sS <target>  (PortScan)                             │
│  - hydra -l admin -P wordlist ssh://<target>  (SSHBrute)     │
│  - hydra -l admin -P wordlist ftp://<target>  (FTPBrute)     │
│  - arpspoof -t <target> <gateway>  (ARPSpoof)                │
│  - hping3 -S -i u10 -p 80 <target>  (SYNFlood)              │
│                                                                │
└─────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

### Windows PC

1. **Python 3.10+** — https://python.org
2. **Node.js 18+** — https://nodejs.org
3. **Npcap** — https://npcap.com (for live packet capture)
   - ⚠️ **IMPORTANT**: Check "WinPcap API-compatible Mode" during installation
4. **Git** — Already have it

### Kali VM

- VMware/VirtualBox with Host-Only Network (VMnet1)
- Network tools: `nmap`, `hydra`, `hping3`, `arpspoof`, `arping`
  ```bash
  sudo apt update && sudo apt install -y nmap hydra hping3 dsniff
  ```

---

## Step-by-Step Setup

### Step 1: Check Your Network Interface Name

**On Windows PowerShell:**

```powershell
ipconfig
```

Find your VMnet1 adapter (e.g., "Realtek PCIe 2.5GbE Family Controller")

Update this in the network config:
```bash
# Edit: project/network_module/config/settings.py
DEFAULT_IFACE = "Your VMnet1 Adapter Name"
```

### Step 2: Install Python Dependencies

**Backend:**

```bash
cd "path/to/FinalProjectAI-BasedIPSAndIDS"
cd project

# Install backend requirements
pip install flask flask-cors python-socketio python-engineio
pip install sqlalchemy joblib xgboost scikit-learn
pip install requests scapy numpy pandas scipy

# Or from requirements file if it exists
# pip install -r requirements.txt
```

**Network Module:**

```bash
cd project
pip install -r network_module/requirements.txt
```

Output should show: ✅ scapy, numpy, pandas, scipy, xgboost installed

### Step 3: Install Node Dependencies (Frontend)

```bash
cd project/frontend
npm install
```

---

## Running the System

### ✅ Method 1: Run Everything Locally (RECOMMENDED FOR TESTING)

**Terminal 1 — Backend (Attack Detection Engine)**

```bash
cd project/backend
python -m flask --app app run
```

Expected output:
```
============================================================
  🔒 AI-Based IDS/IPS Backend Server
  📊 Model loaded:           True
  🌐 Network sensor:         ENABLED
  🔑 Agent key:              (default)
  ❤️ Heartbeat timeout:       30s
  📡 Listening on:           0.0.0.0:5000
============================================================
```

Network sensor should print:
```
[Sniffer] Started on interface: Realtek PCIe 2.5GbE Family Controller
[OK] Network sensor thread started (running in background)
```

**Terminal 2 — Frontend (Web UI)**

```bash
cd project/frontend
npm run dev
```

Expected output:
```
VITE v5.x.x  ready in xxx ms

➜  Local:   http://127.0.0.1:5173/
➜  press h + enter to show help
```

**Terminal 3 — Host Agent (Optional, for testing host detection)**

```bash
cd project/agents/host_agent
python host_agent.py
```

Expected output:
```
[Host Agent] Connecting to backend: http://127.0.0.1:5000
[Host Agent] ✅ Registered: agent_id=xxx
[Host Agent] Starting detection loop...
[Time] Prediction: Normal (prob=0.15)
```

### ✅ Access the System

**Web Dashboard:**
- 🌐 **URL:** http://localhost:5173
- 🔑 **Login:** admin / admin
- 📊 **You'll see:**
  - Real-time host + network alerts
  - Attack statistics by type
  - Agent registry
  - Alert timeline

**Backend API:**
- 📡 **URL:** http://localhost:5000
- 🔍 **Check status:**
  ```bash
  curl http://localhost:5000
  ```

---

## Testing Network Detection

### Test 1: Trigger an Attack from Kali

**On Kali VM:**

```bash
# Find target Windows IP on VMnet1
ip addr show eth0  # Look for inet address

# Port Scan (should trigger MEDIUM alert)
nmap -sS -T4 --top-ports 100 -Pn <Windows-IP>
```

**Expected in Backend Console:**
```
[NetworkSensor-1] Alert #42 sent: PortScan (conf=91.23%)
```

**Expected in Frontend:**
- New alert appears in Dashboard
- Alert log shows: "NetworkSensor-1 | PortScan | Medium | 🟡"

### Test 2: SSH Brute Force

**On Kali:**
```bash
# Prep userlist
echo -e "admin\nroot\nuser" > /tmp/users.txt
echo -e "password\n123456\npassw0rd" > /tmp/pass.txt

# Brute force (requires SSH enabled on Windows)
hydra -L /tmp/users.txt -P /tmp/pass.txt ssh://<Windows-IP> -t 4
```

**Expected Detection:**
- Alert: "SSHBrute | High | 🔴"
- Confidence: 95%+

### Test 3: SYN Flood

```bash
# SYN flood on port 80 (test attack)
sudo hping3 -S -i u10 -p 80 <Windows-IP>
```

**Expected Detection:**
- Alert: "SYNFlood | Critical | 🔴🔴"
- Confidence: 98%+
- ~1000+ packets in single window

---

## Environment Variables (Optional)

Control behavior without code changes:

```bash
# Disable network sensor if needed
export ENABLE_NETWORK_SENSOR=false

# Change heartbeat timeout (default: 30s)
export HEARTBEAT_TIMEOUT=60

# Custom agent key (security)
export AGENT_KEY=my-secret-key

# Run backend
python -m flask --app backend.app run
```

---

## Troubleshooting

### ❌ Backend fails to start: "Address already in use"

```bash
# Port 5000 is in use. Kill the process:
lsof -i :5000
kill -9 <PID>

# Or run on different port:
flask --app app run --port 5001
```

### ❌ Network sensor not starting: "Permission denied"

**Windows:**
- Run PowerShell / Command Prompt **as Administrator**
- Ensure Npcap is installed correctly
- Check network interface name: `ipconfig`

**Linux:**
- Add user to pcap group: `sudo usermod -aG pcap $USER`
- Or run as root: `sudo python app.py`

### ❌ Frontend can't connect to backend

Check:
1. Backend is running on `http://127.0.0.1:5000`
2. Frontend is running on `http://127.0.0.1:5173`
3. CORS is enabled (should be automatic)
4. Check browser console for errors

```bash
# Test backend API
curl http://127.0.0.1:5000/
# Should return JSON with service info
```

### ❌ Network sensor disabled: "Models not found"

The XGBoost model files are missing:
- `project/backend/ai_models/network_xgb/binary_model.json`
- `project/backend/ai_models/network_xgb/attack_model.json`

Currently disabled. When you train the models, copy them to these locations.

**Temporary fix:** Disable network sensor
```bash
export ENABLE_NETWORK_SENSOR=false
python -m flask --app backend.app run
```

### ❌ Host agent can't connect: "Connection refused"

```bash
# Make sure backend is running first
# Check if agent can reach backend
curl http://127.0.0.1:5000/api/agent/health

# Check host_agent config (connection settings)
cat project/agents/host_agent/config.ini
```

---

## Database Inspection

Check detected alerts:

```bash
# SQLite database location
project/backend/instance/ids.db

# Using sqlite3 CLI
sqlite3 project/backend/instance/ids.db

# Query alerts
SELECT * FROM alerts ORDER BY time DESC LIMIT 10;

# Query hosts
SELECT * FROM host ORDER BY last_seen DESC;

# Query agents
SELECT * FROM registered_agent;
```

---

## Key Files & Locations

| Component | Path | Purpose |
|-----------|------|---------|
| **Backend** | `project/backend/app.py` | Flask entry point |
| **Network Sensor** | `project/agents/network_sensor/` | Live capture agent |
| **Network Module** | `project/network_module/` | Packet parsing + feature extraction |
| **Models** | `project/backend/ai_models/` | XGBoost/RF pipelines |
| **Database** | `project/backend/instance/ids.db` | SQLite alerts + hosts |
| **Frontend** | `project/frontend/src/` | React components |
| **Host Agent** | `project/agents/host_agent/` | System behavior monitoring |

---

## Production Deployment (Optional Notes)

For a production environment:

1. **Use Gunicorn instead of Flask dev server:**
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:5000 "backend.app:create_app()"
   ```

2. **Use a real database (PostgreSQL, MySQL):**
   ```bash
   # Update DATABASE_URI environment variable
   export DATABASE_URI="postgresql://user:pass@localhost/ids_db"
   ```

3. **Enable HTTPS for production:**
   ```bash
   # Use SSL certificates (Let's Encrypt, self-signed, etc.)
   flask --app app run --ssl-context=adhoc  # Needs pyopenssl
   ```

4. **Network sensor permissions:**
   ```bash
   # Linux: Use capabilities instead of running as root
   sudo setcap cap_net_raw+ep /usr/bin/python3
   ```

5. **Configure firewall:**
   - Backend: 5000 (internal only)
   - Frontend: 5173 (dev) or 80/443 (production)
   - Agents: Outbound to backend

---

## Summary

**You now have a fully integrated AI-Based IDS/IPS system with:**

✅ **Host-based detection** — 15 features (logins, files, devices)
✅ **Network-based detection** — 48 features (packets, protocols, ports)
✅ **Real-time alerts** — Socket.IO dashboard updates
✅ **Multi-model inference** — XGBoost (primary) + Random Forest (secondary)
✅ **Dual sensor architecture** — Host agent + Network sensor
✅ **Alert database** — SQLite with filtering
✅ **Web dashboard** — React UI with live stats

---

## Next Steps

1. **Test on Kali VM** — Run attacks and verify detections
2. **Tune thresholds** — Adjust confidence limits in config.ini and settings.py
3. **Train custom models** — Use your network traffic data
4. **Deploy to production** — Use Gunicorn + PostgreSQL + HTTPS
5. **Monitor alerts** — Set up notifications (email, Slack, etc.)

---

**Questions?** Check the individual component READMEs:
- `project/backend/README.md` (if exists)
- `project/network_module/README.md`
- `project/agents/network_sensor/README.md`
- `project/frontend/README.md` (if exists)
