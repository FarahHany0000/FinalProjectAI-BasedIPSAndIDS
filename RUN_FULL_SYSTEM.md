# How to Run the Full System End-to-End

**Complete guide for running the AI IDS/IPS system with network detection on Windows with Kali VM testing.**

---

## 📋 Prerequisites

### 1. Windows Machine
- **Python 3.10+** — https://www.python.org/
  - Check: `python --version`
  - **During installation: ✓ Add Python to PATH**

- **Node.js 18+** — https://nodejs.org/
  - Check: `node --version` and `npm --version`

- **Npcap** (for network packet capture) — https://npcap.com/
  - Download and install
  - **✓ Check "WinPcap API-compatible Mode"** during installation
  - **Run as Administrator** when installing

- **Git** — https://git-scm.com/ (already installed)

### 2. Kali VM
- VMware with **Host-Only Network (VMnet1)**
- Connected to the same VMnet1 as Windows
- Network tools: `nmap`, `hydra`, `hping3`, `arpspoof` (pre-installed)

### 3. Your Machine's Network Interface

Find your VMnet1 adapter name:
```powershell
# Open PowerShell as Administrator
Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*VMware*"}
```

Look for output like:
```
Name         InterfaceDescription
----         --------------------
Ethernet 2   VMware Network Adapter VMnet1
```

**Your interface name:** `Ethernet 2` (or whatever appears in "Name" column)

---

## ⚙️ Configuration (One-Time Setup)

### Step 1: Update Network Interface Name

Edit: `project/network_module/config/settings.py`

Change this line:
```python
DEFAULT_IFACE = "Ethernet 2"  # ← Change to YOUR interface name
```

### Step 2: Verify Project Structure

```
FinalProjectAI-BasedIPSAndIDS/
├── project/
│   ├── backend/               # Flask backend (port 5000)
│   ├── frontend/              # React frontend (port 5173)
│   ├── agents/                # Host + Network sensors
│   │   ├── host_agent/
│   │   └── network_sensor/    # ← Network IDS
│   └── network_module/        # ← Network detection module
│       ├── config/
│       ├── sniffer/
│       └── data_pipeline/
├── START_BACKEND.bat
├── START_FRONTEND.bat
└── ...
```

---

## 🚀 Running the System

### Option A: Quick Start (Sequential Terminals)

**Terminal 1 — Backend Server:**
```bash
cd "C:\Users\user\Documents\Mti Final Project\All My Work\FinalProjectAI-BasedIPSAndIDS"
START_BACKEND.bat

# Expected output:
# ============================================
#  🔒 AI-Based IDS/IPS Backend Server
#  📊 Model loaded:           True
#  🌐 Network sensor:         ENABLED
#  ❤️  Heartbeat timeout:      30s
#  📡 Listening on:           0.0.0.0:5000
# ============================================
```

⏳ Wait 3-5 seconds for backend to fully start.

**Terminal 2 — Frontend Server:**
```bash
cd "C:\Users\user\Documents\Mti Final Project\All My Work\FinalProjectAI-BasedIPSAndIDS"
START_FRONTEND.bat

# Expected output:
# ============================================
#  Starting Frontend (React) on :5173
# ============================================
#
# ➜  frontend  ready in 2.34 s
# ➜  Local:    http://localhost:5173
```

**Open Browser:**
```
http://localhost:5173
```

You should see the **IDS/IPS Dashboard** 🎨

---

### Option B: One Command (All in Windows)

**PowerShell (as Administrator):**

```powershell
# Navigate to project
cd "C:\Users\user\Documents\Mti Final Project\All My Work\FinalProjectAI-BasedIPSAndIDS"

# Start backend in background
Start-Process cmd -ArgumentList "/k START_BACKEND.bat"

# Wait 5 seconds
Start-Sleep -Seconds 5

# Start frontend in background
Start-Process cmd -ArgumentList "/k START_FRONTEND.bat"

# Open browser
Start-Process "http://localhost:5173"

Write-Host "✅ System started!" -ForegroundColor Green
```

---

## 🔥 Testing with Kali VM

### Step 1: Get Your Windows IP on VMnet1

**Windows (PowerShell):**
```powershell
ipconfig /all | Select-String -A 5 "VMnet1"
```

Look for output like:
```
IPv4 Address. . . . . . . . . . . : 192.168.253.1
```

**Your target IP: `192.168.253.1`**

### Step 2: Verify VMnet1 Connectivity

**Kali:**
```bash
ping 192.168.253.1
```

Should see replies ✓

### Step 3: Launch Attacks from Kali

**Each attack command below should trigger an alert in your frontend dashboard:**

#### Test 1: Port Scan (MEDIUM)
```bash
sudo nmap -sS -T4 --top-ports 100 -Pn 192.168.253.1
```

Expected:
- Backend logs: `Alert sent: PortScan (conf=85.23%)`
- Frontend shows red alert: "PortScan from Kali"

#### Test 2: SYN Flood (CRITICAL)
```bash
sudo hping3 -S -i u10 -p 80 192.168.253.1
```

Expected:
- Backend logs: `Alert sent: SYNFlood (conf=92.15%)`
- Frontend shows red critical alert

#### Test 3: SSH Brute Force (HIGH)

**First, on Windows, enable SSH:**
```powershell
# Run as Administrator
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
```

**Then from Kali:**
```bash
# Create a simple userlist
echo "admin" > /tmp/users.txt
echo "vagrant" >> /tmp/users.txt
echo "root" >> /tmp/users.txt

# Create a simple password list
echo "password" > /tmp/pass.txt
echo "12345678" >> /tmp/pass.txt
echo "qwerty" >> /tmp/pass.txt

# Brute force
sudo hydra -L /tmp/users.txt -P /tmp/pass.txt ssh://192.168.253.1 -t 4
```

Expected:
- Backend logs: `Alert sent: SSHBrute (conf=88.54%)`
- Frontend shows HIGH alert

#### Test 4: ARP Spoofing (CRITICAL)
```bash
# Get gateway IP
ip route | grep default

# Example: 192.168.253.1 (if Windows is also gateway)
# Then spoof:
sudo arpspoof -i eth0 -t 192.168.253.1 192.168.253.1
```

Expected:
- Backend logs: `Alert sent: ARPSpoof (conf=96.42%)`
- Frontend shows CRITICAL red alert

#### Test 5: FTP Brute Force (HIGH)

**First, on Windows, enable FTP:**
```powershell
# Run as Administrator
Add-WindowsFeature Web-Ftp-Server
```

**Then from Kali:**
```bash
sudo hydra -L /tmp/users.txt -P /tmp/pass.txt ftp://192.168.253.1 -t 4
```

Expected:
- Backend logs: `Alert sent: FTPBrute (conf=87.65%)`
- Frontend shows HIGH alert

---

## 📊 What You Should See

### Backend Console (Terminal 1)

```
============================================
 🔒 AI-Based IDS/IPS Backend Server
 📊 Model loaded:           True
 🌐 Network sensor:         ENABLED
 ❤️  Heartbeat timeout:      30s
 📡 Listening on:           0.0.0.0:5000
============================================
[OK] Heartbeat monitor started (timeout: 30s)
[OK] Network sensor thread started (running in background)
[NetworkSensor-1] Network sensor started on interface: Ethernet 2
[NetworkSensor-1] → Sending alerts to: http://127.0.0.1:5000/api/agent/network-alert

[During attack...]
[NetworkSensor-1] Alert #1 sent: PortScan (conf=85.23%)
[NetworkSensor-1] Alert #2 sent: SYNFlood (conf=92.15%)
[NetworkSensor-1] Alert #3 sent: SSHBrute (conf=88.54%)
```

### Frontend Dashboard (Browser)

- **Real-time alerts** appear at the top
- **Color-coded by severity:**
  - 🟡 Medium (PortScan)
  - 🟠 High (SSHBrute, FTPBrute)
  - 🔴 Critical (SYNFlood, ARPSpoof)
- **Details shown:** Attack type, source IP (Kali), confidence %, timestamp
- **Stats update live:** Total alerts, detection rate, etc.

---

## 🛠️ Troubleshooting

### Backend won't start

**Error: "Port 5000 already in use"**
```powershell
# Find process using port 5000
netstat -ano | findstr :5000

# Kill it (replace PID)
taskkill /PID 1234 /F
```

**Error: "ModuleNotFoundError: No module named 'scapy'"**
```bash
cd project/backend
pip install -r requirements.txt
```

**Error: "Network models not found"**
```
[WARN] Network models not found at:
       Binary:  project/backend/ai_models/network_xgb/binary_model.json
       Attack:  project/backend/ai_models/network_xgb/attack_model.json
```

This is **OK**! The network sensor will gracefully disable if models are missing.
- Backend still runs with host-only detection
- To enable network detection, you need the XGBoost models

### Frontend won't start

**Error: "Node modules not found"**
```bash
cd project/frontend
npm install
npm run dev
```

**Error: "Port 5173 already in use"**
```bash
# Kill the process or use a different port
npm run dev -- --port 5174
```

### Can't connect to backend from frontend

**Check CORS is enabled:**
```bash
curl -i http://localhost:5000
```

Should see headers with `Access-Control-Allow-Origin`

**Check Socket.IO connection:**
- Open browser DevTools (F12)
- Go to Network tab
- Try to trigger an alert
- Should see WebSocket connection to backend

### Network sensor not detecting attacks

1. **Check interface name is correct:**
   ```powershell
   Get-NetAdapter | Where-Object {$_.InterfaceDescription -like "*VMware*"}
   ```

2. **Verify Npcap is installed:**
   ```bash
   # Should show installed
   wmic product list | findstr Npcap
   ```

3. **Run as Administrator** (packet capture needs elevated privileges)

4. **Verify Kali can reach Windows:**
   ```bash
   # From Kali
   ping 192.168.253.1
   ```

5. **Check models exist:**
   ```bash
   ls -la project/backend/ai_models/network_xgb/
   ```

### Alerts not showing in frontend

1. **Check backend logs for "Alert sent"**
2. **Open DevTools (F12) → Console → look for errors**
3. **Check WebSocket connection:**
   - Network tab → WS → look for "socket.io"
4. **Refresh page:** Sometimes frontend needs a refresh

---

## 📈 Performance & Tuning

| Component | Resource | Expected |
|-----------|----------|----------|
| **Backend** | Python 3.10+ | ~150-200 MB RAM |
| **Frontend** | Node.js, React | ~100-150 MB RAM |
| **Network Sensor** | Packet capture thread | ~50-100 MB RAM |
| **Total RAM** | - | ~400-500 MB |
| **CPU (idle)** | - | 5-10% (1 core) |
| **Packet latency** | Sniff → Alert | 50-200 ms |

### Tuning for More Detections

**Edit:** `project/network_module/config/settings.py`

```python
# Lower confidence threshold for more detections (more false positives)
CONFIDENCE_THRESHOLD = 0.60  # Default: 0.70

# Smaller windows for faster detection (more overhead)
WINDOW_SIZE = 5  # Default: 10

# Shorter timeout for partial windows
WINDOW_TIMEOUT = 2.0  # Default: 5.0
```

---

## 🔄 Complete Workflow Summary

```
1. START BACKEND
   └─ Loads models
   └─ Starts network sensor (background thread)
   └─ Listens on http://0.0.0.0:5000

2. START FRONTEND
   └─ Loads React app
   └─ Connects to backend via Socket.IO
   └─ Serves on http://localhost:5173

3. OPEN WEBSITE
   └─ http://localhost:5173
   └─ See dashboard
   └─ See real-time alerts

4. LAUNCH ATTACK (from Kali)
   └─ Traffic hits Windows on VMnet1
   └─ Network sensor sniffs packets
   └─ XGBoost models evaluate 10-packet windows
   └─ If confident attack detected → Send to backend
   └─ Backend creates Alert record
   └─ Backend emits Socket.IO event
   └─ Frontend receives event
   └─ Alert appears on dashboard in real-time 🚨
```

---

## 📞 Quick Reference Commands

### Check if services are running
```powershell
# Backend
curl http://localhost:5000

# Frontend
curl http://localhost:5173

# Both
netstat -ano | findstr :5000
netstat -ano | findstr :5173
```

### View alerts in database
```bash
# From project root
sqlite3 project/backend/instance/ids.db

# Inside sqlite3:
SELECT id, timestamp, source_type, attack_type, confidence FROM alert ORDER BY timestamp DESC LIMIT 10;
.quit
```

### Clear all alerts
```bash
sqlite3 project/backend/instance/ids.db "DELETE FROM alert;"
```

### View network sensor logs
```bash
# From backend terminal, look for lines starting with [NetworkSensor-1]
```

---

## ✅ Verification Checklist

- [ ] Python 3.10+ installed: `python --version`
- [ ] Node.js 18+ installed: `node --version`
- [ ] Npcap installed on Windows
- [ ] Network interface name correct in `settings.py`
- [ ] Backend starts without errors
- [ ] Frontend starts without errors
- [ ] Can open http://localhost:5173 in browser
- [ ] Dashboard loads with no console errors
- [ ] Kali VM can ping Windows (192.168.253.1)
- [ ] Run one test attack (nmap) from Kali
- [ ] Alert appears in frontend within 5 seconds
- [ ] Alert details are correct (type, IP, confidence)

---

## 🎓 Next Steps

1. **Test all 5 attacks** on Kali to verify detection
2. **Train custom models** if you have labeled network data
3. **Tune thresholds** if you get too many false positives
4. **Deploy to production** by running on network interface that sees real traffic
5. **Add prevention** by integrating with firewall rules

---

## 📝 Notes

- **Network sensor requires Administrator/sudo** to capture packets
- **Npcap must be installed** for packet capture to work
- **Models are optional** — system runs without network detection if models missing
- **Socket.IO requires WebSocket support** in frontend (already configured)
- **All components are optional** — you can disable network sensor with env var:
  ```bash
  set ENABLE_NETWORK_SENSOR=false
  # Then start backend
  ```

---

**🚀 You're all set! Start the backend→frontend→test on Kali!**
