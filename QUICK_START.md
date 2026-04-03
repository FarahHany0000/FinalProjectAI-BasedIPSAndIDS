# 🚀 Quick Start Guide

## One-Minute Setup

### 1️⃣ Verify Everything Works
```bash
cd "C:\Users\user\Documents\Mti Final Project\All My Work\FinalProjectAI-BasedIPSAndIDS"
VERIFY_SETUP.bat
```

**Expected:**
- ✓ Python 3.10+ installed
- ✓ Node.js 18+ installed
- ✓ Flask installed
- ✓ VMware network adapter found

---

## Running the System

### 👉 Option A: TWO Command Prompts (Simplest)

**Prompt 1 - Backend:**
```
START_BACKEND.bat

Expected output:
[OK] Network sensor thread started
[NetworkSensor-1] Network sensor started on interface: Ethernet 2
```

**Wait 5 seconds**, then...

**Prompt 2 - Frontend:**
```
START_FRONTEND.bat

Expected output:
➜ Local: http://localhost:5173
```

**Then open browser:**
```
http://localhost:5173
```

---

## 🔥 Test on Kali VM

### Get Windows IP (from Windows):
```powershell
ipconfig /all | Select-String "VMnet1" -A 5
```
Look for: `IPv4 Address . . . . . . . . . . . : 192.168.253.1`

### From Kali, launch any attack:
```bash
# Test PortScan
sudo nmap -sS -T4 --top-ports 100 -Pn 192.168.253.1

# Test SYNFlood
sudo hping3 -S -i u10 -p 80 192.168.253.1

# Test SSH Brute (if SSH enabled on Windows)
sudo hydra -l admin -P rockyou.txt ssh://192.168.253.1 -t 4
```

### Expected Result:

**Backend Console:**
```
[NetworkSensor-1] Alert #1 sent: PortScan (conf=85.23%)
```

**Frontend Dashboard:**
- 🔴 Red alert appears
- Shows attack type, confidence, timestamp
- Real-time update via WebSocket ✓

---

## 📖 Detailed Guide

See: **RUN_FULL_SYSTEM.md** in project root

Contains:
- Complete setup prerequisites
- Network interface configuration
- All 5 attack test cases
- Troubleshooting reference
- Performance tuning

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│              Kali VM (Attacker)                     │
│  nmap, hydra, hping3, arpspoof                      │
└──────────────────────┬──────────────────────────────┘
                       │ Attack traffic
                       ↓
         ┌─────────────────────────────────┐
         │  Windows (Defender)             │
         │  Ethernet 2 (VMnet1)            │
         │                                 │
         │  ┌───────────────────────────┐  │
         │  │ Network Sensor (Thread #1)│  │
         │  │ • Sniffs packets          │  │
         │  │ • 48 features per window  │  │
         │  │ • XGBoost models          │  │
         │  │ • → /api/ alert endpoint  │  │
         │  └────────────┬──────────────┘  │
         │               │ HTTP POST       │
         │  ┌────────────▼──────────────┐  │
         │  │ Flask Backend (:5000)     │  │
         │  │ • Receives alerts         │  │
         │  │ • Creates DB records      │  │
         │  │ • Emits Socket.IO events  │  │
         │  └────────────┬──────────────┘  │
         │               │ WebSocket       │
         │  ┌────────────▼──────────────┐  │
         │  │ React Frontend (:5173)    │  │
         │  │ • Real-time alerts        │  │
         │  │ • Color-coded severity    │  │
         │  │ • Statistics & logs       │  │
         │  └───────────────────────────┘  │
         └─────────────────────────────────┘
```

---

## ✅ What was integrated?

| Component | Status | Details |
|-----------|--------|---------|
| **Network Module** | ✅ Complete | Sniffer, parser, feature engineer, config |
| **Backend** | ✅ Complete | Auto-starts network sensor thread |
| **Frontend** | ✅ Complete | Receives alerts via Socket.IO |
| **Database** | ✅ Complete | Stores all alerts (host + network) |
| **Startup Scripts** | ✅ Complete | START_BACKEND.bat, START_FRONTEND.bat |
| **Documentation** | ✅ Complete | RUN_FULL_SYSTEM.md (300+ lines) |
| **Configuration** | ✅ Complete | VMnet1 interface, Kali testing ready |

---

## 🎯 Attack Types Detected

| Attack | Default Severity | Confidence |
|--------|------------------|------------|
| **PortScan** | Medium | XGBoost binary + attack models |
| **SSHBrute** | High | 10-packet sliding windows |
| **FTPBrute** | High | 48 behavioral features |
| **ARPSpoof** | Critical | Threshold: 0.70 (configurable) |
| **SYNFlood** | Critical | 2-stage hierarchical classification |

---

## 🔧 Configuration (if needed)

**Edit:** `project/network_module/config/settings.py`

```python
# Network interface (find from: ipconfig)
DEFAULT_IFACE = "Ethernet 2"

# Packets per sliding window
WINDOW_SIZE = 10

# Min confidence to trigger alert
CONFIDENCE_THRESHOLD = 0.70

# Attack classes (fixed 5)
ATTACK_CLASSES = ["ARPSpoof", "FTPBrute", "PortScan", "SSHBrute", "SYNFlood"]
```

---

## 📝 File Structure

```
FinalProjectAI-BasedIPSAndIDS/
├── START_BACKEND.bat          ← Click to start backend
├── START_FRONTEND.bat         ← Click to start frontend
├── VERIFY_SETUP.bat           ← Verify prerequisites
├── RUN_FULL_SYSTEM.md         ← Detailed guide
│
├── project/
│   ├── backend/               ← Flask server :5000
│   │   ├── app.py            ← Auto-starts network sensor
│   │   ├── routes/
│   │   │   └── agent.py      ← /api/agent/network-alert endpoint
│   │   ├── controllers/
│   │   │   └── network_alert_controller.py  ← Process detections
│   │   ├── models/
│   │   │   └── alert.py      ← Alert DB model
│   │   └── utils/
│   │       └── model_loader.py  ← Loads XGBoost models
│   │
│   ├── frontend/              ← React app :5173
│   │   └── (automatically shows network alerts)
│   │
│   ├── agents/
│   │   ├── host_agent/
│   │   └── network_sensor/    ← Sends alerts to backend
│   │
│   └── network_module/        ← Network IDS detection
│       ├── config/settings.py ← Configuration
│       ├── sniffer/           ← Packet capture
│       │   ├── packet_parser.py
│       │   ├── live_capture.py
│       │   └── pcap_replay.py
│       └── data_pipeline/
│           └── feature_engineer.py  ← 48 features
```

---

## 🐛 If Something Goes Wrong

### Backend won't start
```bash
# Check Python
python --version

# Check Flask
pip list | findstr flask

# Install dependencies
cd project/backend
pip install -r requirements.txt
```

### Frontend won't start
```bash
# Check Node
node --version
npm --version

# Install deps
cd project/frontend
npm install
npm run dev
```

### Network sensor not detecting
- Check interface name: `ipconfig /all` → look for VMnet1
- Update: `project/network_module/config/settings.py` → DEFAULT_IFACE
- Verify Npcap: https://npcap.com (if not installed)
- Run as Administrator

### Still having issues?
See **"Troubleshooting"** section in RUN_FULL_SYSTEM.md

---

## 🎓 Next Steps

1. **Run verification:** `VERIFY_SETUP.bat`
2. **Start backend:** `START_BACKEND.bat` (Terminal 1)
3. **Start frontend:** `START_FRONTEND.bat` (Terminal 2)
4. **Open browser:** http://localhost:5173
5. **Test attack from Kali:** `sudo nmap -sS 192.168.253.1`
6. **Verify alert appears** in dashboard
7. **Repeat with other attacks** (SYN flood, SSH brute, etc.)

---

## ✨ That's It!

Your AI IDS/IPS system is **fully integrated and ready to detect network attacks in real-time** 🚀

**Start with:** `START_BACKEND.bat` → `START_FRONTEND.bat` → Test on Kali!
