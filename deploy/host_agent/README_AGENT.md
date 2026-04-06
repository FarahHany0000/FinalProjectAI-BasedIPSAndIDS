# IDS Host Agent + Attack Simulation — Deployment Guide
# دليل تثبيت عميل المراقبة + محاكاة الهجوم

## Quick Start / البداية السريعة

### 1. Install & Setup / التثبيت والإعداد
```bash
python install_agent.py
```
This automatically:
- Creates a virtual environment (venv)
- Installs dependencies (psutil, requests)
- No configuration needed — defaults work out of the box!

### 2. Run Agent / تشغيل العميل
```bash
# Activate venv first
venv\Scripts\activate          # Windows

# Run with your server IP
python host_agent.py --server <SERVER_IP>:5000
```

**Example:**
```bash
python host_agent.py --server 192.168.137.1:5000
```

> **Note:** Replace `<SERVER_IP>` with the IP of the machine running the IDS backend.
> The `agent_key` defaults to `changeme` on both server and agent — they match automatically.

### 3. Run Attack Simulation / محاكاة الهجوم
```bash
# Same venv — already has all dependencies
venv\Scripts\activate          # Windows

python attack_simulation.py --server <SERVER_IP>:5000
```
Then pick a scenario from the menu (1-7) to simulate different attack types.

**Example:**
```bash
python attack_simulation.py --server 192.168.137.1:5000
```

### 4. Manual venv setup (alternative)
```bash
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
python host_agent.py --server <SERVER_IP>:5000
```

## What Happens / ماذا يحدث

### Agent Flow:
1. **First Run**: The agent generates a unique hardware fingerprint
2. **Registration**: Sends fingerprint to the IDS server automatically
3. **Approval**: Admin approves this device in the dashboard (or auto-approved)
4. **Monitoring**: Once approved, sends system metrics every 10 seconds
5. **Prevention**: Polls for commands from backend, executes prevention actions

### Attack Simulation Flow:
1. **Pick scenario**: Choose from 7 CERT attack types (sabotage, espionage, fraud, etc.)
2. **Sends fake features**: Simulates malicious behavior patterns to the backend
3. **Backend detects**: ML model classifies as attack → queues prevention commands
4. **Agent executes**: Agent on the same machine picks up and executes prevention

### Admin Alert / تنبيه الأدمن:
When an attack is detected, the agent shows an alert dialog:
- Click **OK** — dismiss (lock screen may still trigger)
- Enter **admin password** + click **Admin Dismiss** — stops ALL prevention & resets
- Default admin password: `admin123`

## Requirements / المتطلبات
- Python 3.8+
- Network connection to the IDS server (same network/subnet)
- psutil, requests (auto-installed)

## Files / الملفات
| File | Purpose |
|------|---------|
| `host_agent.py` | Main agent — monitors & executes prevention |
| `attack_simulation.py` | Simulates attacks — tests the full pipeline |
| `config.ini` | Configuration (optional — CLI args override) |
| `requirements.txt` | Python dependencies |
| `install_agent.py` | Quick setup script |

## Security / الأمان
- Each machine has a unique hardware fingerprint (CPU + MAC + disk serial)
- Copying agent files to another machine will NOT work (fingerprint mismatch)
- New devices require admin approval before monitoring begins

## Troubleshooting / حل المشاكل

| Problem | Solution |
|---------|----------|
| Can't connect | Check the server IP and that port 5000 is open |
| "Pending approval" | Ask admin to approve in the Agents page |
| "Hardware mismatch" | Agent was copied — run on the original machine |
| Alert keeps repeating | Enter admin password in alert dialog to reset |

## Stopping the Agent / إيقاف العميل
Press `Ctrl+C` — the agent stops gracefully.
