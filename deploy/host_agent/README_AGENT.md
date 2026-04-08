# IDS Host Agent — Deployment Package
# دليل تثبيت عميل المراقبة + محاكاة الهجوم

## 📦 What's in this Package / محتويات الحزمة

| File | Purpose / الوظيفة |
|------|----------|
| `host_agent.py` | Main monitoring agent — collects features & executes prevention |
| `alert_ui.py` | Modern security alert dialog (locks screen until admin password) |
| `host_attack_simulation.py` | Simulates insider threat attacks for testing |
| `config.ini` | Configuration (server IP, intervals, etc.) |
| `requirements.txt` | Python dependencies |
| `install_agent.py` | Automated setup script |

---

## 🚀 Quick Start (3 Steps) / البداية السريعة

### Step 1: Setup Virtual Environment / إنشاء بيئة افتراضية

**Option A — Automatic (recommended):**
```bash
cd host_agent
python install_agent.py
```

**Option B — Manual:**
```bash
cd host_agent

# Create virtual environment
python -m venv venv

# Activate it
venv\Scripts\activate          # Windows (CMD)
venv\Scripts\Activate.ps1      # Windows (PowerShell)

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Configure Server IP / تحديد عنوان السيرفر

Edit `config.ini`:
```ini
[agent]
server_host = AUTO          # AUTO = auto-discover on local network
; server_host = 192.168.1.5  # OR set exact IP of IDS server
server_port = 5000
agent_key = changeme
```

> **AUTO** works if the backend is running on the **same local network**.
> If on a different subnet, set the exact IP.

### Step 3: Run the Agent / تشغيل العميل

```bash
# Activate venv first (if not already active)
venv\Scripts\activate          # Windows

# Run the agent
python host_agent.py
```

**With explicit server IP:**
```bash
python host_agent.py --server 192.168.1.5:5000
```

You should see:
```
==================================================
  Host IDS Agent
  Host:     YOUR-PC-NAME (192.168.x.x)
  Agent ID: xxxxxxxx...
  Server:   http://192.168.1.5:5000/api/agent/host-report
  Window:   5s  |  Interval: 10s
  Press Ctrl+C to stop gracefully
==================================================
[HEARTBEAT] Server is UP (attempt 1)
[REGISTER] registered_new (approved: True)
[OK] Threat=Normal | Action=No Action | logons=0 pkts=50 files=3
```

---

## 🔒 How It Works / كيف يعمل

1. **Agent starts** → Generates a unique hardware fingerprint (CPU + MAC + disk serial)
2. **Registers** with the IDS backend server automatically
3. **Monitors** the machine every 10 seconds — collects:
   - File activity (new/modified files)
   - USB/removable device usage
   - Network connections
   - Login patterns
4. **Sends features** to the backend's AI model (XGBoost)
5. **If Attack detected** → The backend sends prevention commands:
   - 🔒 Lock screen
   - ⛔ Disable USB storage
   - ⚠️ Show security alert dialog (LOCKED until admin password)
   - 🔪 Kill suspicious processes
6. **Admin enters password** → Prevention resets, system returns to normal

### Alert Dialog Behavior:
- **Cannot be closed** without the admin password
- **Always on top** — stays above all windows
- **Centered on screen** — impossible to move behind other windows
- Default admin password: `admin123`

---

## 🎯 Testing with Attack Simulation / اختبار بمحاكاة الهجوم

```bash
# Make sure the agent is already running first!

# In a NEW terminal, activate venv:
venv\Scripts\activate

# Run attack simulation:
python host_attack_simulation.py
```

Choose from the attack menu:
| # | Attack Type | What It Does |
|---|-------------|-------------|
| 1 | 💾 Data Exfiltration | Copies files to virtual USB after hours |
| 2 | 🔥 IT Sabotage | Mass file creation/deletion |
| 3 | 🕵️ Espionage | IP theft + multi-PC network access |
| 4 | 💰 Fraud | Unauthorized financial data access |
| 5 | 🌐 System Abuse | Network flooding (mass connections) |
| 6 | ☠️ Combined Attack | All attacks at once (maximum intensity) |
| 7 | 👤 Normal Baseline | Normal activity (should NOT trigger detection) |

> **Safe Mode**: All attacks are simulated — files, USB drives, and changes are automatically cleaned up after each test.

---

## ⚙️ Configuration Reference / مرجع الإعدادات

### config.ini options:
```ini
[agent]
server_host = AUTO          # AUTO or IP address (e.g., 192.168.1.5)
server_port = 5000          # Backend port (default: 5000)
agent_key = changeme        # Must match backend's AGENT_KEY
interval = 10               # Seconds between detection cycles
window = 5                  # Feature collection window (seconds)
```

### Command-line overrides:
```bash
python host_agent.py --server 192.168.1.5:5000
python host_agent.py --server 10.0.0.1:5000
```

---

## 🔧 Troubleshooting / حل المشاكل

| Problem / المشكلة | Solution / الحل |
|---------|----------|
| `ConnectionError` | Check server IP and that port 5000 is open |
| `Pending approval` | Ask admin to approve the device in the dashboard |
| `Hardware mismatch` | Agent was copied to another machine — re-register |
| Alert keeps appearing | Enter admin password (`admin123`) in the dialog |
| `pip install` errors | Make sure you're in the venv: `venv\Scripts\activate` |
| pywebview not working | Run `pip install pywebview>=4.0` in the venv |
| Agent says "rejected" | Delete `.agent_id` file and restart — will re-register |

---

## 🛑 Stopping the Agent / إيقاف العميل
Press `Ctrl+C` — the agent stops gracefully and resets all prevention (USB re-enabled, etc.)

---

## 📋 Requirements / المتطلبات
- **Python 3.8+** (tested with 3.12)
- **Windows 10/11** (for prevention features: USB disable, screen lock)
- Network connection to the IDS backend server
- Dependencies (auto-installed): `psutil`, `requests`, `pywebview`

---

## 🔐 Security Notes / ملاحظات أمنية
- Each machine gets a **unique hardware fingerprint** — copying files to another machine won't work
- The `.agent_id` file is generated on first run — don't copy it between machines
- Admin password is set in the backend (default: `admin123`)
- Agent key must match between `config.ini` and the backend server
