# IDS Host Agent — Deployment Package

## 📦 Package Contents

| File | Description |
|------|-------------|
| `host_agent.py` | Main monitoring agent — collects features and sends them to the server |
| `alert_ui.py` | Security alert dialog (locks screen until admin password is entered) |
| `host_attack_simulation.py` | Attack simulation for testing (6 different attack types) |
| `config.ini` | Server connection settings |
| `requirements.txt` | Python dependencies |
| `install_agent.py` | Automated setup script |

---

## 🚀 Quick Start (3 Steps)

### Step 1: Install the Environment

**Open CMD or PowerShell in the `host_agent` folder and run:**

```bash
python install_agent.py
```

This will automatically create a virtual environment and install all dependencies.

**Or install manually:**
```bash
cd host_agent
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Step 2: Configure the Server IP

**Important:** Open `config.ini` and set `server_host` to the IP address of the server machine:

```ini
[agent]
server_host = 192.168.1.6       ; <-- Put the server IP here
server_port = 5000
agent_key = changeme
```

**How to find the server IP:**
- On the server machine (where the Backend is running): open CMD and type `ipconfig`
- Copy the IPv4 Address (e.g. `192.168.1.6`)
- If both machines are on the same network, you can leave `AUTO` and it will auto-discover

### Step 3: Run the Agent

```bash
venv\Scripts\activate
python host_agent.py
```

**Or specify the server directly:**
```bash
python host_agent.py --server 192.168.1.6:5000
```

**If everything is working correctly, you should see:**
```
==================================================
  Host IDS Agent
  Host:     PC-NAME (192.168.x.x)
  Agent ID: xxxxxxxx...
  Server:   http://192.168.1.6:5000/api/agent/host-report
  Window:   5s  |  Interval: 10s
==================================================
[HEARTBEAT] Server is UP (attempt 1)
[REGISTER] registered_new (approved: True)
[OK] Threat=Normal | Action=No Action | logons=0 pkts=50 files=3
```

---

## 🌐 Connecting Devices Together (Important!)

### On the Server Machine (your machine):
1. Start the Backend: `python app.py` (from `project/backend` folder)
2. Start the Frontend: `npm run dev` (from `project/frontend` folder)
3. Find your IP: run `ipconfig` in CMD → copy the IPv4 Address

### On the Client Machine (target):
1. Copy the entire `host_agent` folder to the target machine (via USB or network share)
2. Run `python install_agent.py`
3. Edit `config.ini` → set the server's IP address
4. Run `python host_agent.py`

### Connection Requirements:
- **Both machines must be on the same network** (same router / hotspot / LAN)
- **Port 5000 must be open** on the server machine
- If the firewall is blocking it, open Port 5000:
  ```bash
  netsh advfirewall firewall add rule name="IDS Backend" dir=in action=allow protocol=TCP localport=5000
  ```

### Quick Test Without a Router:
1. Enable **Mobile Hotspot** on your machine (Settings → Mobile Hotspot)
2. Connect the other machine to your hotspot
3. Use the hotspot IP (usually `192.168.137.1`)

---

## 🔒 How the Agent Works

1. **First run** → Generates a unique Hardware Fingerprint (CPU + MAC + Disk Serial)
2. **Registers** with the IDS backend server automatically
3. **Every 10 seconds** — collects data from the machine:
   - File activity (new/modified files)
   - USB / removable device usage
   - Network connections
   - Login patterns and timing
4. **Sends features** to the AI model (XGBoost) on the server
5. **If an attack is detected** → The server sends prevention commands:
   - 🔒 Lock screen
   - ⛔ Disable USB storage
   - ⚠️ Show security alert dialog (requires admin password to close)
   - 🔪 Kill suspicious processes
6. **Admin enters password** → Everything returns to normal

### Alert Dialog Behavior:
- **Cannot be closed** without the admin password
- **Always on top** — stays above all windows
- **Centered on screen** — cannot be moved
- Default admin password: `admin123`

---

## 🎯 Testing with Attack Simulation

**The agent MUST be running before starting the simulation!**

Open a new terminal and run:
```bash
venv\Scripts\activate
python host_attack_simulation.py
```

### Available Attacks:
| # | Attack Type | Description |
|---|-------------|-------------|
| 1 | 💾 Data Exfiltration | Copies files to a virtual USB drive |
| 2 | 🔥 IT Sabotage | Mass file creation/deletion |
| 3 | 🕵️ Espionage | IP theft + multi-PC network access |
| 4 | 💰 Fraud | Unauthorized financial data access |
| 5 | 🌐 System Abuse | Network flooding (mass connections) |
| 6 | ☠️ Combined Attack | All attacks at once (maximum intensity) |
| 7 | 👤 Normal Baseline | Normal activity (should NOT trigger detection) |

> **Safe Mode**: All attacks are simulated — files, USB drives, and changes are automatically cleaned up after each test.

---

## ⚙️ Configuration Reference

### config.ini:
```ini
[agent]
server_host = 192.168.1.6   ; Server IP (or AUTO for auto-discovery)
server_port = 5000           ; Server port (fixed)
agent_key = changeme         ; Authentication key (must match the server)
interval = 10                ; Seconds between each detection cycle
window = 5                   ; Feature collection window (seconds)
```

### Command-line Overrides:
```bash
python host_agent.py --server 192.168.1.6:5000    # Specify server directly
python host_agent.py --interval 5                   # Scan every 5 seconds
```

---

## 🔧 Troubleshooting

| Problem | Solution |
|---------|----------|
| `ConnectionError` | Check the server IP and make sure Port 5000 is open |
| `Pending approval` | The admin must approve the device from the Dashboard |
| Alert keeps appearing (false positive) | Enter the admin password: `admin123` |
| `pip install` errors | Make sure you're in the venv: `venv\Scripts\activate` |
| pywebview not working | Run: `pip install pywebview>=4.0` |
| Agent says `rejected` | Delete the `.agent_id` file and restart the agent |
| Device not showing in Dashboard | Make sure both machines are on the same network |
| Agent can't find server (AUTO) | Set the exact IP in `config.ini` instead of AUTO |

---

## 🛑 Stopping the Agent
Press `Ctrl+C` — the agent stops gracefully and resets all prevention actions (re-enables USB, etc.)

---

## 📋 Requirements
- **Python 3.8+** (tested with 3.12)
- **Windows 10/11**
- Network connection to the IDS backend server
- Dependencies (auto-installed): `psutil`, `requests`, `pywebview`

---

## 🔐 Security Notes
- Each machine generates a **unique hardware fingerprint** — copying files to another machine won't reuse the same identity
- The `.agent_id` file is generated on first run — **do NOT copy it** between machines
- Default admin password: `admin123`
- The `agent_key` in `config.ini` must match the server's AGENT_KEY
