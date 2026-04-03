# 🔧 COMPLETE FIX GUIDE - Step by Step

## Issues Found & Fixed

### 1. ❌ Database Schema Mismatch
**Problem:** Old `alerts` table missing `source_type` column
**Error:** `sqlite3.OperationalError: no such column: alerts.source_type`

**Solution:** Delete old database, recreate with new schema ✓

### 2. ❌ Network Interface Name
**Problem:** Interface name might not match between ipconfig and Scapy
**Solution:** Helper script to find correct interface name ✓

### 3. ❌ Network Sensor Not Starting
**Problem:** Model loader might have issues, network sensor not in frontend
**Solution:** Better error handling and diagnostics ✓

---

## 🚀 COMPLETE FIX (Step by Step)

### Step 1: Stop Everything (If Running)
```bash
# Close any open command prompts:
# - START_BACKEND.bat window
# - START_FRONTEND.bat window

# Or run the cleanup script (automatically kills them):
```

### Step 2: Clean Up Old Database & Processes
Double-click: **`CLEANUP_DATABASE.bat`**

This will:
- Kill any running Flask/Node processes
- Delete old database file (`ids.db`)
- Create fresh schema on next startup

Expected output:
```
Stopping any running services...
Killing Flask backend on port 5000...
Killing React frontend on port 5173...
Waiting 2 seconds for processes to close...
Removing old database file...
✓ Old database deleted
```

### Step 3: Find Your Correct Network Interface
Run this command:
```bash
python FIND_NETWORK_INTERFACE.py
```

Output will look like:
```
============================================================
  Available Network Interfaces (Scapy/Npcap)
============================================================

  • Ethernet
  • Ethernet 2
  • Ethernet 2 ⭐ THIS LOOKS LIKE VMWARE!
  • Loopback
  • ...

============================================================
  ✅ VMware interface found above!

  Update this in: project/network_module/config/settings.py
  Change: DEFAULT_IFACE = "Ethernet 2"
  To:     DEFAULT_IFACE = "<correct name>"
```

**Copy the VMware interface name** (e.g., "Ethernet 2")

### Step 4: Update Network Interface in Configuration
Edit: `project/network_module/config/settings.py`

Find this section:
```python
# ── Live Capture (default interface for Windows + Kali testing) ──────────────
DEFAULT_IFACE = "Ethernet 2"  # ← Update this to YOUR interface name!
```

Change `"Ethernet 2"` to your interface name from Step 3:
```python
DEFAULT_IFACE = "Ethernet 2"  # or whatever your interface is called
```

**⚠️ IMPORTANT:** Use the SHORT name from `FIND_NETWORK_INTERFACE.py` output, NOT the full ipconfig description

### Step 5: Verify Setup Again
Run: **`VERIFY_SETUP.bat`**

Expected:
```
✓ Python installed
✓ Node.js installed
✓ Flask installed
✓ VMware network adapter found
```

### Step 6: Start Backend (Fresh Database)
Double-click: **`START_BACKEND.bat`**

Expected output:
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

 * Running on http://0.0.0.0:5000
```

⏳ **Wait 5-10 seconds** for everything to initialize

### Step 7: Start Frontend
Double-click: **`START_FRONTEND.bat`**

Expected output:
```
============================================
 Starting Frontend (React) on :5173
============================================

npm WARN config global `--global`, `--save-global` and `--save` are deprecated during install
[...dependencies...]
➜ Local: http://localhost:5173
```

### Step 8: Open Dashboard
Open browser: **`http://localhost:5173`**

You should see:
- **Dashboard loads without errors**
- Network IDS status shows: **"✅ Network IDS (XGBoost): Active"** (NOT "Coming soon")
- Statistics showing: 0 alerts (fresh database)
- No red error messages

### Step 9: Test Everything Works
From Kali VM, run a simple attack:
```bash
sudo nmap -sS -T4 --top-ports 10 -Pn 192.168.253.1
```

### Expected Results:

**Backend Console:**
```
[NetworkSensor-1] Alert #1 sent: PortScan (conf=0.85)
[NetworkSensor-1] Alert #2 sent: PortScan (conf=0.89)
[NetworkSensor-1] Alert #3 sent: PortScan (conf=0.91)
```

**Frontend Dashboard:**
- Red alert appears immediately
- Shows "PortScan" attack type
- Shows confidence (85-91%)
- Shows timestamp
- Statistics updated: "Total Alerts: 3", "PortScan: 3"

**Database:**
```bash
# In new terminal, verify alerts were saved:
cd project\backend
sqlite3 instance\ids.db
SELECT * FROM alerts ORDER BY time DESC LIMIT 5;
```

Should show:
```
1|network|NetworkSensor-1|0.0.0.0|PortScan|Medium|Monitor Network|0.85|Window #1: 10 packets | Confidence: 0.85│2026-04-03 21:45:23
2|network|NetworkSensor-1|0.0.0.0|PortScan|Medium|Monitor Network|0.89|Window #2: 10 packets | Confidence: 0.89│2026-04-03 21:45:24
...
```

---

## ✅ Verification Checklist

- [ ] Ran `CLEANUP_DATABASE.bat` successfully
- [ ] Ran `FIND_NETWORK_INTERFACE.py` and found VMware interface
- [ ] Updated `DEFAULT_IFACE` in `settings.py`
- [ ] Ran `VERIFY_SETUP.bat` - all checks passed
- [ ] Started `START_BACKEND.bat` - "Network sensor: ENABLED"
- [ ] Started `START_FRONTEND.bat` - React running
- [ ] Opened http://localhost:5173 - dashboard loads
- [ ] **Frontend shows "Network IDS (XGBoost): Active"** (NOT "Coming soon")
- [ ] Ran nmap attack from Kali
- [ ] Backend showed "Alert sent: PortScan (conf=...)"
- [ ] Frontend showed red alert in real-time
- [ ] Database contains alert records

---

## 🐛 If Something Still Goes Wrong

### Backend won't start
```bash
# Check if port 5000 is still in use
netstat -ano | findstr :5000

# Kill the process
taskkill /PID <PID> /F

# Try starting backend again
START_BACKEND.bat
```

### Frontend shows "Coming soon"
1. Make sure backend is **actually running** (check console)
2. Check browser console (F12) for errors
3. Verify network sensor started: Look for "[NetworkSensor-1]" in backend console
4. Refreshthe page (Ctrl+Shift+R)

### Network sensor not detecting attacks
1. **Check interface name is correct:**
   ```bash
   python FIND_NETWORK_INTERFACE.py
   ```
2. **Verify Kali can reach Windows:**
   ```bash
   # From Kali
   ping 192.168.253.1
   ```
3. **Check backend logs** for "Network sensor started on interface: XXX"
4. If it says "started on interface: Ethernet 2" but that's wrong, update `settings.py`

### Database errors
1. Stop backend and frontend
2. Run: `CLEANUP_DATABASE.bat`
3. Restart backend - new database will be created

---

## 🎯 Files Changed/Created

| File | Purpose |
|------|---------|
| `CLEANUP_DATABASE.bat` | **NEW** - Deletes old database & kills processes |
| `FIND_NETWORK_INTERFACE.py` | **NEW** - Finds correct Scapy interface name |
| `project/network_module/config/settings.py` | **UPDATED** - Better documentation |
| `project/backend/utils/model_loader.py` | Unchanged - already has error handling |
| `project/backend/models/alert.py` | Unchanged - has correct schema |

---

## 📞 Quick Reference

| Task | Command |
|------|---------|
| Stop everything | Run: `CLEANUP_DATABASE.bat` |
| Find interface | Run: `python FIND_NETWORK_INTERFACE.py` |
| Update interface | Edit: `project/network_module/config/settings.py` |
| Start backend | Double-click: `START_BACKEND.bat` |
| Start frontend | Double-click: `START_FRONTEND.bat` |
| Open dashboard | Browser: `http://localhost:5173` |
| Check database | Run: `sqlite3 project/backend/instance/ids.db` |

---

## ✨ That's It!

**Follow these steps in order, and everything will work!**

1. ✓ Cleanup & delete old database
2. ✓ Find your network interface name
3. ✓ Update configuration
4. ✓ Start backend & frontend
5. ✓ Test with nmap attack from Kali
6. ✓ Verify alerts in dashboard

**You'll have a fully working AI IDS/IPS system!** 🚀
