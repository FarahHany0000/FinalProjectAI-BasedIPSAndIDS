# IDS Host Agent — Deployment Guide
# دليل تثبيت عميل المراقبة

## Quick Start / البداية السريعة

### 1. Install / التثبيت
```bash
python install_agent.py
```

### 2. Configure / الإعداد
Edit `config.ini`:
- **server_host**: Set to `AUTO` for automatic discovery, or the server's IP
- **agent_key**: Must match the server's AGENT_KEY (ask your admin)

### 3. Run / التشغيل
```bash
python host_agent.py
```

## What Happens / ماذا يحدث

1. **First Run**: The agent generates a unique hardware fingerprint
2. **Registration**: Sends fingerprint to the IDS server
3. **Approval**: Admin must approve this device in the dashboard
4. **Monitoring**: Once approved, sends system metrics every 10 seconds

## Requirements / المتطلبات
- Python 3.8+
- Network connection to the IDS server (same network/subnet)
- psutil, requests (auto-installed)

## Security / الأمان
- Each machine has a unique hardware fingerprint (CPU + MAC + disk serial)
- Copying agent files to another machine will NOT work (fingerprint mismatch)
- New devices require admin approval before monitoring begins
- All communication uses authentication headers

## Troubleshooting / حل المشاكل

| Problem | Solution |
|---------|----------|
| "Auto-discovery failed" | Set server_host manually in config.ini |
| "Bad agent key" | Check agent_key matches the server |
| "Pending approval" | Ask admin to approve in the Agents page |
| "Hardware mismatch" | Agent was copied — run on the original machine |
| Can't connect | Check firewall allows port 5000 (TCP) and 5001 (UDP) |

## Stopping the Agent / إيقاف العميل
Press `Ctrl+C` — the agent stops gracefully.
