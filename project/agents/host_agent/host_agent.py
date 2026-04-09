# host_agent.py — Lightweight Host IDS Agent
# Deploy this file + config.ini + requirements.txt to each monitored device.
# Collects 15 CERT Insider Threat features via psutil, sends JSON to backend.
#
# Usage:
#   pip install -r requirements.txt
#   python host_agent.py                     (uses config.ini)
#   python host_agent.py --server 192.168.137.1:5000 --key mytoken
#
# Design:
#   - ONE outgoing connection to backend (port 5000 only)
#   - No DNS lookups to external services
#   - Reuses TCP connection via requests.Session (keep-alive)
#   - Minimal footprint: psutil + requests only
#   - Graceful shutdown on Ctrl+C
#   - Heartbeat: waits for backend before starting detection loop
#   - Unique agent_id: registers with backend to prove identity

import os
import sys
import time
import uuid
import signal
import socket
import string
import platform
import argparse
import configparser
import hashlib
import hmac
import json
import ctypes
import subprocess
import threading
import psutil
from datetime import datetime

try:
    import requests
except ImportError:
    print("[FATAL] 'requests' not installed. Run: pip install requests")
    sys.exit(1)

# ─────────────────────────────────────────────────────────
# Graceful Shutdown
# ─────────────────────────────────────────────────────────

_shutdown = False
_prevention_paused = False          # Admin dismissed alert → pause prevention
_alert_dialog_active = False        # Prevents double dialog spawning
_last_prevention = {}               # {cmd_type: timestamp} — cooldown tracker
_PREVENTION_COOLDOWN = 120          # seconds before same action can repeat
_ADMIN_PASSWORD = "admin123"        # Password to dismiss alert & reset prevention

# Backend info for alert dialog reporting (set in run_agent)
_backend_base_url = ""
_current_agent_id = ""
_current_host_name = ""


def _handle_signal(signum, frame):
    global _shutdown
    _shutdown = True
    print("\n[INFO] Shutdown signal received. Finishing current cycle...")


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)

# ─────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "server_host": "AUTO",            # Auto-discover server via UDP broadcast
    "server_port": "5000",
    "agent_key": "changeme",
    "interval": "10",                  # seconds between reports
    "window": "5",                     # seconds to sample disk/net deltas
    "endpoint": "/api/agent/host-report",
}


def load_config():
    """Load config from config.ini if present, then override with CLI args."""
    config = dict(DEFAULT_CONFIG)

    ini_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")
    if os.path.exists(ini_path):
        cp = configparser.ConfigParser()
        cp.read(ini_path)
        if cp.has_section("agent"):
            config.update(dict(cp.items("agent")))

    parser = argparse.ArgumentParser(description="Host IDS Agent")
    parser.add_argument("--server", help="Backend address host:port")
    parser.add_argument("--key", help="Agent authentication key")
    parser.add_argument("--interval", type=int, help="Seconds between reports")
    parser.add_argument("--window", type=int, help="Seconds to sample deltas")
    args = parser.parse_args()

    if args.server:
        if ":" in args.server:
            host, port = args.server.rsplit(":", 1)
            config["server_host"] = host
            config["server_port"] = port
        else:
            config["server_host"] = args.server
    if args.key:
        config["agent_key"] = args.key
    if args.interval:
        config["interval"] = str(args.interval)
    if args.window:
        config["window"] = str(args.window)

    # Auto-discovery: if server_host is "AUTO", try UDP broadcast
    if config["server_host"] in ("AUTO", "auto", "0.0.0.0"):
        discovered_host, discovered_port = discover_server()
        if discovered_host:
            config["server_host"] = discovered_host
            config["server_port"] = str(discovered_port)
        else:
            print("[CONFIG] Auto-discovery failed. Scanning network for server...")
            import requests as _req

            # Build smart fallback list: default gateway + common IPs + subnet scan
            fallback_ips = []

            # 1. Get the default gateway (most likely the server)
            try:
                import subprocess as _sp
                gw_result = _sp.run(["ipconfig"], capture_output=True, text=True, timeout=5)
                for line in gw_result.stdout.split("\n"):
                    if "Default Gateway" in line:
                        gw = line.split(":")[-1].strip()
                        if gw and gw not in fallback_ips:
                            fallback_ips.append(gw)
            except Exception:
                pass

            # 2. Scan the local subnet (e.g. if we're on 10.100.241.28, try .1-.254)
            try:
                my_ip = get_local_ip("8.8.8.8")
                if my_ip and my_ip != "127.0.0.1":
                    prefix = my_ip.rsplit(".", 1)[0]
                    # Try common server positions in subnet
                    for last_octet in (1, 2, 100, 200, 140, 28, 50):
                        candidate = f"{prefix}.{last_octet}"
                        if candidate != my_ip and candidate not in fallback_ips:
                            fallback_ips.append(candidate)
            except Exception:
                pass

            # 3. Common hotspot/router IPs
            for static_ip in ("192.168.137.1", "192.168.1.1", "192.168.0.1", "10.0.0.1"):
                if static_ip not in fallback_ips:
                    fallback_ips.append(static_ip)

            for fallback_ip in fallback_ips:
                try:
                    r = _req.get(f"http://{fallback_ip}:5000/api/hosts", timeout=2)
                    if r.status_code in (200, 401, 403):
                        config["server_host"] = fallback_ip
                        print(f"[CONFIG] Found server at {fallback_ip}:5000")
                        break
                except Exception:
                    continue
            else:
                print("[CONFIG] No server found. Please use: python host_agent.py --server <IP>:5000")

    return config


# ─────────────────────────────────────────────────────────
# Agent Identity — unique ID per device
# ─────────────────────────────────────────────────────────

AGENT_ID_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".agent_id")


def get_or_create_agent_id():
    """
    Load agent_id from .agent_id file, or generate a new UUID on first run.
    This ID is unique per device and persists across restarts.
    """
    if os.path.exists(AGENT_ID_FILE):
        with open(AGENT_ID_FILE, "r") as f:
            agent_id = f.read().strip()
            if agent_id:
                return agent_id

    # First run — generate new UUID
    agent_id = str(uuid.uuid4())
    with open(AGENT_ID_FILE, "w") as f:
        f.write(agent_id)
    print(f"[IDENTITY] New agent_id generated: {agent_id[:8]}...")
    return agent_id


# ─────────────────────────────────────────────────────────
# Hardware Fingerprint — unique per physical machine
# ─────────────────────────────────────────────────────────

def _get_hardware_fingerprint(agent_key):
    """
    Generate a hardware-bound fingerprint using HMAC-SHA256.
    Combines: CPU info + primary MAC address + disk serial (if available).
    Even if someone copies the agent files to another machine,
    the fingerprint will be different → server rejects it.
    """
    parts = []

    # CPU identifier
    try:
        parts.append(platform.processor() or platform.machine())
    except Exception:
        parts.append("unknown_cpu")

    # Primary MAC address (first non-loopback interface)
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == psutil.AF_LINK and addr.address and addr.address != "00:00:00:00:00:00":
                    parts.append(addr.address)
                    break
            if len(parts) > 1:
                break
    except Exception:
        parts.append("unknown_mac")

    # Machine unique ID (hostname + platform node as fallback)
    try:
        parts.append(platform.node())
    except Exception:
        parts.append("unknown_node")

    # Disk serial (Windows-specific, best effort)
    try:
        if platform.system() == "Windows":
            import subprocess
            result = subprocess.run(
                ["wmic", "diskdrive", "get", "serialnumber"],
                capture_output=True, text=True, timeout=5
            )
            serial = result.stdout.strip().split("\n")[-1].strip()
            if serial and serial != "SerialNumber":
                parts.append(serial)
    except Exception:
        pass

    # Combine and hash with agent_key
    raw = "|".join(parts)
    hw_id = hmac.new(
        agent_key.encode("utf-8"),
        raw.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return hw_id


# ─────────────────────────────────────────────────────────
# IP Detection (no external DNS, no noise)
# ─────────────────────────────────────────────────────────

def get_local_ip(server_host):
    """
    Get this machine's IP on the network facing the server.
    Uses a UDP socket pointed at the server (no actual packet sent).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((server_host, 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass

    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                return addr.address
    return "127.0.0.1"


# ─────────────────────────────────────────────────────────
# Server Auto-Discovery via UDP Broadcast
# ─────────────────────────────────────────────────────────

def discover_server(timeout=5, port=5001):
    """
    Send UDP broadcast 'IDS_DISCOVER' and wait for server response.
    Returns (host, port) if found, or (None, None) if not.
    Works on any network — home WiFi, mobile hotspot, any LAN.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(timeout)

        # Send broadcast
        s.sendto(b"IDS_DISCOVER", ("<broadcast>", port))
        print(f"[DISCOVERY] Sent broadcast on port {port}...")

        data, addr = s.recvfrom(1024)
        msg = data.decode("utf-8", errors="ignore").strip()

        if msg.startswith("IDS_SERVER:"):
            parts = msg.split(":")
            if len(parts) >= 3:
                server_host = parts[1]
                server_port = int(parts[2])
                print(f"[DISCOVERY] Found server at {server_host}:{server_port}")
                s.close()
                return server_host, server_port

        s.close()
    except socket.timeout:
        print("[DISCOVERY] No server responded to broadcast.")
    except Exception as e:
        print(f"[DISCOVERY] Error: {e}")

    return None, None


# ─────────────────────────────────────────────────────────
# Feature Collection (15 CERT Insider Threat features)
# ─────────────────────────────────────────────────────────

FEATURE_NAMES = [
    "total_logons",
    "avg_logon_hour",
    "std_logon_hour",
    "weekend_logons",
    "after_hours_logons",
    "unique_pcs_logon",
    "total_device_activities",
    "unique_pcs_device",
    "avg_device_hour",
    "after_hours_device",
    "total_file_activities",
    "unique_files",
    "unique_pcs_file",
    "avg_file_hour",
    "after_hours_files",
]


def _count_recent_files(max_age_seconds=300, max_scan_time=5):
    """
    Count files modified within the last N seconds in user home dirs.
    Caps scan time to avoid blocking on large directories.
    """
    home = os.path.expanduser("~")
    scan_dirs = [
        os.path.join(home, "Desktop"),
        os.path.join(home, "Downloads"),
        os.path.join(home, "Documents"),
    ]
    now_ts = time.time()
    deadline = now_ts + max_scan_time
    count = 0

    for scan_root in scan_dirs:
        if not os.path.exists(scan_root):
            continue
        for base, dirs, files in os.walk(scan_root):
            if time.time() > deadline:
                return count
            # Skip deep/hidden/large dirs that slow scanning and cause false positives
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                       ('node_modules', '__pycache__', '.git', 'venv', '.venv',
                        'AppData', '.cache', 'site-packages', 'dist', '.next',
                        '.nuxt', 'build', '.parcel-cache', '.angular')]
            for name in files:
                try:
                    path = os.path.join(base, name)
                    if now_ts - os.stat(path).st_mtime <= max_age_seconds:
                        count += 1
                except Exception:
                    pass
    return count


def _net_snapshot():
    """Capture current network counters + connection stats."""
    c = psutil.net_io_counters()
    conns = psutil.net_connections(kind='inet')
    return {
        "bytes_sent": c.bytes_sent,
        "bytes_recv": c.bytes_recv,
        "packets_sent": c.packets_sent,
        "packets_recv": c.packets_recv,
        "connections": len(conns),
        "established": sum(1 for x in conns if x.status == "ESTABLISHED"),
    }


# ─────────────────────────────────────────────────────────
# USB / Removable Device Monitoring
# ─────────────────────────────────────────────────────────

_known_drives = None      # Initialized on first call
_usb_event_log = []       # Timestamped USB events for reporting

# USB persistence: keep device weight active for multiple cycles after detection
_usb_last_detection_time = 0
_usb_cached_weight = 0
_USB_PERSIST_SECONDS = 15   # seconds to keep USB weight after detection (short bridge)

# Standard system drives to ignore (C: always present, etc.)
_SYSTEM_DRIVES = {"C:"}


def _get_all_drives():
    """Get all current drive letters using Windows kernel32 API."""
    if platform.system() != "Windows":
        return set()
    try:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        drives = set()
        for i in range(26):
            if bitmask & (1 << i):
                letter = chr(ord('A') + i)
                drives.add(f"{letter}:")
        return drives
    except Exception:
        return set()


def _get_drive_type(drive_letter):
    """
    Get drive type using Windows API.
    Returns: 0=Unknown, 1=NoRoot, 2=Removable, 3=Fixed, 4=Network, 5=CDROM, 6=RAMDisk
    """
    if platform.system() != "Windows":
        return 0
    try:
        return ctypes.windll.kernel32.GetDriveTypeW(f"{drive_letter}\\")
    except Exception:
        return 0


def _detect_drive_changes():
    """
    Detect new/removed drives since last check.
    Returns (new_count, new_drive_letters, removed_drive_letters).
    First call initializes baseline — returns 0 new drives.
    """
    global _known_drives
    current = _get_all_drives()

    if _known_drives is None:
        _known_drives = current
        return 0, set(), set()

    new_drives = current - _known_drives
    removed = _known_drives - current
    _known_drives = current

    ts = datetime.now().strftime("%H:%M:%S")
    for d in new_drives:
        dtype = _get_drive_type(d)
        type_name = {0: "Unknown", 1: "NoRoot", 2: "Removable", 3: "Fixed/Virtual",
                     4: "Network", 5: "CDROM", 6: "RAMDisk"}.get(dtype, "?")
        print(f"[{ts}] [USB-MONITOR] ⚠ New drive detected: {d}\\ (type={type_name})")
        _usb_event_log.append({"time": ts, "drive": d, "type": type_name, "event": "connected"})

    for d in removed:
        print(f"[{ts}] [USB-MONITOR] Drive removed: {d}\\")
        _usb_event_log.append({"time": ts, "drive": d, "event": "disconnected"})

    return len(new_drives), new_drives, removed


def _count_drive_files(drive_letter, max_files=5000, max_time=2):
    """Count files on a drive (for USB content assessment). Capped by time and count."""
    count = 0
    deadline = time.time() + max_time
    try:
        for root, dirs, files in os.walk(f"{drive_letter}\\"):
            if time.time() > deadline or count > max_files:
                break
            dirs[:] = [d for d in dirs if not d.startswith('.') and d != '$RECYCLE.BIN'
                       and d != 'System Volume Information']
            count += len(files)
    except (PermissionError, OSError):
        pass
    return count


# ─────────────────────────────────────────────────────────
# Prevention Actions — Executed locally on the host
# ─────────────────────────────────────────────────────────

# Whitelist of known safe system processes (never kill these)
_SAFE_PROCESSES = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "svchost.exe", "explorer.exe", "dwm.exe", "conhost.exe",
    "taskhostw.exe", "runtimebroker.exe", "searchhost.exe", "startmenuexperiencehost.exe",
    "shellexperiencehost.exe", "sihost.exe", "fontdrvhost.exe", "winlogon.exe",
    "ctfmon.exe", "dllhost.exe", "spoolsv.exe", "audiodg.exe",
    "python.exe", "pythonw.exe", "python3.exe",
    "code.exe", "node.exe",
}

# Suspicious process names to kill (common hacker tools, reverse shells, etc.)
_SUSPICIOUS_PATTERNS = {
    "nc.exe", "ncat.exe", "netcat.exe",          # Netcat
    "mimikatz.exe", "mimi.exe",                    # Credential theft
    "psexec.exe", "psexec64.exe",                  # Remote execution
    "powershell_ise.exe",                          # Script abuse
    "wmic.exe",                                     # WMI abuse
    "certutil.exe",                                 # Download abuse
    "bitsadmin.exe",                                # Download abuse
    "mshta.exe",                                    # Script host
    "regsvr32.exe",                                 # DLL injection
    "rundll32.exe",                                 # DLL injection
    "cscript.exe", "wscript.exe",                  # Script hosts
    "cmd.exe",                                      # Command shell (suspicious in context)
}


def execute_prevention_commands(commands, test_mode=True):
    """
    Execute prevention commands received from the backend.
    - Deduplicates by command type (only first of each type runs)
    - Respects cooldown (same type won't re-run within _PREVENTION_COOLDOWN seconds)
    - Skips if prevention is paused (admin dismissed)
    - Handles 'reset_prevention' command to undo all prevention
    Returns list of results for confirmation back to backend.
    """
    global _prevention_paused, _last_prevention

    if not commands:
        return []

    ts = datetime.now().strftime("%H:%M:%S")
    mode = "TEST" if test_mode else "LIVE"
    results = []
    now = time.time()

    # Check for reset command first
    for cmd in commands:
        if cmd.get("type") == "reset_prevention":
            print(f"[{ts}] [PREVENTION] ← RESET command received — undoing all prevention")
            _do_reset_prevention()
            results.append({"type": "reset_prevention", "success": True, "mode": mode, "time": datetime.now().isoformat()})
            return results

    # Skip if paused
    if _prevention_paused:
        print(f"[{ts}] [PREVENTION] Skipped {len(commands)} commands (admin paused)")
        return [{"type": c.get("type", "?"), "success": False, "mode": "PAUSED", "time": datetime.now().isoformat()} for c in commands]

    # Deduplicate by type — only keep first occurrence of each type
    seen_types = set()
    unique_commands = []
    for cmd in commands:
        ctype = cmd.get("type", "")
        if ctype not in seen_types:
            seen_types.add(ctype)
            unique_commands.append(cmd)

    if len(unique_commands) < len(commands):
        print(f"[{ts}] [PREVENTION] Deduplicated {len(commands)} → {len(unique_commands)} commands")

    for cmd in unique_commands:
        cmd_type = cmd.get("type", "")
        reason = cmd.get("reason", "")
        success = False

        # Cooldown check
        last_run = _last_prevention.get(cmd_type, 0)
        if now - last_run < _PREVENTION_COOLDOWN:
            remaining = int(_PREVENTION_COOLDOWN - (now - last_run))
            print(f"[{ts}] [PREVENTION] Skipped {cmd_type} (cooldown: {remaining}s remaining)")
            results.append({"type": cmd_type, "success": False, "mode": "COOLDOWN", "time": datetime.now().isoformat()})
            continue

        if cmd_type == "lock_screen":
            print(f"[{ts}] [PREVENT-{mode}] LOCK SCREEN — {reason}")
            if not test_mode:
                success = _do_lock_screen()
            else:
                success = True

        elif cmd_type == "kill_suspicious_processes":
            print(f"[{ts}] [PREVENT-{mode}] KILL SUSPICIOUS PROCESSES — {reason}")
            if not test_mode:
                success = _do_kill_suspicious()
            else:
                success = True

        elif cmd_type == "disable_usb":
            print(f"[{ts}] [PREVENT-{mode}] DISABLE USB STORAGE — {reason}")
            if not test_mode:
                success = _do_disable_usb()
            else:
                success = True

        elif cmd_type == "alert_user":
            print(f"[{ts}] [PREVENT-{mode}] ALERT — {reason}")
            if not test_mode:
                success = _do_alert_user(reason)
            else:
                success = True

        else:
            print(f"[{ts}] [PREVENT-{mode}] UNKNOWN COMMAND: {cmd_type}")

        if success:
            _last_prevention[cmd_type] = now

        results.append({
            "type": cmd_type,
            "success": success,
            "mode": mode,
            "time": datetime.now().isoformat(),
        })

    return results


def _do_reset_prevention():
    """Undo all prevention actions — restore system to normal state."""
    global _prevention_paused, _last_prevention
    _prevention_paused = False
    _last_prevention.clear()

    # Re-enable USB storage
    if platform.system() == "Windows":
        try:
            subprocess.run(
                ["reg", "add", r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
                 "/v", "Start", "/t", "REG_DWORD", "/d", "3", "/f"],
                capture_output=True, text=True, timeout=10
            )
            print("[RESET] ✓ USB storage re-enabled")
        except Exception:
            print("[RESET] Could not re-enable USB (needs admin)")

    print("[RESET] ✓ Prevention state cleared — system back to normal")


def _do_lock_screen():
    """Lock the Windows workstation (Win+L equivalent)."""
    try:
        if platform.system() == "Windows":
            ctypes.windll.user32.LockWorkStation()
            print("[PREVENT] ✓ Screen locked successfully")
            return True
        else:
            subprocess.run(["loginctl", "lock-session"], timeout=5,
                           capture_output=True, text=True)
            print("[PREVENT] ✓ Screen locked (Linux)")
            return True
    except Exception as e:
        print(f"[PREVENT] ✗ Failed to lock screen: {e}")
        return False


def _do_kill_suspicious():
    """Kill processes that match known suspicious/hacking tool patterns."""
    killed = []
    my_pid = os.getpid()
    my_parent = psutil.Process(my_pid).ppid()

    for proc in psutil.process_iter(["pid", "name", "username"]):
        try:
            pname = (proc.info["name"] or "").lower()
            pid = proc.info["pid"]

            if pid in (0, 4, my_pid, my_parent):
                continue

            # Only kill processes that match known suspicious patterns
            if pname in _SUSPICIOUS_PATTERNS:
                proc.kill()
                killed.append(f"{pname} (PID {pid})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue

    if killed:
        print(f"[PREVENT] ✓ Killed {len(killed)} suspicious processes: {', '.join(killed[:5])}")
    else:
        print("[PREVENT] ✓ No suspicious processes found to kill")
    return True


def _do_disable_usb():
    """Disable USB storage devices via Windows registry."""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["reg", "add", r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
                 "/v", "Start", "/t", "REG_DWORD", "/d", "4", "/f"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                print("[PREVENT] ✓ USB storage disabled via registry")
                return True
            else:
                print(f"[PREVENT] ✗ Failed to disable USB: {result.stderr or result.stdout}")
                return False
        else:
            print("[PREVENT] USB disable not implemented for this OS")
            return False
    except Exception as e:
        print(f"[PREVENT] ✗ Failed to disable USB: {e}")
        return False


def _do_alert_user(reason):
    """
    Show a security alert dialog with admin password option.
    Tries modern HTML dialog (pywebview) first, falls back to tkinter.
    Runs in a separate thread so it doesn't block the agent loop.
    Prevents double dialog spawning via _alert_dialog_active flag.
    """
    global _prevention_paused, _alert_dialog_active

    if _alert_dialog_active:
        print("[ALERT] Dialog already active — skipping duplicate")
        return True  # Return True to prevent re-queuing

    _alert_dialog_active = True

    def _show_dialog():
        global _prevention_paused, _alert_dialog_active

        # ── Try modern HTML dialog via subprocess ──
        try:
            script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alert_ui.py")
            if os.path.exists(script):
                env = os.environ.copy()
                env["_IDS_ADMIN_PW"] = _ADMIN_PASSWORD
                cmd = [sys.executable, script, "--reason", reason]
                # Pass backend info for event reporting
                if _backend_base_url:
                    backend_root = _backend_base_url.replace("/api/agent", "")
                    cmd.extend(["--backend-url", backend_root])
                if _current_agent_id:
                    cmd.extend(["--agent-id", _current_agent_id])
                if _current_host_name:
                    cmd.extend(["--host-name", _current_host_name])
                result = subprocess.run(cmd, env=env, timeout=300)
                if result.returncode == 0:
                    _prevention_paused = True
                    _do_reset_prevention()
                    print("[ALERT] ✓ Admin authenticated — prevention paused & reset")
                _alert_dialog_active = False
                return
        except Exception as e:
            print(f"[ALERT] Modern dialog unavailable ({e}), using tkinter fallback")

        # ── Fallback: tkinter dialog ──
        try:
            import tkinter as tk

            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)

            dialog = tk.Toplevel(root)
            dialog.title("IDS/IPS — Threat Detected")
            dialog.geometry("420x320")
            dialog.attributes("-topmost", True)
            dialog.resizable(False, False)
            dialog.protocol("WM_DELETE_CLOSE", lambda: None)

            dialog.update_idletasks()
            x = (dialog.winfo_screenwidth() // 2) - 210
            y = (dialog.winfo_screenheight() // 2) - 160
            dialog.geometry(f"+{x}+{y}")

            tk.Label(dialog, text="⚠  Security Alert!", font=("Segoe UI", 16, "bold"),
                     fg="#c0392b").pack(pady=(15, 5))
            tk.Label(dialog, text=reason, font=("Segoe UI", 10),
                     wraplength=380, justify="center").pack(pady=5)
            tk.Label(dialog, text="Your system activity has been flagged as suspicious.\n"
                     "Please contact your IT administrator.",
                     font=("Segoe UI", 9), fg="#555", wraplength=380, justify="center").pack(pady=5)

            tk.Frame(dialog, height=1, bg="#ccc").pack(fill="x", padx=20, pady=10)

            tk.Label(dialog, text="Admin / IT Password (to dismiss):",
                     font=("Segoe UI", 9)).pack()
            pw_var = tk.StringVar()
            pw_entry = tk.Entry(dialog, textvariable=pw_var, show="*", width=30,
                                font=("Segoe UI", 10))
            pw_entry.pack(pady=5)

            status_label = tk.Label(dialog, text="", font=("Segoe UI", 9), fg="red")
            status_label.pack()

            def on_dismiss():
                global _prevention_paused
                entered = pw_var.get().strip()
                if entered == _ADMIN_PASSWORD:
                    _prevention_paused = True
                    _do_reset_prevention()
                    print("[ALERT] ✓ Admin authenticated — prevention paused & reset")
                    dialog.destroy()
                    root.destroy()
                else:
                    status_label.config(text="Wrong password! Try again.")

            def on_ok():
                dialog.destroy()
                root.destroy()

            btn_frame = tk.Frame(dialog)
            btn_frame.pack(pady=10)
            tk.Button(btn_frame, text="OK", width=12, command=on_ok,
                      font=("Segoe UI", 10)).pack(side="left", padx=5)
            tk.Button(btn_frame, text="Admin Dismiss", width=14, command=on_dismiss,
                      font=("Segoe UI", 10), bg="#e74c3c", fg="white").pack(side="left", padx=5)

            pw_entry.focus_set()
            pw_entry.bind("<Return>", lambda e: on_dismiss())
            dialog.mainloop()
        except ImportError:
            MB_OK = 0x00000000
            MB_ICONWARNING = 0x00000030
            MB_TOPMOST = 0x00040000
            ctypes.windll.user32.MessageBoxW(
                0,
                f"Security Alert!\n\n{reason}\n\nYour system activity has been flagged as suspicious.\nPlease contact your IT administrator.",
                "IDS/IPS — Threat Detected",
                MB_OK | MB_ICONWARNING | MB_TOPMOST
            )
        except Exception as e:
            print(f"[PREVENT] ✗ Alert dialog error: {e}")

        _alert_dialog_active = False  # Always reset flag when dialog finishes

    # Run in thread so it doesn't block the agent loop
    t = threading.Thread(target=_show_dialog, daemon=True)
    t.start()
    print("[PREVENT] ✓ Alert dialog shown to user")
    return True


def collect_features(window_seconds=5):
    """
    Collect 15 CERT features matching the proven Host LIVE Test.py approach.
    Uses network snapshots + recent file counting + USB drive monitoring.
    
    CERT r4.2 scale mapping:
      - total_logons: NEW connections per window (not total open sockets)
      - total_device_activities: packet delta + USB events
      - total_file_activities: recently modified files in user dirs
    
    Returns (features_list, extras_dict)
    """
    # Snapshot before
    prev = _net_snapshot()
    time.sleep(window_seconds)

    # Snapshot after
    now = datetime.now()
    curr = _net_snapshot()
    hour = now.hour
    weekend = 1 if now.weekday() >= 5 else 0
    after_hours = 1 if (hour < 8 or hour >= 18) else 0

    # Deltas
    d_packets_sent = curr["packets_sent"] - prev["packets_sent"]
    d_packets_recv = curr["packets_recv"] - prev["packets_recv"]
    total_packets = max(0, d_packets_sent + d_packets_recv)

    # Connection delta (NEW connections this window, not total open sockets)
    # CERT total_logons = login events (3-5 normal, 20+ attack)
    # Raw psutil connections = 150-300 always → causes false positives
    delta_connections = max(0, curr["connections"] - prev["connections"])
    delta_established = max(0, curr["established"] - prev["established"])

    # Noise filter: normal background traffic (browsers, services, Windows
    # updates, DNS, etc.) can create 20-70 new connections per 5s window in
    # bursts.  Only count truly massive connection spikes as logon signals.
    # Attack simulations open 50-200+ sockets rapidly → exceeds 50.
    LOGON_NOISE_THRESHOLD = 50
    if delta_connections < LOGON_NOISE_THRESHOLD:
        delta_connections = 0

    # File activity — count recently modified files
    # Use a short window (45s ≈ 3 agent cycles) to avoid counting old activity.
    # 300s was too long and caused false positives from normal IDE/browser usage.
    recent_files = _count_recent_files(45)

    # USB / removable device monitoring
    new_drive_count, new_drives, removed_drives = _detect_drive_changes()
    usb_device_weight = new_drive_count * 200

    # Count files on newly connected drives
    usb_files_on_drive = 0
    for drv in new_drives:
        usb_files_on_drive += _count_drive_files(drv)

    # ── Build 15 features in exact model order ──
    # CERT total_logons = daily login events (3-5 normal, 20+ attack).
    # Our delta_connections = new TCP connections per 5s window (0-15 normal).
    # Normalize: divide by 10 to map to CERT daily scale.
    #   Normal: delta 0-49 → filtered to 0 → logons 0 (CERT normal)
    #   Attack: delta 50-200 → logons 5-20 (CERT attack range)
    LOGON_NORMALIZATION_FACTOR = 10.0
    total_logons = float(delta_connections) / LOGON_NORMALIZATION_FACTOR

    # CERT total_device_activities = USB/device operations (0-10 normal, 500+ attack)
    # DO NOT use network packets here — those are 300-600 normally and cause
    # massive false positives. Only USB events map to CERT device activities.
    total_device_activities = float(usb_device_weight) + float(usb_files_on_drive)

    # ── USB persistence ──
    # Bridge detection and file counting across cycles (15s window).
    global _usb_last_detection_time, _usb_cached_weight
    if new_drive_count > 0:
        _usb_last_detection_time = time.time()
        _usb_cached_weight = max(total_device_activities, 200.0)
    elif len(removed_drives) > 0:
        # USB was physically removed — clear persistence immediately
        ts_now = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts_now}] [USB-MONITOR] ✓ Drive removed — clearing USB persistence")
        _usb_last_detection_time = 0
        _usb_cached_weight = 0
        total_device_activities = 0.0
    if time.time() - _usb_last_detection_time < _USB_PERSIST_SECONDS:
        total_device_activities = max(total_device_activities, _usb_cached_weight)

    # ── File-based device inference ──
    # Mass file operations (>250 files in 45s) indicate heavy disk I/O, which maps
    # to CERT device_activities even without USB. The disk IS being used.
    # Threshold raised from 100 to 250 to avoid false positives from IDE/builds.
    if recent_files > 250:
        file_io_weight = min(float(recent_files) * 0.25, 500.0)
        total_device_activities = max(total_device_activities, file_io_weight)

    # ── Feature Scaling ──
    # CERT data = DAILY aggregates across an employee's full workday (~8-10 hours).
    # Our agent window = 5 seconds. If we see 2000 files in 5s, that's proportionally
    # FAR more suspicious than 20000 files in a full day.
    # Scale factor maps 5-second observations to CERT daily scale:
    #   Normal: 3 files × 10 = 30  → CERT normal range (0-50)  ✓
    #   Attack: 2000 files × 10 = 20000 → CERT attack range    ✓
    FILE_ACTIVITY_SCALE = 10.0
    total_file_activities = float(recent_files) * FILE_ACTIVITY_SCALE
    scaled_unique_files = float(recent_files) * (FILE_ACTIVITY_SCALE * 0.75)

    # ── Activity-based logon inference ──
    # CERT model requires logon features to classify as attack. In real-world
    # observation, connection deltas often miss attack sockets (opened before window).
    # If we observe high file activity (>250 files in 45s) or USB usage, someone IS
    # actively using the machine — infer a minimum logon count.
    #   Normal: files < 250, no USB → logon stays 0 (no inference) ✓
    #   Attack: files > 250 or USB → logon = max(observed, 2.0)  ✓
    ACTIVITY_LOGON_FLOOR = 2.0
    usb_active = new_drive_count > 0 or (time.time() - _usb_last_detection_time < _USB_PERSIST_SECONDS)
    if recent_files > 250 or usb_active:
        total_logons = max(total_logons, ACTIVITY_LOGON_FLOOR)

    features = [
        total_logons,                                    # 0: total_logons
        float(hour),                                     # 1: avg_logon_hour
        0.5 if total_logons > 0 else 0.0,               # 2: std_logon_hour
        float(weekend * total_logons),                   # 3: weekend_logons
        float(after_hours * total_logons),               # 4: after_hours_logons
        1.0,                                             # 5: unique_pcs_logon
        total_device_activities,                         # 6: total_device_activities
        1.0 if usb_active else 0.0,                     # 7: unique_pcs_device
        float(hour),                                     # 8: avg_device_hour
        float(after_hours * total_device_activities),    # 9: after_hours_device
        total_file_activities,                           # 10: total_file_activities
        scaled_unique_files,                             # 11: unique_files
        1.0 if recent_files > 0 else 0.0,               # 12: unique_pcs_file
        float(hour),                                     # 13: avg_file_hour
        float(after_hours * total_file_activities),      # 14: after_hours_files
    ]

    extras = {
        "net_packets_delta": int(total_packets),
        "connections": curr["connections"],
        "connections_delta": delta_connections,
        "established": curr["established"],
        "established_delta": delta_established,
        "recent_files": recent_files,
        "is_after_hours": after_hours,
        "is_weekend": weekend,
        "hour": hour,
        "usb_new_drives": len(new_drives),
        "usb_removed_drives": len(removed_drives),
        "usb_files_on_drive": usb_files_on_drive,
        "usb_device_weight": usb_device_weight,
    }

    return features, extras


# ─────────────────────────────────────────────────────────
# Heartbeat — wait for backend before starting detection
# ─────────────────────────────────────────────────────────

def wait_for_server(session, url, interval=5):
    """
    Block until the backend responds or shutdown is requested.
    Tries every `interval` seconds. Shows a heartbeat in the console.
    """
    attempt = 0
    while not _shutdown:
        attempt += 1
        try:
            r = session.get(
                url.rsplit("/", 1)[0] + "/health",
                timeout=5,
            )
            if r.status_code == 200:
                print(f"[HEARTBEAT] Server is UP (attempt {attempt})")
                return True
        except requests.exceptions.ConnectionError:
            pass
        except Exception:
            pass

        # Also accept a successful POST (in case /health doesn't exist yet)
        try:
            r = session.options(url, timeout=3)
            if r.status_code < 500:
                print(f"[HEARTBEAT] Server reachable (attempt {attempt})")
                return True
        except Exception:
            pass

        ts = datetime.now().strftime("%H:%M:%S")
        backoff = min(interval + (attempt * 2), 60)
        print(f"[{ts}] [HEARTBEAT] Waiting for server... (attempt {attempt}, retry in {backoff}s)")
        _interruptible_sleep(backoff)

    return False


def register_with_backend(session, base_url, agent_id, host_name, ip, hardware_id=""):
    """
    Register this agent with the backend. Must be called after server is reachable.
    Returns True if registered/approved, "pending" if awaiting approval, False if rejected.
    """
    url = base_url + "/register"
    payload = {
        "agent_id": agent_id,
        "host_name": host_name,
        "ip": ip,
        "os_info": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "hardware_id": hardware_id,
    }

    try:
        r = session.post(url, json=payload, timeout=10)
        if r.status_code in (200, 201):
            data = r.json()
            status = data.get("status", "unknown")
            approved = data.get("is_approved", False)
            print(f"[REGISTER] {status} (approved: {approved})")
            if not approved:
                print("[REGISTER] Agent is PENDING admin approval. Waiting...")
                return "pending"
            return True
        elif r.status_code == 401:
            print("[REGISTER] Bad agent key. Check config.ini")
            return False
        elif r.status_code == 403:
            error_msg = r.json().get("error", "Rejected")
            print(f"[REGISTER] REJECTED: {error_msg}")
            return False
        else:
            print(f"[REGISTER] Unexpected response: {r.status_code}")
            return False
    except Exception as e:
        print(f"[REGISTER] Failed: {e}")
        return False


def _interruptible_sleep(seconds):
    """Sleep that can be interrupted by Ctrl+C (checks _shutdown every 0.5s)."""
    end = time.time() + seconds
    while time.time() < end and not _shutdown:
        time.sleep(min(0.5, end - time.time()))


def _confirm_prevention(session, base_url, host_name, results):
    """Send confirmation back to backend that prevention was executed."""
    if not results:
        return
    try:
        session.post(
            f"{base_url}/prevention-confirm",
            json={
                "host_name": host_name,
                "results": results,
                "timestamp": datetime.now().isoformat(),
            },
            timeout=5,
        )
        succeeded = sum(1 for r in results if r.get("success"))
        print(f"[PREVENTION] ✓ Confirmed {succeeded}/{len(results)} actions to backend")
    except Exception:
        print("[PREVENTION] Could not confirm to backend (non-critical)")


# ─────────────────────────────────────────────────────────
# Main Agent Loop
# ─────────────────────────────────────────────────────────

def run_agent():
    config = load_config()

    server_host = config["server_host"]
    server_port = int(config["server_port"])
    agent_key = config["agent_key"]
    interval = int(config["interval"])
    window = int(config["window"])
    endpoint = config["endpoint"]

    base_url = f"http://{server_host}:{server_port}/api/agent"
    report_url = f"http://{server_host}:{server_port}{endpoint}"

    # Set module-level backend info for alert dialog reporting
    global _backend_base_url, _current_agent_id, _current_host_name

    host_name = socket.gethostname()
    agent_id = get_or_create_agent_id()
    hardware_id = _get_hardware_fingerprint(agent_key)

    _backend_base_url = base_url
    _current_agent_id = agent_id
    _current_host_name = host_name

    # Reuse TCP connection — one persistent session, no noise
    session = requests.Session()
    session.headers.update({
        "X-Agent-Key": agent_key,
        "X-Agent-ID": agent_id,
        "X-Hardware-ID": hardware_id,
        "Content-Type": "application/json",
    })

    ip = get_local_ip(server_host)
    print("=" * 50)
    print(f"  Host IDS Agent")
    print(f"  Host:     {host_name} ({ip})")
    print(f"  Agent ID: {agent_id[:8]}...")
    print(f"  HW Hash:  {hardware_id[:16]}...")
    print(f"  Server:   {report_url}")
    print(f"  Window:   {window}s  |  Interval: {interval}s")
    print(f"  Press Ctrl+C to stop gracefully")
    print("=" * 50)

    if agent_key == "changeme":
        print("[WARN] Using default agent key. Set a real key in config.ini")

    # ── Heartbeat: wait for backend ──
    print("[HEARTBEAT] Checking if backend is reachable...")
    if not wait_for_server(session, report_url):
        print("[INFO] Shutdown requested before server came up. Exiting.")
        return

    # ── Register with backend ──
    print("[REGISTER] Introducing this agent to the backend...")
    reg_result = register_with_backend(session, base_url, agent_id, host_name, ip, hardware_id)
    if reg_result == "pending":
        # Wait for admin approval
        print("[APPROVAL] Waiting for admin to approve this device...")
        while not _shutdown:
            _interruptible_sleep(10)
            reg_result = register_with_backend(session, base_url, agent_id, host_name, ip, hardware_id)
            if reg_result is True:
                print("[APPROVAL] Device approved! Starting detection.")
                break
            elif reg_result is False:
                print("[FATAL] Device rejected. Exiting.")
                return
            # Still pending — continue waiting
        if _shutdown:
            return
    elif not reg_result:
        print("[FATAL] Registration failed. Cannot proceed.")
        return

    print("[INFO] Backend is online. Agent is registered. Starting detection loop.\n")
    consecutive_errors = 0

    while not _shutdown:
        try:
            ip = get_local_ip(server_host)

            features, extras = collect_features(window)

            if _shutdown:
                break

            payload = {
                "agent_id": agent_id,
                "host_name": host_name,
                "ip": ip,
                "features": features,
                "os_info": f"{platform.system()} {platform.release()} ({platform.machine()})",
            }

            response = session.post(report_url, json=payload, timeout=30)

            if response.status_code == 200:
                res = response.json()
                threat = res.get("prediction", "Unknown")
                action = res.get("action", "N/A")
                ts = datetime.now().strftime("%H:%M:%S")

                status_icon = "OK" if threat == "Normal" else "!!"
                usb_info = f" usb={extras['usb_new_drives']}" if extras.get('usb_new_drives', 0) > 0 else ""
                ah_tag = " [AH]" if extras.get('is_after_hours') else ""
                print(
                    f"[{ts}] [{status_icon}] "
                    f"Threat={threat} | Action={action} | "
                    f"logons={extras['connections_delta']} pkts={extras['net_packets_delta']} files={extras['recent_files']}{usb_info}{ah_tag}"
                )

                # Execute prevention commands from response (direct)
                prevention = res.get("prevention", {})
                prevention_cmds = prevention.get("prevention_commands", [])
                is_test_mode = prevention.get("test_mode", True)
                if prevention_cmds:
                    print(f"[{ts}] [PREVENTION] Received {len(prevention_cmds)} commands (mode={'TEST' if is_test_mode else 'LIVE'})")
                    results = execute_prevention_commands(prevention_cmds, test_mode=is_test_mode)
                    _confirm_prevention(session, base_url, host_name, results)

                # Also poll for queued commands (from attack simulation or other sources)
                try:
                    cmd_url = f"{base_url}/pending-commands"
                    cmd_resp = session.post(cmd_url, json={"host_name": host_name}, timeout=5)
                    if cmd_resp.status_code == 200:
                        cmd_data = cmd_resp.json()
                        queued_cmds = cmd_data.get("commands", [])
                        cmd_test_mode = cmd_data.get("test_mode", True)
                        if queued_cmds:
                            print(f"[{ts}] [PREVENTION] Queued {len(queued_cmds)} commands (mode={'TEST' if cmd_test_mode else 'LIVE'})")
                            results = execute_prevention_commands(queued_cmds, test_mode=cmd_test_mode)
                            _confirm_prevention(session, base_url, host_name, results)
                except Exception:
                    pass  # Non-critical — don't break the main loop

                consecutive_errors = 0

            elif response.status_code == 401:
                print("[ERROR] Authentication failed. Check agent_key in config.ini")
                consecutive_errors += 1
            elif response.status_code == 403:
                print("[WARN] Agent rejected (403). Attempting re-registration...")
                reg_result = register_with_backend(session, base_url, agent_id, host_name, ip, hardware_id)
                if reg_result is True:
                    print("[OK] Re-registered successfully. Resuming...")
                    consecutive_errors = 0
                elif reg_result == "pending":
                    print("[APPROVAL] Waiting for admin approval...")
                    while not _shutdown:
                        _interruptible_sleep(10)
                        reg_result = register_with_backend(session, base_url, agent_id, host_name, ip, hardware_id)
                        if reg_result is True:
                            print("[OK] Re-approved! Resuming.")
                            break
                        elif reg_result is False:
                            break
                    consecutive_errors = 0
                else:
                    consecutive_errors += 1
            else:
                print(f"[ERROR] Server returned {response.status_code}")
                consecutive_errors += 1

        except requests.exceptions.ConnectionError:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] [WARN] Lost connection to server. Retrying...")
            consecutive_errors += 1
            if consecutive_errors >= 5:
                print("[HEARTBEAT] Too many failures. Waiting for server to come back...")
                if not wait_for_server(session, report_url):
                    break
                consecutive_errors = 0
                continue
        except Exception as e:
            print(f"[ERROR] {e}")
            consecutive_errors += 1

        if _shutdown:
            break

        # Exponential backoff on repeated errors (max 60s extra)
        wait = interval
        if consecutive_errors > 3:
            wait = min(interval + (consecutive_errors * 5), interval + 60)
            print(f"[WARN] {consecutive_errors} errors. Next retry in {wait}s")

        _interruptible_sleep(wait)

    # ── Clean shutdown — undo all prevention so user keeps full access ──
    print("\n[SHUTDOWN] Resetting all prevention before exit...")
    _do_reset_prevention()
    session.close()
    print("=" * 50)
    print("  Agent stopped cleanly. All prevention reset.")
    print("=" * 50)


if __name__ == "__main__":
    run_agent()