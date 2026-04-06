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
import platform
import argparse
import configparser
import hashlib
import hmac
import json
import ctypes
import subprocess
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


def _count_recent_files(max_age_seconds=300, max_scan_time=3):
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
            # Skip deep/hidden/large dirs
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                       ('node_modules', '__pycache__', '.git', 'venv', '.venv')]
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
    In test_mode: only logs what WOULD happen.
    In live mode: actually executes the actions.
    Returns list of results for confirmation back to backend.
    """
    if not commands:
        return []

    ts = datetime.now().strftime("%H:%M:%S")
    mode = "TEST" if test_mode else "LIVE"
    results = []

    for cmd in commands:
        cmd_type = cmd.get("type", "")
        reason = cmd.get("reason", "")
        success = False

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

        results.append({
            "type": cmd_type,
            "success": success,
            "mode": mode,
            "time": datetime.now().isoformat(),
        })

    return results


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
    """Show a warning message box to the user."""
    try:
        if platform.system() == "Windows":
            MB_OK = 0x00000000
            MB_ICONWARNING = 0x00000030
            MB_TOPMOST = 0x00040000
            ctypes.windll.user32.MessageBoxW(
                0,
                f"Security Alert!\n\n{reason}\n\nYour system activity has been flagged as suspicious.\nPlease contact your IT administrator.",
                "IDS/IPS — Threat Detected",
                MB_OK | MB_ICONWARNING | MB_TOPMOST
            )
            print("[PREVENT] ✓ Alert shown to user")
            return True
    except Exception as e:
        print(f"[PREVENT] ✗ Failed to show alert: {e}")
        return False


def collect_features(window_seconds=5):
    """
    Collect 15 CERT features matching the proven Host LIVE Test.py approach.
    Uses network snapshots + recent file counting (NOT raw disk I/O).
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
    after_hours = 1 if (hour < 8 or hour > 18) else 0

    # Deltas
    d_packets_sent = curr["packets_sent"] - prev["packets_sent"]
    d_packets_recv = curr["packets_recv"] - prev["packets_recv"]
    total_packets = max(0, d_packets_sent + d_packets_recv)

    # File activity — count recently modified files (same as "next try")
    recent_files = _count_recent_files(300)

    # ── Build 15 features in exact model order ──
    total_logons = float(curr["connections"])
    total_device_activities = float(total_packets)
    total_file_activities = float(recent_files)

    features = [
        total_logons,                                    # 0: total_logons
        float(hour),                                     # 1: avg_logon_hour
        0.5 if total_logons > 0 else 0.0,               # 2: std_logon_hour
        float(weekend * total_logons),                   # 3: weekend_logons
        float(after_hours * total_logons),               # 4: after_hours_logons
        1.0,                                             # 5: unique_pcs_logon
        total_device_activities,                         # 6: total_device_activities
        1.0 if total_packets > 0 else 0.0,              # 7: unique_pcs_device
        float(hour),                                     # 8: avg_device_hour
        float(after_hours * total_device_activities),    # 9: after_hours_device
        total_file_activities,                           # 10: total_file_activities
        float(recent_files),                             # 11: unique_files
        1.0 if recent_files > 0 else 0.0,               # 12: unique_pcs_file
        float(hour),                                     # 13: avg_file_hour
        float(after_hours * total_file_activities),      # 14: after_hours_files
    ]

    extras = {
        "net_packets_delta": int(total_packets),
        "connections": curr["connections"],
        "established": curr["established"],
        "recent_files": recent_files,
        "is_after_hours": after_hours,
        "is_weekend": weekend,
        "hour": hour,
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

    host_name = socket.gethostname()
    agent_id = get_or_create_agent_id()
    hardware_id = _get_hardware_fingerprint(agent_key)

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
                print(
                    f"[{ts}] [{status_icon}] "
                    f"Threat={threat} | Action={action} | "
                    f"conns={extras['connections']} pkts={extras['net_packets_delta']} files={extras['recent_files']}"
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

    # ── Clean shutdown ──
    session.close()
    print("\n" + "=" * 50)
    print("  Agent stopped cleanly.")
    print("=" * 50)


if __name__ == "__main__":
    run_agent()