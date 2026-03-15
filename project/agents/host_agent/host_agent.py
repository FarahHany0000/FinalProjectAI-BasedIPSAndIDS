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

import os
import sys
import time
import signal
import socket
import argparse
import configparser
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
    "server_host": "192.168.137.1",   # Laptop5 gateway IP (Windows Mobile Hotspot default)
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

    return config


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


def collect_features(window_seconds):
    """
    Collect 15 features by sampling system metrics over a time window.
    Based on the proven approach from Host LIVE Test.py (next try).

    Returns (features_list, extras_dict)
    """
    now = datetime.now()
    hour = now.hour
    is_weekend = 1 if now.weekday() >= 5 else 0
    is_after_hours = 1 if (hour < 8 or hour > 18) else 0

    # Snapshot before
    net_start = psutil.net_io_counters()
    disk_start = psutil.disk_io_counters()

    time.sleep(window_seconds)

    # Snapshot after
    net_end = psutil.net_io_counters()
    disk_end = psutil.disk_io_counters()

    # ── Logon features ──
    users = psutil.users()
    total_logons = float(len(users) * 5)
    unique_hosts = set(u.host for u in users if u.host)
    unique_pcs_logon = float(len(unique_hosts)) if unique_hosts else 1.0

    # ── Device/Network activity (packet deltas) ──
    net_ops = (
        (net_end.packets_sent - net_start.packets_sent)
        + (net_end.packets_recv - net_start.packets_recv)
    )
    total_device_activities = float(net_ops)

    # ── File/Disk activity (I/O operation deltas) ──
    disk_ops = (
        (disk_end.read_count - disk_start.read_count)
        + (disk_end.write_count - disk_start.write_count)
    )
    total_file_activities = float(disk_ops)
    unique_files = float(max(1, int(disk_ops * 0.1)))

    # After-hours proportional to activity, not binary
    after_hours_logons = float(is_after_hours * total_logons)
    after_hours_device = float(is_after_hours * total_device_activities)
    after_hours_files = float(is_after_hours * total_file_activities)

    # ── 15 features in exact model order ──
    features = [
        total_logons,                            # 0: total_logons
        float(hour),                             # 1: avg_logon_hour
        0.5,                                     # 2: std_logon_hour
        float(is_weekend * total_logons),         # 3: weekend_logons
        after_hours_logons,                       # 4: after_hours_logons
        unique_pcs_logon,                         # 5: unique_pcs_logon
        total_device_activities,                  # 6: total_device_activities
        1.0 if net_ops > 0 else 0.0,             # 7: unique_pcs_device
        float(hour),                             # 8: avg_device_hour
        after_hours_device,                       # 9: after_hours_device
        total_file_activities,                    # 10: total_file_activities
        unique_files,                            # 11: unique_files
        1.0 if disk_ops > 0 else 0.0,           # 12: unique_pcs_file
        float(hour),                             # 13: avg_file_hour
        after_hours_files,                        # 14: after_hours_files
    ]

    extras = {
        "net_packets_delta": int(net_ops),
        "disk_ops_delta": int(disk_ops),
        "is_after_hours": is_after_hours,
        "is_weekend": is_weekend,
        "active_users": len(users),
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


def _interruptible_sleep(seconds):
    """Sleep that can be interrupted by Ctrl+C (checks _shutdown every 0.5s)."""
    end = time.time() + seconds
    while time.time() < end and not _shutdown:
        time.sleep(min(0.5, end - time.time()))


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

    url = f"http://{server_host}:{server_port}{endpoint}"

    host_name = socket.gethostname()

    # Reuse TCP connection — one persistent session, no noise
    session = requests.Session()
    session.headers.update({
        "X-Agent-Key": agent_key,
        "Content-Type": "application/json",
    })

    ip = get_local_ip(server_host)
    print("=" * 50)
    print(f"  Host IDS Agent")
    print(f"  Host:    {host_name} ({ip})")
    print(f"  Server:  {url}")
    print(f"  Window:  {window}s  |  Interval: {interval}s")
    print(f"  Press Ctrl+C to stop gracefully")
    print("=" * 50)

    if agent_key == "changeme":
        print("[WARN] Using default agent key. Set a real key in config.ini")

    # ── Heartbeat: wait for backend before entering detection loop ──
    print("[HEARTBEAT] Checking if backend is reachable...")
    if not wait_for_server(session, url):
        print("[INFO] Shutdown requested before server came up. Exiting.")
        return

    print("[INFO] Backend is online. Starting detection loop.\n")
    consecutive_errors = 0

    while not _shutdown:
        try:
            # Re-detect IP every cycle (handles DHCP changes)
            ip = get_local_ip(server_host)

            features, extras = collect_features(window)

            if _shutdown:
                break

            payload = {
                "host_name": host_name,
                "ip": ip,
                "features": features,
            }

            response = session.post(url, json=payload, timeout=10)

            if response.status_code == 200:
                res = response.json()
                threat = res.get("threats", "Unknown")
                action = res.get("action", "N/A")
                ts = datetime.now().strftime("%H:%M:%S")

                status_icon = "OK" if threat == "Normal" else "!!"
                print(
                    f"[{ts}] [{status_icon}] "
                    f"Threat={threat} | Action={action} | "
                    f"net={extras['net_packets_delta']} disk={extras['disk_ops_delta']}"
                )
                consecutive_errors = 0

            elif response.status_code == 401:
                print("[ERROR] Authentication failed. Check agent_key in config.ini")
                consecutive_errors += 1
            else:
                print(f"[ERROR] Server returned {response.status_code}")
                consecutive_errors += 1

        except requests.exceptions.ConnectionError:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] [WARN] Lost connection to server. Retrying...")
            consecutive_errors += 1
            # Re-enter heartbeat mode if too many consecutive errors
            if consecutive_errors >= 5:
                print("[HEARTBEAT] Too many failures. Waiting for server to come back...")
                if not wait_for_server(session, url):
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