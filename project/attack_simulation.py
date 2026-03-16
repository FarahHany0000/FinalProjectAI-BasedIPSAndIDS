#!/usr/bin/env python3
"""
==========================================================================
  Attack Simulation — Tests the full IDS pipeline via backend API
==========================================================================
  Sends crafted CERT r4.2 attack feature vectors to the backend.
  Tests: simulation → HTTP POST → backend → CNN model → response

  Usage:
      python attack_simulation.py                   (default: 127.0.0.1:5000)
      python attack_simulation.py --server 192.168.137.1:5000

  This file is standalone — delete it when you're done testing.
==========================================================================
"""

import os
import sys
import time
import uuid
import shutil
import platform
import threading
import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
import argparse

parser = argparse.ArgumentParser(description="IDS Attack Simulation")
parser.add_argument("--server", default="127.0.0.1:5000", help="Backend address (host:port)")
parser.add_argument("--key", default="changeme", help="Agent key")
args = parser.parse_args()

BASE_URL = f"http://{args.server}"
AGENT_KEY = args.key

# Read the real agent ID from the host agent's .agent_id file
_agent_id_file = os.path.join(os.path.dirname(__file__), "agents", "host_agent", ".agent_id")
if os.path.exists(_agent_id_file):
    AGENT_ID = open(_agent_id_file).read().strip()
else:
    AGENT_ID = str(uuid.uuid4())

import platform
HOST_NAME = platform.node()

SESSION = requests.Session()
SESSION.headers.update({
    "Content-Type": "application/json",
    "X-Agent-Key": AGENT_KEY,
    "X-Agent-ID": AGENT_ID,
})

# ---------------------------------------------------------------------------
# 15 CERT r4.2 Features (same order as host_agent.py)
# ---------------------------------------------------------------------------
FEATURE_NAMES = [
    "total_logons",        "avg_logon_hour",      "std_logon_hour",
    "weekend_logons",      "after_hours_logons",   "unique_pcs_logon",
    "total_device_activities", "unique_pcs_device", "avg_device_hour",
    "after_hours_device",
    "total_file_activities", "unique_files",        "unique_pcs_file",
    "avg_file_hour",       "after_hours_files",
]

# ---------------------------------------------------------------------------
# Attack Scenarios — calibrated from CERT r4.2 dataset
# ---------------------------------------------------------------------------
SCENARIOS = {
    "1": {
        "name": "Normal Employee Behavior",
        "type": "BASELINE",
        "desc": "Regular employee — works during business hours, normal file access",
        "expected": "Normal (no detection)",
        "features": [3, 10.0, 1.2, 0, 0, 1.0, 2, 1.0, 10.0, 0, 80, 60, 1.0, 10.0, 0],
    },
    "2": {
        "name": "IT Sabotage — Mass File Deletion",
        "type": "SABOTAGE",
        "desc": "Disgruntled employee deleting files across 15 PCs at midnight",
        "expected": "ATTACK (high file activity + after hours + multi-PC)",
        "features": [20, 3.0, 2.0, 10, 20, 15.0, 10, 1.0, 3.0, 10, 80000, 60000, 15.0, 3.0, 80000],
    },
    "3": {
        "name": "Espionage — IP Theft (Multi-PC After Hours)",
        "type": "ESPIONAGE",
        "desc": "Employee stealing IP from 3 PCs after 9PM",
        "expected": "ATTACK (off-hours + multi-PC + file access)",
        "features": [4, 21.0, 1.5, 0, 4, 3.0, 5, 2.0, 21.0, 5, 10000, 8000, 3.0, 21.0, 10000],
    },
    "4": {
        "name": "Fraud — Unauthorized Financial Data Access",
        "type": "FRAUD",
        "desc": "Employee accessing 50,000+ financial files during business hours",
        "expected": "ATTACK (massive file access volume)",
        "features": [5, 13.0, 1.0, 0, 0, 1.0, 0, 0.0, 0.0, 0, 50000, 40000, 1.0, 13.0, 0],
    },
    "5": {
        "name": "Low-Level Fraud — Anomalous Pattern",
        "type": "FRAUD_LIGHT",
        "desc": "Employee accessing files abnormally but at low volume (500 files)",
        "expected": "ATTACK (CNN pattern detection)",
        "features": [4, 11.0, 0.8, 0, 0, 1.0, 0, 0.0, 0.0, 0, 500, 400, 1.0, 11.0, 0],
    },
    "6": {
        "name": "Data Exfiltration — USB Copy After Hours",
        "type": "EXFILTRATION",
        "desc": "Employee copying files to USB drive after work hours",
        "expected": "ATTACK (high device + file activity after hours)",
        "features": [2, 22.0, 0.5, 1, 2, 1.0, 500, 2.0, 22.0, 500, 20000, 15000, 1.0, 22.0, 20000],
    },
    "7": {
        "name": "System Abuse — Network Flooding",
        "type": "ABUSE",
        "desc": "Employee making mass network requests / downloading tools",
        "expected": "ATTACK (extreme device activity after hours)",
        "features": [3, 20.0, 1.0, 0, 3, 1.0, 2000, 1.0, 20.0, 2000, 100, 80, 1.0, 20.0, 100],
    },
}

# ---------------------------------------------------------------------------
# Helper: progress bar
# ---------------------------------------------------------------------------
def bar(prob, width=25):
    filled = int(prob * width)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


# ---------------------------------------------------------------------------
# Register this simulation agent
# ---------------------------------------------------------------------------
def register():
    print(f"[*] Registering as {HOST_NAME} ({AGENT_ID[:8]}...)...")
    try:
        r = SESSION.post(f"{BASE_URL}/api/agent/register", json={
            "agent_id": AGENT_ID,
            "host_name": HOST_NAME,
            "os_info": f"{platform.system()} {platform.release()}",
        })
        if r.status_code == 201:
            print(f"[OK] Registered successfully\n")
            return True
        elif r.status_code == 200:
            print(f"[OK] Already registered\n")
            return True
        else:
            print(f"[FAIL] Registration failed: {r.status_code} — {r.text}")
            return False
    except requests.ConnectionError:
        print(f"[FAIL] Cannot connect to backend at {BASE_URL}")
        print(f"       Make sure the backend is running: cd project/backend && python app.py")
        return False


# ---------------------------------------------------------------------------
# Send attack features to backend
# ---------------------------------------------------------------------------
def send_features(features, scenario_name):
    payload = {
        "host_name": HOST_NAME,
        "features": features,
    }
    try:
        r = SESSION.post(f"{BASE_URL}/api/agent/host-report", json=payload)
        if r.status_code == 200:
            data = r.json()
            pred = data.get("prediction", "?")
            prob = data.get("probability", 0)
            action = data.get("action", "?")

            is_attack = pred == "Attack"
            icon = "!!!" if is_attack else "   "
            color_start = "\033[91m" if is_attack else "\033[92m"
            color_end = "\033[0m"

            print(f"  {color_start}{icon} {bar(prob)} {prob*100:5.1f}%  "
                  f"Prediction: {pred:6s}  |  Action: {action}{color_end}")
            return data
        else:
            print(f"  [ERROR] {r.status_code}: {r.text[:100]}")
            return None
    except requests.ConnectionError:
        print(f"  [ERROR] Lost connection to backend")
        return None


# ---------------------------------------------------------------------------
# Mode 1: Run a single scenario
# ---------------------------------------------------------------------------
def run_scenario(key):
    sc = SCENARIOS[key]
    print("=" * 70)
    print(f"  SCENARIO {key}: {sc['name']}")
    print(f"  Type    : {sc['type']}")
    print(f"  Desc    : {sc['desc']}")
    print(f"  Expected: {sc['expected']}")
    print("-" * 70)

    # Show feature values
    print("  Features:")
    for name, val in zip(FEATURE_NAMES, sc["features"]):
        print(f"    {name:<28} = {val}")
    print("-" * 70)

    # Send 3 pulses
    print("  Backend CNN Response:")
    for i in range(3):
        print(f"  --- Pulse {i+1}/3 ---")
        send_features(sc["features"], sc["name"])
        if i < 2:
            time.sleep(1)

    print("=" * 70 + "\n")


# ---------------------------------------------------------------------------
# Mode 2: Run ALL scenarios
# ---------------------------------------------------------------------------
def run_all():
    print("\n" + "=" * 70)
    print("  RUNNING ALL 7 CERT r4.2 SCENARIOS")
    print("=" * 70 + "\n")

    results = {}
    for key in sorted(SCENARIOS.keys()):
        sc = SCENARIOS[key]
        print(f"  [{key}] {sc['name']:<45} ", end="", flush=True)
        data = send_features(sc["features"], sc["name"])
        if data:
            results[key] = data
        print()
        time.sleep(0.5)

    # Summary
    print("\n" + "=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    print(f"  {'#':<4} {'Scenario':<40} {'Result':>10} {'Prob':>8}")
    print("-" * 70)
    for key in sorted(results.keys()):
        sc = SCENARIOS[key]
        r = results[key]
        pred = r.get("prediction", "?")
        prob = r.get("probability", 0)
        mark = " *** " if pred == "Attack" else "     "
        print(f"  {key:<4} {sc['name']:<40} {pred:>10} {prob*100:7.1f}%{mark}")
    print("=" * 70)

    attacks = sum(1 for r in results.values() if r.get("prediction") == "Attack")
    normals = len(results) - attacks
    print(f"\n  Detected as Attack: {attacks}/7")
    print(f"  Detected as Normal: {normals}/7")
    print()


# ---------------------------------------------------------------------------
# Mode 3: Live attack simulation (creates real file activity + sends to backend)
# ---------------------------------------------------------------------------
_stop = threading.Event()

def live_simulation():
    print("\n" + "=" * 70)
    print("  LIVE ATTACK SIMULATION")
    print("  Creates real file activity on your machine + sends features to backend")
    print("=" * 70)
    print("  Choose attack:")
    print("  1. Data Exfiltration — mass file copy (simulates USB)")
    print("  2. IT Sabotage — mass file deletion")
    print("  3. Fraud — mass financial file access")
    print("  4. Normal activity — baseline")
    print("  Q. Back")

    choice = input("\n  Choice: ").strip().upper()
    if choice == "Q":
        return

    sim_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_attack_sim_temp")
    _stop.clear()

    if choice == "1":
        _live_exfiltration(sim_dir)
    elif choice == "2":
        _live_sabotage(sim_dir)
    elif choice == "3":
        _live_fraud(sim_dir)
    elif choice == "4":
        _live_normal(sim_dir)
    else:
        print("  Invalid choice")


def _live_exfiltration(sim_dir):
    print("\n  [ATTACK] Data Exfiltration — copying 200 files...")
    src = os.path.join(sim_dir, "src")
    dst = os.path.join(sim_dir, "dst")
    os.makedirs(src, exist_ok=True)
    os.makedirs(dst, exist_ok=True)

    # Create files
    for i in range(50):
        with open(os.path.join(src, f"secret_{i}.txt"), "w") as f:
            f.write("CONFIDENTIAL " * 100)

    # Copy in background
    def do_copy():
        copied = 0
        for rep in range(4):
            if _stop.is_set():
                break
            for i in range(50):
                shutil.copy(os.path.join(src, f"secret_{i}.txt"),
                            os.path.join(dst, f"copy_{rep}_{i}.txt"))
                copied += 1
        print(f"  [SIM] {copied} files copied")

    t = threading.Thread(target=do_copy, daemon=True)
    t.start()
    time.sleep(1)

    print("  [+] Sending USB Exfiltration features to backend...")
    for i in range(3):
        print(f"  --- Pulse {i+1}/3 ---")
        send_features(SCENARIOS["6"]["features"], "EXFILTRATION")
        time.sleep(2)

    _stop.set()
    t.join(timeout=5)
    shutil.rmtree(sim_dir, ignore_errors=True)
    print("  [DONE] Simulation complete, temp files cleaned.\n")


def _live_sabotage(sim_dir):
    print("\n  [ATTACK] IT Sabotage — creating then deleting 200 files...")
    os.makedirs(sim_dir, exist_ok=True)

    for i in range(200):
        with open(os.path.join(sim_dir, f"system_{i}.dat"), "w") as f:
            f.write("CRITICAL " * 200)

    def do_delete():
        deleted = 0
        for i in range(200):
            if _stop.is_set():
                break
            try:
                os.remove(os.path.join(sim_dir, f"system_{i}.dat"))
                deleted += 1
            except Exception:
                pass
        print(f"  [SIM] {deleted} files deleted")

    t = threading.Thread(target=do_delete, daemon=True)
    t.start()
    time.sleep(1)

    print("  [+] Sending IT Sabotage features to backend...")
    for i in range(3):
        print(f"  --- Pulse {i+1}/3 ---")
        send_features(SCENARIOS["2"]["features"], "SABOTAGE")
        time.sleep(2)

    _stop.set()
    t.join(timeout=5)
    shutil.rmtree(sim_dir, ignore_errors=True)
    print("  [DONE] Simulation complete, temp files cleaned.\n")


def _live_fraud(sim_dir):
    print("\n  [ATTACK] Fraud — creating and reading 300 financial files...")
    os.makedirs(sim_dir, exist_ok=True)

    def do_access():
        for i in range(300):
            if _stop.is_set():
                break
            path = os.path.join(sim_dir, f"financial_{i}.csv")
            with open(path, "w") as f:
                f.write("account,amount\n" + "\n".join(f"ACC{j},{j*100}" for j in range(50)))
            with open(path, "r") as f:
                _ = f.read()
        print(f"  [SIM] 300 financial files accessed")

    t = threading.Thread(target=do_access, daemon=True)
    t.start()
    time.sleep(1)

    print("  [+] Sending Fraud features to backend...")
    for i in range(3):
        print(f"  --- Pulse {i+1}/3 ---")
        send_features(SCENARIOS["4"]["features"], "FRAUD")
        time.sleep(2)

    _stop.set()
    t.join(timeout=8)
    shutil.rmtree(sim_dir, ignore_errors=True)
    print("  [DONE] Simulation complete, temp files cleaned.\n")


def _live_normal(sim_dir):
    print("\n  [BASELINE] Normal employee behavior...")
    os.makedirs(sim_dir, exist_ok=True)
    path = os.path.join(sim_dir, "work_doc.txt")
    with open(path, "w") as f:
        f.write("Regular work notes\n" * 10)
    with open(path, "r") as f:
        _ = f.read()

    print("  [+] Sending Normal features to backend...")
    for i in range(3):
        print(f"  --- Pulse {i+1}/3 ---")
        send_features(SCENARIOS["1"]["features"], "NORMAL")
        time.sleep(2)

    shutil.rmtree(sim_dir, ignore_errors=True)
    print("  [DONE] Simulation complete.\n")


# ---------------------------------------------------------------------------
# Main Menu
# ---------------------------------------------------------------------------
def main():
    print()
    print("#" * 70)
    print("#  CERT r4.2 Attack Simulation — Full Pipeline Test                 #")
    print("#  Sends attack features → Backend API → CNN Model → Response       #")
    print("#" * 70)
    print(f"  Backend : {BASE_URL}")
    print(f"  Agent ID: {AGENT_ID[:8]}...")

    # Check backend
    try:
        r = requests.get(f"{BASE_URL}/api/agent/health", timeout=30)
        if r.status_code == 200:
            data = r.json()
            print(f"  Status  : ONLINE (model_loaded={data.get('model_loaded')})")
        else:
            print(f"  Status  : ERROR ({r.status_code})")
    except requests.ConnectionError:
        print(f"\n  [FAIL] Backend is not running at {BASE_URL}")
        print(f"  Start it first: cd project/backend && python app.py")
        sys.exit(1)

    # Register
    if not register():
        sys.exit(1)

    while True:
        print("=" * 70)
        print("  MAIN MENU")
        print("=" * 70)
        print("  1. Run single scenario      (choose attack type)")
        print("  2. Run ALL 7 scenarios       (quick summary table)")
        print("  3. Live attack simulation    (real file activity on your machine)")
        print("  Q. Exit")
        print("=" * 70)

        choice = input("  Choice: ").strip().upper()

        if choice == "1":
            print("\n  Choose scenario:")
            for key, sc in SCENARIOS.items():
                print(f"    {key}. {sc['name']:<45} [{sc['type']}]")
            sub = input("\n  Scenario #: ").strip()
            if sub in SCENARIOS:
                run_scenario(sub)
            else:
                print("  Invalid scenario number")

        elif choice == "2":
            run_all()

        elif choice == "3":
            live_simulation()

        elif choice == "Q":
            print("\n  Goodbye!\n")
            break

        else:
            print("  Invalid choice, try again")


if __name__ == "__main__":
    main()
