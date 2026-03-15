import socket
import time
import requests
import numpy as np
import random
from datetime import datetime

# ---------------- CONFIG ----------------
API_URL = "http://127.0.0.1:5000/api/agent/host-report"
AGENT_KEY = "mysecrettoken"

FEATURE_ORDER = [
    'total_logons', 'avg_logon_hour', 'std_logon_hour', 'weekend_logons',
    'after_hours_logons', 'unique_pcs_logon', 'total_device_activities',
    'unique_pcs_device', 'avg_device_hour', 'after_hours_device',
    'total_file_activities', 'unique_files', 'unique_pcs_file', 'avg_file_hour',
    'after_hours_files'
]

# ---------------- HELPERS ----------------
def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except:
        ip = "127.0.0.1"
    return ip

def collect_features(simulate_attack=False):
    """Generates normal or attack features"""
    now = datetime.now()
    
    values = {
        "total_logons": random.randint(1, 5),
        "avg_logon_hour": now.hour,
        "std_logon_hour": random.uniform(0.1, 1.0),
        "weekend_logons": 0,
        "after_hours_logons": 0,
        "unique_pcs_logon": 1,
        "total_device_activities": random.randint(2, 10),
        "unique_pcs_device": 1,
        "avg_device_hour": now.hour,
        "after_hours_device": 0,
        "total_file_activities": random.randint(1, 15),
        "unique_files": random.randint(1, 5),
        "unique_pcs_file": 1,
        "avg_file_hour": now.hour,
        "after_hours_files": 0
    }

    # ---------- Attack Simulation ----------
    if simulate_attack or random.random() > 0.7:  # 30% chance of attack
        attack_type = random.choice(["SQL Injection", "Brute Force", "Malware"])
        if attack_type == "SQL Injection":
            values["total_logons"] = random.randint(50, 100)
            values["after_hours_logons"] = random.randint(5, 10)
            values["total_file_activities"] = random.randint(100, 200)
        elif attack_type == "Brute Force":
            values["total_logons"] = random.randint(20, 50)
            values["std_logon_hour"] = random.uniform(5.0, 8.0)
        elif attack_type == "Malware":
            values["total_device_activities"] = random.randint(50, 100)
            values["after_hours_device"] = random.randint(5, 10)
        
        values["simulated_attack_type"] = attack_type
    else:
        values["simulated_attack_type"] = "Normal"

    features_list = [values[name] for name in FEATURE_ORDER]
    return features_list, values

# ---------------- MAIN LOOP ----------------
def run():
    hostname = socket.gethostname()
    ip = get_ip()
    print(f" Agent started on {hostname} ({ip})...")
    
    while True:
        # Randomly simulate an attack sometimes
        features, raw_data = collect_features()

        payload = {
            "host_name": hostname,
            "ip": ip,
            "features": features,
            "info": raw_data
        }

        try:
            r = requests.post(
                API_URL,
                json=payload,
                headers={"X-Agent-Key": AGENT_KEY},
                timeout=5
            )
            if r.status_code == 200:
                res_data = r.json()
                print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                      f"Status: {res_data.get('status')} | "
                      f"Threat: {res_data.get('threats')} | "
                      f"Action: {res_data.get('action')}")
            else:
                print(f"❌ Server returned {r.status_code}")
        except Exception as e:
            print(f" Connection Error: {e}")

        time.sleep(5)  

if __name__ == "__main__":
    run()