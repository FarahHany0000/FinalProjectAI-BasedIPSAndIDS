import socket
import time
from datetime import datetime, UTC
import requests
import psutil
from datetime import datetime

API_URL = "http://127.0.0.1:5000/api/agent/host-report"
AGENT_KEY = "mysecrettoken"


def get_cert_features():
    now = datetime.now()

    # time features
    is_weekend = 1.0 if now.weekday() >= 5 else 0.0
    is_after_hours = 1.0 if (now.hour < 8 or now.hour > 18) else 0.0

    # process features
    procs = list(psutil.process_iter())
    proc_count = float(len(procs))

    return [
        float(len(psutil.users())),                 # total_logons
        float(now.hour),                            # avg_logon_hour
        0.0,                                        # std_logon_hour
        is_weekend,                                 # weekend_logons
        is_after_hours,                             # after_hours_logons
        1.0,                                        # unique_pcs_logon
        float(len(psutil.disk_partitions())),       # total_device_activities
        1.0,                                        # unique_pcs_device
        float(now.hour),                            # avg_device_hour
        is_after_hours,                             # after_hours_device
        proc_count,                                 # total_file_activities
        proc_count * 0.5,                           # unique_files
        1.0,                                        # unique_pcs_file
        float(now.hour),                            # avg_file_hour
        is_after_hours                              # after_hours_files
    ]


def get_system_status():
    """System metrics"""
    return {
        "cpu": psutil.cpu_percent(),
        "memory": psutil.virtual_memory().percent,
        "connections": len(psutil.net_connections())
    }


def run_agent():
    host_name = socket.gethostname()
    ip = socket.gethostbyname(host_name)

    print(f"🛡️ Agent started on {host_name} ({ip})")

    while True:

        features = get_cert_features()
        system = get_system_status()

        payload = {
            "host_name": host_name,
            "ip": ip,
            "features": features,
            "system": system,
            "timestamp": datetime.now(UTC).isoformat(),
            "status": "online"
        }

        try:
            res = requests.post(
                API_URL,
                json=payload,
                headers={"X-Agent-Key": AGENT_KEY},
                timeout=5
            )

            if res.status_code == 200:
                data = res.json()

                print(
                    f"[{datetime.now().strftime('%H:%M:%S')}] "
                    f"Status: Online | "
                    f"Threat: {data.get('threat','Normal')} | "
                    f"Action: {data.get('action','No Action')}"
                )

            else:
                print(f"Server Error: {res.status_code}")

        except Exception as e:
            print(f"Connection Error → Agent cannot reach server: {e}")

        time.sleep(10)


if __name__ == "__main__":
    run_agent()