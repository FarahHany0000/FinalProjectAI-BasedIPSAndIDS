import socket
import time
import requests
import psutil
from datetime import datetime

API_URL = "http://127.0.0.1:5000/api/agent/host-report"
AGENT_KEY = "mysecrettoken"

def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except: return "127.0.0.1"

def run_agent():
    host_name = socket.gethostname()
    ip = get_ip()
    print(f" Agent is running on {host_name} ({ip})...")

    while True:

        features = [
            float(len(psutil.users())),
            float(datetime.now().hour),
            float(psutil.cpu_percent()),
            float(psutil.virtual_memory().percent),
            float(len(psutil.pids())),
            0.0, 1.0, 0.0, 0.0, 1.0, 
            0.0, 0.0, 1.0, 0.0, 0.0  
        ]

        payload = {
            "host_name": host_name,
            "ip": ip,
            "features": features
        }

        try:
            response = requests.post(
                API_URL, 
                json=payload, 
                headers={"X-Agent-Key": AGENT_KEY}, 
                timeout=5
            )
            if response.status_code == 200:
                res_data = response.json()
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Threat Level: {res_data['threats']} | Action: {res_data['action']}")
            else:
                print(f"Server Error: {response.status_code}")
        except Exception as e:
            print(f"Connection Error: {e}")

        time.sleep(10)

if __name__ == "__main__":
    run_agent()