import psutil
import requests
import socket
import time
from datetime import datetime

API_URL = "http://127.0.0.1:8000/agent-data"
INTERVAL = 10  

host_name = socket.gethostname()

while True:
    try:
        device_count = len(psutil.disk_partitions())

        email_count = len(psutil.users())

        connections = psutil.net_connections()
        http_count = len(connections)

        data = {
            "device_count": device_count,
            "email_count": email_count,
            "http_count": http_count
        }

        response = requests.post(API_URL, json=data)

        print(f"[{datetime.now().strftime('%H:%M:%S')}]")
        print("Sent:", data)
        print("Response:", response.json())
        print("-" * 40)

    except Exception as e:
        print("Error:", e)

    time.sleep(INTERVAL)