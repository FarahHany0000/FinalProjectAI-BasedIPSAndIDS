import psutil
import requests
import socket
import time
from datetime import datetime

API_URL = "http://127.0.0.1:5000/api/agent/host-report"
AGENT_KEY = "mysecrettoken"
INTERVAL = 60

host_name = socket.gethostname()

while True:
    # CPU
    cpu_percent = psutil.cpu_percent(interval=1)
    cpu_cores = psutil.cpu_count(logical=True)

    # Memory
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()

    # Disk
    disks = []
    for part in psutil.disk_partitions():
        usage = psutil.disk_usage(part.mountpoint)
        disks.append({
            "device": part.device,
            "mountpoint": part.mountpoint,
            "fstype": part.fstype,
            "total": usage.total,
            "used": usage.used,
            "free": usage.free,
            "percent": usage.percent
        })

    disk_io = psutil.disk_io_counters()

    # Network
    net_io = psutil.net_io_counters(pernic=True)
    net_addrs = psutil.net_if_addrs()

    # Processes
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        processes.append(proc.info)

    # Users
    users = []
    for user in psutil.users():
        users.append({
            "name": user.name,
            "terminal": user.terminal,
            "host": user.host,
            "started": datetime.fromtimestamp(user.started).strftime('%Y-%m-%d %H:%M:%S')
        })

    # Boot time
    boot_time = datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')

    # إعداد البيانات
    data = {
        "host_name": host_name,
        "cpu": {"percent": cpu_percent, "cores": cpu_cores},
        "memory": {"virtual": memory._asdict(), "swap": swap._asdict()},
        "disks": disks,
        "disk_io": disk_io._asdict(),
        "network": {nic: net_io[nic]._asdict() for nic in net_io},
        "network_addrs": {nic: [addr._asdict() for addr in net_addrs[nic]] for nic in net_addrs},
        "processes": processes,
        "users": users,
        "boot_time": boot_time,
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    headers = {"X-Agent-Key": AGENT_KEY}

    try:
        res = requests.post(API_URL, json=data, headers=headers)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Sent data, response: {res.json()}")
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Error sending data: {e}")

    time.sleep(INTERVAL)
