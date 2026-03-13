# agent.py
import psutil
import socket
import time
import numpy as np
import joblib
import requests
import platform
import subprocess
from use_models import CNNPipeline

# ---------------- CONFIG ----------------
API_URL = "http://127.0.0.1:5000/api/agent/host-report"
AGENT_KEY = "mysecrettoken"
MODEL_PATH = r"C:\Users\HANY\Desktop\frontend\backend\ai_models\cnn_complete_pipeline.pkl"

SLEEP_INTERVAL = 1        # كل 1 ثانية
CPU_THRESHOLD = 85         # CPU % يعتبر عالي
NETWORK_THRESHOLD = 400    # network KB/s يعتبر عالي

print("\n🛡️ AI Host IDS Agent Starting...\n")

# ---------------- LOAD MODEL ----------------
try:
    model = joblib.load(MODEL_PATH)
    print("✅ CNN Model Loaded")
except Exception as e:
    print("❌ Model load failed:", e)
    exit()

# ---------------- GET LOCAL IP ----------------
def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

# ---------------- NETWORK USAGE ----------------
def get_network_usage(prev_total):
    net = psutil.net_io_counters()
    total = net.bytes_sent + net.bytes_recv
    usage = (total - prev_total) / 1024
    return total, round(usage, 2)

# ---------------- COLLECT FEATURES ----------------
def collect_features(prev_net):
    cpu = psutil.cpu_percent(interval=0.5)
    memory = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    processes = len(psutil.pids())
    connections = len(psutil.net_connections())
    new_total, network = get_network_usage(prev_net)

    threads = 0
    for p in psutil.process_iter():
        try:
            threads += p.num_threads()
        except:
            pass

    # Features مصممة لتتوافق مع الموديل
    features = [
        cpu, memory, disk, network, processes, connections, threads,
        cpu * network, cpu + memory, disk + memory, network * 2,
        processes / 10, connections * 2, threads / 10, cpu
    ]

    raw = {
        "cpu": cpu,
        "memory": memory,
        "disk": disk,
        "network": network,
        "processes": processes,
        "connections": connections
    }

    return features, raw, new_total

# ---------------- AI PREDICTION ----------------
def predict_attack(features):
    try:
        import numpy as np

        # تحويل features إلى numpy array مع الشكل الصحيح للموديل
        X = np.array(features, dtype=np.float32).reshape(1, 1, 15)

        # استدعاء الموديل
        result = model.predict(X)

        print("\n🧠 MODEL RESULT:", result)

        if result['prediction'] == "Attack":
            verdict = "Attack"
            attack_type = "AI Detected Threat"
        else:
            verdict = "Safe"
            attack_type = "None"

        return attack_type, verdict

    except Exception as e:
        print("⚠️ AI prediction error:", e)
        return "Unknown", "Safe"

# ---------------- AUTO PREVENTION ----------------
def auto_prevent(raw):
    action = "SAFE"
    isolated = False

    try:
        if raw["cpu"] > CPU_THRESHOLD or raw["network"] > NETWORK_THRESHOLD:
            print("\n🚨 ATTACK DETECTED - RUNNING AUTO PREVENTION\n")
            isolated = True

            # قتل العمليات المريبة
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                try:
                    name = proc.info['name'].lower()
                    if name in ["python.exe", "powershell.exe", "system"]:
                        continue
                    if proc.info['cpu_percent'] > 60:
                        print(f"⚠️ Killing suspicious process: {name}")
                        proc.kill()
                        action = "BLOCKED"
                except:
                    pass

            # عزل الجهاز عن الشبكة
            if platform.system() == "Windows":
                subprocess.run('netsh interface set interface "Wi-Fi" admin=disable', shell=True)
                subprocess.run('netsh interface set interface "Ethernet" admin=disable', shell=True)
            else:
                subprocess.run("sudo iptables -A INPUT -j DROP", shell=True)
                subprocess.run("sudo iptables -A OUTPUT -j DROP", shell=True)

            print("🛑 Device isolated and network blocked")

    except Exception as e:
        print("❌ Auto prevention error:", e)

    return action, isolated

# ---------------- MAIN LOOP ----------------
def run():
    prev_net = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
    print("🚀 Agent Running...\n")

    while True:
        features, raw, prev_net = collect_features(prev_net)

        attack_type, verdict = predict_attack(features)

        action = "SAFE"
        online_status = True

        if verdict == "Attack":
            action, isolated = auto_prevent(raw)
            if isolated:
                online_status = False

        payload = {
            "host_name": socket.gethostname(),
            "ip": get_ip(),
            "cpu": raw["cpu"],
            "memory": raw["memory"],
            "disk": raw["disk"],
            "network": raw["network"],
            "processes": raw["processes"],
            "connections": raw["connections"],
            "attack_type": attack_type,
            "status": verdict,
            "threats": attack_type,
            "action": action,
            "online": online_status,
            "timestamp": time.time()
        }

        print("\n📡 PAYLOAD SENT")
        for k, v in payload.items():
            print(f"{k}: {v}")
        print("-" * 50)

        try:
            requests.post(
                API_URL,
                json=payload,
                headers={"X-Agent-Key": AGENT_KEY},
                timeout=5
            )
        except:
            payload["online"] = False
            print("⚠ Server unreachable (Agent Offline)")

        time.sleep(SLEEP_INTERVAL)

# ---------------- RUN ----------------
if __name__ == "__main__":
    run()