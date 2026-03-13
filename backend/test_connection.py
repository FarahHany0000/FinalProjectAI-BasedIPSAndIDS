import pyodbc


payload = {
    "host_name": "TestHost",
    "ip": "192.168.1.10",
    "cpu": 95,
    "memory": 90,
    "disk": 80,
    "network": 5000,
    "processes": 120,
    "connections": 50,
    "attack_type": "DOS",
    "action": "BLOCKED"
}

try:
    response = requests.post(API_URL, json=payload, headers={"X-Agent-Key": AGENT_KEY}, timeout=5)
    if response.status_code == 200:
        print("✔ API test successful, data sent!")
    else:
        print(f"⚠ API returned status: {response.status_code}, content: {response.text}")
except Exception as e:
    print("❌ Could not send API request:", e)