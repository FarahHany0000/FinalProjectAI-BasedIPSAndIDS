# agent.py - Simple IDS Agent
import requests
import time
import psutil

BACKEND_URL = "http://127.0.0.1:5000/predict"
HOSTNAME = "Host-1"
SCAN_INTERVAL = 10

prev_stats = psutil.net_io_counters()
prev_time = time.time()

def collect_features():
    global prev_stats, prev_time
    now = time.time()
    duration = now - prev_time
    stats = psutil.net_io_counters()

    features = {
        "init_fwd_win_byts": stats.bytes_sent - prev_stats.bytes_sent,
        "fwd_seg_size_min": 60,
        "subflow_fwd_byts": stats.bytes_sent - prev_stats.bytes_sent,
        "flow_iat_max": duration*1000,
        "fwd_iat_max": duration*1000,
        "fwd_iat_tot": duration*1000,
        "totlen_fwd_pkts": stats.packets_sent - prev_stats.packets_sent,
        "flow_iat_mean": duration*1000,
        "bwd_pktss": stats.packets_recv - prev_stats.packets_recv,
        "flow_iat_min": 1,
        "fwd_header_len": 20,
        "fwd_seg_size_avg": (stats.bytes_sent - prev_stats.bytes_sent)/max(1, stats.packets_sent - prev_stats.packets_sent),
        "fwd_iat_min": 1,
        "fwd_iat_mean": duration*1000,
        "init_bwd_win_byts": stats.bytes_recv - prev_stats.bytes_recv,
        "fwd_pktss": stats.packets_sent - prev_stats.packets_sent,
        "flow_pktss": (stats.packets_sent - prev_stats.packets_sent)+(stats.packets_recv - prev_stats.packets_recv),
        "fwd_pkt_len_max": 1500,
        "fwd_pkt_len_mean": (stats.bytes_sent - prev_stats.bytes_sent)/max(1, stats.packets_sent - prev_stats.packets_sent),
        "flow_duration": duration
    }

    prev_stats = stats
    prev_time = now
    return features

def send_features():
    features = collect_features()
    payload = {"host": HOSTNAME, "features": features}
    try:
        resp = requests.post(BACKEND_URL, json=payload)
        if resp.status_code == 200:
            r = resp.json()
            print(f"[{r['date']}] Attack: {r['type']} | Severity: {r['severity']} | Action: {r['action']} | Final State: {r['final_state']}")
        else:
            print(f"Error: {resp.json()}")
    except Exception as e:
        print(f"Connection error: {e}")

if __name__ == "__main__":
    print("Starting Basic IDS Agent...")
    while True:
        send_features()
        time.sleep(SCAN_INTERVAL)