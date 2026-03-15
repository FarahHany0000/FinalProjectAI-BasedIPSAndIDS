# advanced_agent.py - Advanced IDS + IPS Agent with Scapy
import time
import psutil
import threading
import requests
from scapy.all import sniff, IP, TCP, UDP

BACKEND_URL = "http://127.0.0.1:5000/predict"
HOSTNAME = "Host-1"
SCAN_INTERVAL = 10
CAPTURE_DURATION = 5

prev_net_stats = psutil.net_io_counters()
prev_time = time.time()

def extract_packet_features(pkt):
    features = {}
    if IP in pkt:
        ip = pkt[IP]
        features['src_bytes'] = len(pkt)
        features['dst_bytes'] = len(pkt)
        features['src_port'] = pkt.sport if TCP in pkt or UDP in pkt else 0
        features['dst_port'] = pkt.dport if TCP in pkt or UDP in pkt else 0
        features['protocol'] = ip.proto
        features['ttl'] = ip.ttl
    return features

def sniff_packets(duration=CAPTURE_DURATION):
    packets = []
    def store(pkt):
        f = extract_packet_features(pkt)
        if f:
            packets.append(f)
    sniff(prn=store, timeout=duration)
    return packets

def aggregate_features(packets):
    if not packets:
        return None
    src_bytes = [p['src_bytes'] for p in packets]
    dst_bytes = [p['dst_bytes'] for p in packets]
    ttl_list = [p['ttl'] for p in packets]

    agg = {
        'init_fwd_win_byts': max(src_bytes),
        'fwd_seg_size_min': min(src_bytes),
        'subflow_fwd_byts': sum(src_bytes),
        'flow_iat_max': max(ttl_list),
        'fwd_iat_max': max(dst_bytes),
        'fwd_iat_tot': sum(dst_bytes),
        'totlen_fwd_pkts': sum(src_bytes)+sum(dst_bytes),
        'flow_iat_mean': int(sum(src_bytes)/len(src_bytes)),
        'bwd_pktss': len(packets),
        'flow_iat_min': min(ttl_list),
        'fwd_header_len': 20,
        'fwd_seg_size_avg': int(sum(src_bytes)/len(src_bytes)),
        'fwd_iat_min': min(ttl_list),
        'fwd_iat_mean': int(sum(src_bytes)/len(src_bytes)),
        'init_bwd_win_byts': sum(dst_bytes),
        'fwd_pktss': len(packets),
        'flow_pktss': len(packets),
        'fwd_pkt_len_max': max(src_bytes),
        'fwd_pkt_len_mean': int(sum(src_bytes)/len(src_bytes)),
        'flow_duration': CAPTURE_DURATION
    }
    return agg

def collect_system_features():
    global prev_net_stats, prev_time
    now = time.time()
    duration = now - prev_time
    stats = psutil.net_io_counters()
    features = {
        "init_fwd_win_byts": stats.bytes_sent - prev_net_stats.bytes_sent,
        "fwd_seg_size_min": 60,
        "subflow_fwd_byts": stats.bytes_sent - prev_net_stats.bytes_sent,
        "flow_iat_max": duration*1000,
        "fwd_iat_max": duration*1000,
        "fwd_iat_tot": duration*1000,
        "totlen_fwd_pkts": stats.packets_sent - prev_net_stats.packets_sent,
        "flow_iat_mean": duration*1000,
        "bwd_pktss": stats.packets_recv - prev_net_stats.packets_recv,
        "flow_iat_min": 1,
        "fwd_header_len": 20,
        "fwd_seg_size_avg": (stats.bytes_sent - prev_net_stats.bytes_sent)/max(1, stats.packets_sent - prev_net_stats.packets_sent),
        "fwd_iat_min": 1,
        "fwd_iat_mean": duration*1000,
        "init_bwd_win_byts": stats.bytes_recv - prev_net_stats.bytes_recv,
        "fwd_pktss": stats.packets_sent - prev_net_stats.packets_sent,
        "flow_pktss": (stats.packets_sent - prev_net_stats.packets_sent)+(stats.packets_recv - prev_net_stats.packets_recv),
        "fwd_pkt_len_max": 1500,
        "fwd_pkt_len_mean": (stats.bytes_sent - prev_net_stats.bytes_sent)/max(1, stats.packets_sent - prev_net_stats.packets_sent),
        "flow_duration": duration
    }
    prev_net_stats = stats
    prev_time = now
    return features

def send_features():
    packets = sniff_packets()
    agg_features = aggregate_features(packets)
    sys_features = collect_system_features()
    features = agg_features.copy() if agg_features else {}
    features.update(sys_features)

    payload = {"host": HOSTNAME, "features": features}
    try:
        resp = requests.post(BACKEND_URL, json=payload, timeout=5)
        if resp.status_code == 200:
            r = resp.json()
            print(f"[{r['date']}] Attack: {r['type']} | Severity: {r['severity']} | Action: {r['action']} | Final State: {r['final_state']}")
            if r['severity'] in ["High","Critical"]:
                print(f"⚠️ Prevention Applied: {r['action']}")
        else:
            print(f"Prediction error: {resp.json()}")
    except Exception as e:
        print(f"Connection error: {e}")

def main_loop():
    while True:
        send_features()
        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    print("Starting Advanced IDS + IPS Agent...")
    main_loop()