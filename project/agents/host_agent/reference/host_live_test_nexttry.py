#!/usr/bin/env python3
import os
import time
import joblib
import psutil
import numpy as np
from datetime import datetime
from tensorflow.keras.models import load_model

# =========================================================
# SAME CLASSES USED WHEN THE PKL FILES WERE SAVED
# =========================================================
class RandomForestPipeline:
    def __init__(self, model, scaler, feature_names, threshold):
        self.model = model
        self.scaler = scaler
        self.feature_names = feature_names
        self.threshold = threshold
        self.name = "Random Forest"

    def predict(self, features):
        features_scaled = self.scaler.transform([features])
        proba = self.model.predict_proba(features_scaled)[0][1]
        prediction = 1 if proba >= self.threshold else 0
        return {
            'prediction': 'Attack' if prediction == 1 else 'Normal',
            'probability': float(proba),
            'threshold': self.threshold,
            'model': self.name
        }

class XGBoostPipeline:
    def __init__(self, model, feature_names, threshold=0.5):
        self.model = model
        self.feature_names = feature_names
        self.threshold = threshold
        self.name = "XGBoost"

    def predict(self, features):
        proba = self.model.predict_proba([features])[0][1]
        prediction = 1 if proba >= self.threshold else 0
        return {
            'prediction': 'Attack' if prediction == 1 else 'Normal',
            'probability': float(proba),
            'threshold': self.threshold,
            'model': self.name
        }

class CNNPipeline:
    def __init__(self, model, scaler, feature_names, threshold=0.5):
        self.model = model
        self.scaler = scaler
        self.feature_names = feature_names
        self.threshold = threshold
        self.name = "CNN"

    def predict(self, features):
        features_scaled = self.scaler.transform([features])
        features_cnn = features_scaled.reshape(1, 1, -1)
        proba = self.model.predict(features_cnn, verbose=0)[0][0]
        prediction = 1 if proba >= self.threshold else 0
        return {
            'prediction': 'Attack' if prediction == 1 else 'Normal',
            'probability': float(proba),
            'threshold': self.threshold,
            'model': self.name
        }

# =========================================================
# LOAD MODELS
# =========================================================
rf_model = None
xgb_model = None
cnn_pipeline = None

print("[+] Loading models...")

try:
    rf_model = joblib.load('rf_complete_pipeline.pkl')
    print("[OK] Random Forest loaded")
except Exception as e:
    print(f"[ERR] Random Forest load failed: {e}")

try:
    xgb_model = joblib.load('xgb_complete_pipeline.pkl')
    print("[OK] XGBoost loaded")
except Exception as e:
    print(f"[ERR] XGBoost load failed: {e}")

try:
    cnn_pipeline = joblib.load('cnn_complete_pipeline.pkl')
    cnn_weights = load_model('cnn_weights.h5')
    cnn_pipeline.model = cnn_weights
    print("[OK] CNN loaded")
except Exception as e:
    print(f"[ERR] CNN load failed: {e}")

# =========================================================
# FEATURE ORDER
# =========================================================
FEATURE_NAMES = [
    'total_logons', 'avg_logon_hour', 'std_logon_hour',
    'weekend_logons', 'after_hours_logons', 'unique_pcs_logon',
    'total_device_activities', 'unique_pcs_device',
    'avg_device_hour', 'after_hours_device',
    'total_file_activities', 'unique_files', 'unique_pcs_file',
    'avg_file_hour', 'after_hours_files'
]

def is_after_hours(hour):
    return 1 if (hour < 8 or hour > 18) else 0

def is_weekend(dt):
    return 1 if dt.weekday() >= 5 else 0

def count_usb_like():
    count = 0
    try:
        parts = psutil.disk_partitions(all=True)
        for p in parts:
            text = f"{p.device} {p.mountpoint} {p.fstype}".lower()
            if any(k in text for k in ["usb", "media", "removable", "/run/media", "/media/"]):
                count += 1
    except Exception:
        pass
    return count

def count_recent_files():
    home = os.path.expanduser("~")
    roots = [
        home,
        os.path.join(home, "Desktop"),
        os.path.join(home, "Downloads"),
        os.path.join(home, "Documents"),
    ]
    now = time.time()
    touched = []
    seen = set()

    for root in roots:
        if not os.path.exists(root):
            continue
        for base, dirs, files in os.walk(root):
            for name in files:
                path = os.path.join(base, name)
                if path in seen:
                    continue
                seen.add(path)
                try:
                    st = os.stat(path)
                    if now - st.st_mtime <= 300:
                        touched.append(path)
                except Exception:
                    pass
    return len(touched)

def net_snapshot():
    c = psutil.net_io_counters()
    conns = psutil.net_connections(kind='inet')
    return {
        "bytes_sent": c.bytes_sent,
        "bytes_recv": c.bytes_recv,
        "packets_sent": c.packets_sent,
        "packets_recv": c.packets_recv,
        "connections": len(conns),
        "syn_recv": sum(1 for x in conns if x.status == "SYN_RECV"),
        "established": sum(1 for x in conns if x.status == "ESTABLISHED"),
    }

def build_features(prev_snap, curr_snap, dt_now):
    d_bytes_sent = curr_snap["bytes_sent"] - prev_snap["bytes_sent"]
    d_bytes_recv = curr_snap["bytes_recv"] - prev_snap["bytes_recv"]
    d_packets_sent = curr_snap["packets_sent"] - prev_snap["packets_sent"]
    d_packets_recv = curr_snap["packets_recv"] - prev_snap["packets_recv"]

    total_packets = max(0, d_packets_sent + d_packets_recv)
    current_hour = dt_now.hour
    weekend = is_weekend(dt_now)
    after_hours = is_after_hours(current_hour)
    recent_files = count_recent_files()

    # Approximation layer to feed the 15 expected features
    total_logons = float(curr_snap["connections"])
    avg_logon_hour = float(current_hour)
    std_logon_hour = 0.5 if total_logons > 0 else 0.0
    weekend_logons = float(weekend * total_logons)
    after_hours_logons = float(after_hours * total_logons)
    unique_pcs_logon = 1.0

    total_device_activities = float(total_packets)
    unique_pcs_device = 1.0 if total_packets > 0 else 0.0
    avg_device_hour = float(current_hour)
    after_hours_device = float(after_hours * total_device_activities)

    total_file_activities = float(recent_files)
    unique_files = float(recent_files)
    unique_pcs_file = 1.0 if recent_files > 0 else 0.0
    avg_file_hour = float(current_hour)
    after_hours_files = float(after_hours * total_file_activities)

    features = [
        total_logons,
        avg_logon_hour,
        std_logon_hour,
        weekend_logons,
        after_hours_logons,
        unique_pcs_logon,
        total_device_activities,
        unique_pcs_device,
        avg_device_hour,
        after_hours_device,
        total_file_activities,
        unique_files,
        unique_pcs_file,
        avg_file_hour,
        after_hours_files,
    ]

    extras = {
        "packets_sent_delta": d_packets_sent,
        "packets_recv_delta": d_packets_recv,
        "bytes_sent_delta": d_bytes_sent,
        "bytes_recv_delta": d_bytes_recv,
        "connections_now": curr_snap["connections"],
        "syn_recv_now": curr_snap["syn_recv"],
        "established_now": curr_snap["established"],
        "recent_files": recent_files,
        "usb_count": count_usb_like(),
        "after_hours": after_hours,
        "weekend": weekend,
    }
    return features, extras

def show_result(label, res):
    if res is None:
        print(f"{label}: NOT LOADED")
    else:
        print(f"{label}: {res['prediction']} | prob={res['probability']:.3f} | thr={res['threshold']}")

def main():
    print("\n[+] Live IDS monitor started")
    print("[+] Sampling every 5 seconds")
    print("[+] Press Ctrl+C to stop\n")

    prev = net_snapshot()
    time.sleep(5)

    while True:
        now = datetime.now()
        curr = net_snapshot()
        features, extras = build_features(prev, curr, now)

        xgb_res = xgb_model.predict(features) if xgb_model is not None else None
        rf_res = rf_model.predict(features) if rf_model is not None else None
        cnn_res = cnn_pipeline.predict(features) if cnn_pipeline is not None else None

        print("=" * 80)
        print(f"[{now.strftime('%Y-%m-%d %H:%M:%S')}]")
        print(f"Traffic delta: sent_pkts={extras['packets_sent_delta']} recv_pkts={extras['packets_recv_delta']} sent_bytes={extras['bytes_sent_delta']} recv_bytes={extras['bytes_recv_delta']}")
        print(f"Connections: total={extras['connections_now']} established={extras['established_now']} syn_recv={extras['syn_recv_now']}")
        print(f"USB-like mounts: {extras['usb_count']} | Recent files(5m): {extras['recent_files']} | After-hours={extras['after_hours']} | Weekend={extras['weekend']}")
        print("-" * 80)
        show_result("XGB", xgb_res)
        show_result("RF ", rf_res)
        show_result("CNN", cnn_res)

        alerts = []
        for name, res in [("XGB", xgb_res), ("RF", rf_res), ("CNN", cnn_res)]:
            if res is not None and res["prediction"] == "Attack":
                alerts.append(f"{name}={res['probability']:.3f}")

        if alerts:
            print("ALERT:", " | ".join(alerts))
        else:
            print("Status: normal")

        prev = curr
        time.sleep(5)

if __name__ == "__main__":
    main()