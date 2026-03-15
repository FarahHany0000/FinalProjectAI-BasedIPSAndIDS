import time
import os
import sys
import datetime
import warnings
import statistics
import numpy as np
import joblib
import psutil
import socket

warnings.filterwarnings('ignore')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

# --- Pipeline classes (must match how pkl files were saved) ---
class RandomForestPipeline:
    def __init__(self, model, scaler, feature_names, threshold):
        self.model = model; self.scaler = scaler
        self.feature_names = feature_names; self.threshold = threshold; self.name = "Random Forest"
    def predict(self, features):
        fs = self.scaler.transform([features])
        p = self.model.predict_proba(fs)[0][1]
        return {'prediction': 'Attack' if p >= self.threshold else 'Normal', 'probability': float(p), 'threshold': self.threshold, 'model': self.name}

class XGBoostPipeline:
    def __init__(self, model, feature_names, threshold=0.5):
        self.model = model; self.feature_names = feature_names; self.threshold = threshold; self.name = "XGBoost"
    def predict(self, features):
        p = self.model.predict_proba([features])[0][1]
        return {'prediction': 'Attack' if p >= self.threshold else 'Normal', 'probability': float(p), 'threshold': self.threshold, 'model': self.name}

class CNNPipeline:
    def __init__(self, model, scaler, feature_names, threshold=0.5):
        self.model = model; self.scaler = scaler
        self.feature_names = feature_names; self.threshold = threshold; self.name = "CNN"
    def predict(self, features):
        fs = self.scaler.transform([features])
        fc = fs.reshape(1, 1, -1)
        p = self.model.predict(fc, verbose=0)[0][0]
        return {'prediction': 'Attack' if p >= self.threshold else 'Normal', 'probability': float(p), 'threshold': self.threshold, 'model': self.name}

def get_current_features(window_seconds=5):
    now = datetime.datetime.now()
    hour = now.hour
    is_weekend = 1 if now.weekday() >= 5 else 0
    is_after_hours = 1 if hour < 8 or hour > 18 else 0

    net_start = psutil.net_io_counters()
    disk_start = psutil.disk_io_counters()
    time.sleep(window_seconds)
    net_end = psutil.net_io_counters()
    disk_end = psutil.disk_io_counters()

    users = psutil.users()
    total_logons = float(len(users) * 5)
    unique_pcs_logon = float(len(set([u.host for u in users if u.host])) or 1)

    disk_ops = (disk_end.read_count - disk_start.read_count) + (disk_end.write_count - disk_start.write_count)
    total_file_activities = float(disk_ops)
    unique_files = float(max(1, int(disk_ops * 0.1)))

    net_ops = (net_end.packets_sent - net_start.packets_sent) + (net_end.packets_recv - net_start.packets_recv)
    total_device_activities = float(net_ops)

    # BUG FIX: after_hours must be PROPORTIONAL to activity, not 0/1
    after_hours_logons  = float(is_after_hours * total_logons)
    after_hours_device  = float(is_after_hours * total_device_activities)
    after_hours_files   = float(is_after_hours * total_file_activities)

    features = [
        total_logons,                    # total_logons
        float(hour),                     # avg_logon_hour
        0.5,                             # std_logon_hour
        float(is_weekend * total_logons),# weekend_logons
        after_hours_logons,              # after_hours_logons
        unique_pcs_logon,                # unique_pcs_logon
        total_device_activities,          # total_device_activities
        1.0,                             # unique_pcs_device
        float(hour),                     # avg_device_hour
        after_hours_device,              # after_hours_device
        total_file_activities,            # total_file_activities
        unique_files,                    # unique_files
        1.0,                             # unique_pcs_file
        float(hour),                     # avg_file_hour
        after_hours_files,               # after_hours_files
    ]
    return features, {
        'disk_ops': int(disk_ops), 'net_ops': int(net_ops),
        'after_hours': is_after_hours, 'weekend': is_weekend,
    }

def main():
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")

    print("[*] Loading models...")
    rf_model = xgb_model = cnn_model = None

    try:
        rf_model = joblib.load(os.path.join(base, 'rf_complete_pipeline.pkl'))
        print("  [OK] Random Forest")
    except Exception as e:
        print(f"  [--] RF: {e}")

    try:
        xgb_model = joblib.load(os.path.join(base, 'xgb_complete_pipeline.pkl'))
        print("  [OK] XGBoost")
    except Exception as e:
        print(f"  [--] XGB: {e}")

    try:
        from tensorflow.keras.models import load_model as tf_load
        cnn_model = joblib.load(os.path.join(base, 'cnn_complete_pipeline.pkl'))
        cnn_model.model = tf_load(os.path.join(base, 'cnn_weights.h5'))
        print("  [OK] CNN")
    except Exception as e:
        print(f"  [--] CNN: {e}")

    if not any([rf_model, xgb_model, cnn_model]):
        print("No models loaded!"); return

    print()
    print("=" * 60)
    print("  LIVE HOST MONITOR — Sampling every 5 seconds")
    print("  Run simulate_attacks.py in another terminal!")
    print("  Press Ctrl+C to stop")
    print("=" * 60)

    while True:
        try:
            feats, stats = get_current_features(window_seconds=5)

            print()
            print("=" * 60)
            print(f"  [{time.strftime('%H:%M:%S')}]  Disk I/O: {stats['disk_ops']}  |  Net pkts: {stats['net_ops']}  |  After-hrs: {stats['after_hours']}")
            print("-" * 60)

            alerts = []
            for model_obj, tag in [(rf_model, "RF "), (xgb_model, "XGB"), (cnn_model, "CNN")]:
                if model_obj is None:
                    print(f"  [{tag}]  not loaded")
                    continue
                r = model_obj.predict(feats)
                pct = r['probability'] * 100
                filled = int(r['probability'] * 20)
                bar = '#' * filled + '-' * (20 - filled)
                flag = " <<< ATTACK!" if r['prediction'] == 'Attack' else ""
                print(f"  [{tag}]  [{bar}]  {pct:5.1f}%{flag}")
                if r['prediction'] == 'Attack':
                    alerts.append(f"{tag}={pct:.0f}%")

            if alerts:
                print(f"\n  >>> ALERT: {', '.join(alerts)} <<<")
            else:
                print(f"\n  Status: Normal")

        except KeyboardInterrupt:
            print("\n  Stopped.")
            break

if __name__ == "__main__":
    main()
