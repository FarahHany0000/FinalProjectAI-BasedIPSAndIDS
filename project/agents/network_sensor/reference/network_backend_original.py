# app.py - Full IDS Backend with XGBoost
from flask import Flask, request, jsonify
from flask_cors import CORS
import pyodbc
import joblib
import numpy as np
import datetime

# ================= Flask Setup =================
app = Flask(__name__)
CORS(app)

# ================= SQL Server Setup =================
server = r'DESKTOP-7HIR3KC\MSQLSERVER'
database = 'IDS_DB'
username = 'app_user'
password = 'AppPass2026!'
driver = '{ODBC Driver 17 for SQL Server}'

conn_str = f'DRIVER={driver};SERVER={server};DATABASE={database};UID={username};PWD={password}'
conn = pyodbc.connect(conn_str, autocommit=True)
cursor = conn.cursor()

# ================= Create events table if not exists =================
cursor.execute("""
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='events' AND xtype='U')
CREATE TABLE events (
    id INT IDENTITY(1,1) PRIMARY KEY,
    date NVARCHAR(50),
    host NVARCHAR(50),
    attack_type NVARCHAR(50),
    severity NVARCHAR(50),
    action NVARCHAR(50),
    final_state NVARCHAR(50)
)
""")
conn.commit()

# ================= Load AI Models =================
binary_model_path = r"C:\Users\HANY\Desktop\frontend\Network\ai_models\xgboost_binary_idps.pkl"
multi_model_path = r"C:\Users\HANY\Desktop\frontend\Network\ai_models\xgboost_multiclass_idps.pkl"
label_encoder_path = r"C:\Users\HANY\Desktop\frontend\Network\ai_models\label_encoder_multiclass.pkl"

binary_model = joblib.load(binary_model_path)
multi_model = joblib.load(multi_model_path)
label_encoder = joblib.load(label_encoder_path)

try:
    features = binary_model.get_booster().feature_names
except:
    features = ["init_fwd_win_byts", "fwd_seg_size_min", "subflow_fwd_byts", "flow_iat_max",
                "fwd_iat_max", "fwd_iat_tot", "totlen_fwd_pkts", "flow_iat_mean", "bwd_pktss",
                "flow_iat_min", "fwd_header_len", "fwd_seg_size_avg", "fwd_iat_min", "fwd_iat_mean",
                "init_bwd_win_byts", "fwd_pktss", "flow_pktss", "fwd_pkt_len_max", "fwd_pkt_len_mean",
                "flow_duration"]

print("Detected features:", features)

# ================= Helper Functions =================
def generate_action(severity):
    return {
        "Critical": "Host Isolated",
        "High": "IP Blacklisted",
        "Medium": "Traffic Dropped",
        "Low": "Firewall Rule Added"
    }.get(severity, "Connection Reset")

def predict_attack(features_dict):
    try:
        X = np.array([features_dict[f] for f in features]).reshape(1, -1)
    except KeyError as e:
        return {"error": f"Missing feature: {e}"}

    binary_pred = binary_model.predict(X)[0]
    if binary_pred == 0:
        return {"type": "Normal", "severity": "Low", "action": generate_action("Low"), "final_state": "Online"}

    multi_pred = multi_model.predict(X)
    attack_type = label_encoder.inverse_transform(multi_pred)[0]

    severity_map = {
        "Malware": "Critical",
        "DDoS": "High",
        "Phishing": "Medium",
        "Recon": "Low"
    }
    severity = severity_map.get(attack_type, "Low")
    action = generate_action(severity)
    final_state = "Offline" if severity == "Critical" else "Online"

    return {"type": attack_type, "severity": severity, "action": action, "final_state": final_state}

# ================= Routes =================
@app.route("/predict", methods=["POST"])
def predict():
    data = request.json
    host = data.get("host", "Host-Unknown")
    features_input = data.get("features", {})

    result = predict_attack(features_input)
    if "error" in result:
        return jsonify(result), 400

    result["date"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result["host"] = host

    cursor.execute("""
        INSERT INTO events (date, host, attack_type, severity, action, final_state)
        VALUES (?, ?, ?, ?, ?, ?)
    """, result["date"], result["host"], result["type"], result["severity"], result["action"], result["final_state"])
    conn.commit()

    return jsonify(result)

@app.route("/events", methods=["GET"])
def get_events():
    cursor.execute("SELECT date, host, attack_type, severity, action, final_state FROM events")
    rows = cursor.fetchall()
    events = [{"date": r[0], "host": r[1], "type": r[2], "severity": r[3], "action": r[4], "final_state": r[5]} for r in rows]
    return jsonify(events)

@app.route("/features", methods=["GET"])
def get_features():
    return jsonify(features)

@app.route("/attacks", methods=["GET"])
def get_attacks():
    return jsonify(list(label_encoder.classes_))

# ================= Run Server =================
if __name__ == "__main__":
    print("Starting IDS Backend App...")
    app.run(debug=True)