import os
import sys
import datetime
import platform
import subprocess
import numpy as np
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS


AI_MODELS_PATH = r"C:\Users\HANY\Desktop\frontend\backend\ai_models"
sys.path.append(AI_MODELS_PATH)


try:
    from cnn_pipeline import CNNPipeline
    model_pipeline = CNNPipeline()
except ImportError:
    print("Error: cnn_pipeline.py not found in the specified path.")
    model_pipeline = None


app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ids.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

AGENT_KEY = "mysecrettoken"
NUM_FEATURES = 15 


class Host(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host_name = db.Column(db.String(100), nullable=False)
    ip = db.Column(db.String(100))
    last_seen = db.Column(db.DateTime)
    status = db.Column(db.String(20))

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host_name = db.Column(db.String(100))
    ip = db.Column(db.String(100))
    threat_type = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    action = db.Column(db.String(100))
    time = db.Column(db.DateTime)


def block_ip(ip):
    """تنفيذ الحظر على مستوى نظام التشغيل"""
    try:
        system = platform.system()
        if system == "Windows":
         
            cmd = f'netsh advfirewall firewall add rule name="BLOCK_{ip}" dir=in action=block remoteip={ip}'
            subprocess.run(cmd, shell=True, check=True)
            print(f" IP {ip} has been blocked in Windows Firewall.")
        elif system == "Linux":
            cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
            subprocess.run(cmd, shell=True, check=True)
            print(f" IP {ip} has been blocked in Iptables.")
    except Exception as e:
        print(f" Error blocking IP {ip}: {e}")

def classify_threat(pred):
    """
    بما أن الموديل يخرج قيمة واحدة (Dense 1):
    0 تعني Normal
    1 تعني Attack
    """
  
    val = pred[0] if isinstance(pred, (list, np.ndarray)) else pred
    
 
    final_decision = 1 if val >= 0.5 else 0
    
    if final_decision == 0:
        return ("Normal", "Low")
    else:
   
        return ("Cyber Attack Detected", "High")
@app.route("/api/agent/host-report", methods=["POST"])
def agent_report():
    # التحقق من مفتاح الأمان
    if request.headers.get("X-Agent-Key") != AGENT_KEY:
        print("⚠️ Unauthorized access attempt blocked.")
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    host_name = data.get("host_name")
    ip = data.get("ip")
    features = data.get("features")
    current_time = datetime.datetime.now()

    # --- [Console Logging] بداية طباعة المعلومات في السيرفر ---
    print("\n" + "="*50)
    print(f"🕒 Time: {current_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🖥️  Host: {host_name} ({ip})")
    print(f"📡 Status: ONLINE ✅")
    print("-" * 30)

    # 1. تحديث قاعدة البيانات
    host = Host.query.filter_by(host_name=host_name).first()
    if not host:
        host = Host(host_name=host_name, ip=ip, last_seen=current_time, status="Online")
        db.session.add(host)
    else:
        host.last_seen = current_time
        host.status = "Online"
        host.ip = ip

    # 2. التنبؤ عبر الـ CNN
    threat, severity = "Normal", "Low"
    action = "No Action Taken"

    if model_pipeline and features:
        prediction = model_pipeline.predict(features)
        threat, severity = classify_threat(prediction)
        
        # طباعة نتيجة تحليل الذكاء الاصطناعي
        print(f"🧠 AI Analysis: {threat} | Severity: {severity}")

    # 3. اتخاذ القرار (Prevention Logic)
    if severity in ["High", "Critical"]:
        action = "PREVENTION ACTIVE: IP Blocked 🚫"
        print(f"🛑 CRITICAL: Executing actual prevention on IP: {ip}")
        block_ip(ip) # استدعاء دالة جدار الحماية
    
        new_alert = Alert(
            host_name=host_name, ip=ip, threat_type=threat, 
            severity=severity, action=action, time=current_time
        )
        db.session.add(new_alert)
    else:
        print(f"Safe: No threats detected. No action needed.")

    print(f" Final Action: {action}")
    print("="*50 + "\n")

    db.session.commit()
    return jsonify({
        "status": "Success", 
        "threats": threat, 
        "severity": severity, 
        "action": action,
        "time": current_time.isoformat()
    })
@app.route("/api/hosts", methods=["GET"])
def get_hosts():
    hosts = Host.query.all()
    return jsonify([{"host": h.host_name, "ip": h.ip, "status": h.status, "last_seen": h.last_seen} for h in hosts])

@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    alerts = Alert.query.order_by(Alert.time.desc()).all()
    return jsonify([{
        "host": a.host_name, "ip": a.ip, "threat": a.threat_type, 
        "severity": a.severity, "action": a.action, "time": a.time
    } for a in alerts])


if __name__ == "__main__":
    with app.app_context():
        # إنشاء الجداول
        db.create_all()
        print("Database initialized and tables created.")
    
    app.run(host='0.0.0.0', port=5000, debug=True)