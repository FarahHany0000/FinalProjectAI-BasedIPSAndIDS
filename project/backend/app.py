import os
import sys
import datetime
import platform
import subprocess
import numpy as np
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

# إعداد المسارات
sys.path.append(r"C:\Users\HANY\Desktop\frontend\backend\ai_models")
from cnn_pipeline import CNNPipeline

app = Flask(__name__)
CORS(app)

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ids.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# الموديلات (Tables)
class Host(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host_name = db.Column(db.String(100))
    ip = db.Column(db.String(100))
    last_seen = db.Column(db.DateTime)
    status = db.Column(db.String(20))
    action = db.Column(db.String(100))

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host_name = db.Column(db.String(100))
    ip = db.Column(db.String(100))
    threat_type = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    action = db.Column(db.String(100))
    time = db.Column(db.DateTime)

# تحميل موديل الـ AI
try:
    model_pipeline = CNNPipeline()
except Exception as e:
    print(f"Model Init Error: {e}")
    model_pipeline = None
# ... (نفس الكود السابق من استيراد وموديلات)

# مسار لجلب قائمة الأجهزة (يعمل معه ملف Host.js)
@app.route("/api/hosts", methods=["GET"])
def get_hosts():
    hosts = Host.query.all()
    output = []
    for h in hosts:
        output.append({
            "host_name": h.host_name,
            "ip": h.ip,
            "last_seen": h.last_seen.isoformat() if h.last_seen else None,
            "status": h.status,
            "action": h.action
        })
    return jsonify(output)

# مسار لجلب سجلات التنبيهات لجهاز معين (يعمل معه ملف HostLogs.js)
@app.route("/api/alerts/<hostname>", methods=["GET"])
def get_alerts(hostname):
    alerts = Alert.query.filter_by(host_name=hostname).order_by(Alert.time.desc()).all()
    output = []
    for a in alerts:
        output.append({
            "threat": a.threat_type,
            "severity": a.severity,
            "action": a.action,
            "time": a.time.isoformat() if a.time else None
        })
    return jsonify(output)

# ... (بقية كود الـ agent_report كما هو)
@app.route("/api/agent/host-report", methods=["POST"])
def agent_report():
    try:
        data = request.json
        if not data: return jsonify({"error": "No data"}), 400
        
        features = data.get("features")
        host_name = data.get("host_name")
        ip = data.get("ip")
        
        threat, severity, action = ("Normal", "Low", "No Action")

        # التنبؤ (مع حماية كاملة)
        if model_pipeline and features:
            try:
                # الموديل يتوقع 15 ميزة
                prediction = model_pipeline.predict(features)
                if prediction[0] == 1:
                    threat, severity, action = "Attack", "High", "IP BLOCKED"
                    # block_ip_firewall(ip) # فعلها بعد التأكد من عمل السيرفر
            except Exception as e:
                print(f"Prediction Error: {e}")

        # تحديث قاعدة البيانات
        with app.app_context():
            host = Host.query.filter_by(host_name=host_name).first()
            if not host:
                host = Host(host_name=host_name, ip=ip, last_seen=datetime.datetime.now(), status="Online", action=action)
                db.session.add(host)
            else:
                host.last_seen = datetime.datetime.now()
                host.action = action
                host.status = "Online"
            
            if threat != "Normal":
                alert = Alert(host_name=host_name, ip=ip, threat_type=threat, severity=severity, action=action, time=datetime.datetime.now())
                db.session.add(alert)
            
            db.session.commit()
            
        return jsonify({"threats": threat, "severity": severity, "action": action})

    except Exception as e:
        print(f"🔥 CRITICAL ERROR: {e}")
        return jsonify({"error": "Internal Error"}), 500

if __name__ == "__main__":
    with app.app_context():
        # db.drop_all() # فك التهميش عن هذا السطر لو استمر الخطأ 500 لمرة واحدة فقط
        db.create_all()
    app.run(host='0.0.0.0', port=5000, threaded=False) # threaded=False يحل مشاكل الـ AI مع الـ SQL