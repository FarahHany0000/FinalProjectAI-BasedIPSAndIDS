# AI-Based IDS/IPS System

## 📖 Overview

A dual-layer **Intrusion Detection & Prevention System** powered by AI:
- **Network IDS**: Real-time packet capture → XGBoost (binary + multi-class) detects 5 attack types
- **Host IDS**: Collects 15 CERT features → XGBoost + Random Forest detects insider threats
- **Prevention**: Auto-blocks attacker IPs via Windows Firewall rules
- **Dashboard**: React frontend with real-time Socket.IO alerts

---

## 🚀 How to Run

### 1. Backend (Flask API)
```bash
cd project/backend
python -m venv ../../venv          # first time only
../../venv/Scripts/activate        # Windows
pip install -r requirements.txt    # first time only
python app.py
```
Backend runs on **http://127.0.0.1:5000**

### 2. Frontend (React)
```bash
cd project/frontend
npm install          # first time only
npm run dev
```
Frontend runs on **http://127.0.0.1:3000**

### 3. Login
- **Username:** admin
- **Password:** admin

---

## 🧪 Testing Attacks (from Kali VM)

```bash
# Port Scan
sudo nmap -sS -T4 --top-ports 100 -Pn 192.168.253.1

# SSH Brute Force
sudo hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.253.1

# SYN Flood
sudo hping3 -S --flood -V -p 80 192.168.253.1
```

---

## 📁 Project Structure

```
FinalProjectAI-BasedIPSAndIDS/
├── .gitignore
├── README.md
├── venv/                          (Python env - not tracked)
└── project/
    ├── doc/                       (Documentation)
    │   └── PREVENTION_METHODOLOGY.md
    ├── training/                  (Model training - separate from runtime)
    │   ├── captures/              (.pcap files for training)
    │   ├── csv/                   (Training datasets)
    │   ├── data_pipeline/         (train.py, balance, pcap_to_csv, verify)
    │   └── RETRAINING_GUIDE.md
    ├── agents/
    │   ├── host_agent/            (Host IDS agent - runs on endpoints)
    │   │   ├── host_agent.py
    │   │   └── config.ini
    │   └── network_sensor/        (Network IDS sensor)
    │       └── network_sensor.py
    ├── backend/
    │   ├── app.py                 (Flask app factory + startup)
    │   ├── extensions.py          (DB, CORS, SocketIO init)
    │   ├── requirements.txt
    │   ├── ai_models/             (Pre-trained model files)
    │   │   ├── host_cnn/          (XGBoost, RF, CNN for host)
    │   │   └── network_xgb/       (XGBoost binary + attack)
    │   ├── models/                (SQLAlchemy ORM models)
    │   ├── controllers/           (Business logic controllers)
    │   ├── routes/                (Flask route blueprints)
    │   ├── middleware/            (Auth decorators)
    │   ├── utils/                 (Constants, model pipelines)
    │   └── src/
    │       ├── domain/            (Core entities & enums)
    │       ├── application/       (Service layer)
    │       ├── api/               (API blueprint & endpoints)
    │       └── infra/             (Model loader + network module)
    │           └── network_module/
    │               ├── config/    (IDS settings & thresholds)
    │               ├── sniffer/   (Live capture + packet parser)
    │               └── data_pipeline/ (Feature engineering - runtime)
    └── frontend/
        ├── index.html
        ├── package.json
        ├── vite.config.js
        └── src/
            ├── App.jsx            (Router setup)
            ├── socket.js          (Socket.IO client)
            ├── config.js          (API base URL)
            ├── context/           (System state context)
            └── Components/
                ├── Login/         (Auth page)
                ├── Dashboard/     (Main stats)
                ├── Network/       (Network alerts - real-time)
                ├── Host/          (Host monitoring)
                ├── HostLogs/      (Host event logs)
                ├── AlertPage/     (All alerts view)
                ├── Agents/        (Registered agents)
                ├── Controls/      (Prevention controls)
                ├── Sidebar/       (Navigation)
                └── NotFound/      (404 page)
```

---

## ✨ Features

- **5 AI Attack Types**: PortScan, SSHBrute, FTPBrute, ARPSpoof, SYNFlood
- **Heuristic Detection**: ICMPFlood, DDoS, DDoS-UDP, DDoS-RAW, DDoS-ICMP
- **Real-Time Alerts**: Socket.IO live updates to browser
- **Prevention Mode**: Auto-blocks IPs after 5+ alerts via firewall rules
- **Clean Architecture**: Domain → Application → Infrastructure → API
- **Host Monitoring**: Insider threat detection via CERT features

---

## ⚙️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Flask + Flask-SocketIO |
| Frontend | React + Vite |
| Network AI | XGBoost (binary + multi-class) |
| Host AI | XGBoost + Random Forest + TensorFlow CNN |
| Sniffer | Scapy |
| Database | SQLite |
| Real-time | Socket.IO |
