# AI-Based IDS/IPS System

## 📖 Overview

A dual-layer **Intrusion Detection & Prevention System** powered by AI:
- **Network IDS/IPS**: Real-time packet capture → 2-stage XGBoost detects 8+ attack types + auto-blocks via firewall
- **Host IDS/IPS**: 15 CERT r4.2 features → XGBoost (threshold 0.65) detects insider threats + lock screen, USB disable, process kill
- **Alert Dialog**: Fullscreen threat alert with admin password authentication
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

### 3. Host Agent (on monitored devices)
```bash
cd deploy/host_agent
pip install -r requirements.txt
python host_agent.py
```
See `deploy/host_agent/README_AGENT.md` for full setup instructions.

### 4. Login
- **Username:** admin
- **Password:** admin

---

## 📁 Project Structure

```
FinalProjectAI-BasedIPSAndIDS/
├── README.md
├── host_attack_simulation.py      (Host attack testing tool)
├── deploy/
│   └── host_agent/                (Deploy package for client machines)
│       ├── host_agent.py
│       ├── alert_ui.py
│       ├── config.ini
│       ├── install_agent.py
│       ├── requirements.txt
│       └── README_AGENT.md
└── project/
    ├── agents/
    │   └── host_agent/            (Development copy of host agent)
    ├── backend/
    │   ├── app.py                 (Flask app + startup)
    │   ├── requirements.txt
    │   ├── ai_models/
    │   │   ├── host_cnn/          (XGBoost + RF for host detection)
    │   │   └── network_xgb/       (2-stage XGBoost for network)
    │   ├── models/                (SQLAlchemy ORM)
    │   ├── controllers/           (Business logic)
    │   ├── routes/                (Flask blueprints)
    │   ├── utils/                 (Response orchestrator, pipelines)
    │   └── src/infra/
    │       ├── model_loader.py    (AI model loading)
    │       └── network_module/
    │           ├── config/        (Thresholds & settings)
    │           ├── sniffer/       (Live capture + packet parser)
    │           └── data_pipeline/ (52-feature engineering)
    └── frontend/
        └── src/Components/
            ├── Dashboard/         (Stats + threat overview)
            ├── Network/           (Network alerts)
            ├── Host/              (Host monitoring)
            ├── Controls/          (Prevention settings)
            └── Agents/            (Registered agents)
```

---

## ✨ Features

- **8+ Attack Types**: PortScan, SSHBrute, FTPBrute, ARPSpoof, SYNFlood (AI) + ICMP Flood, DDoS UDP, DDoS RAW (heuristic)
- **Host Insider Threats**: USB detection, file activity, after-hours monitoring, network anomalies
- **Real-Time Alerts**: Socket.IO live updates to dashboard
- **Severity-Based Auto-Block**: Critical (3 alerts) → High (10) → Medium (15) before firewall block
- **Host Prevention**: Lock screen + disable USB + kill processes + fullscreen alert dialog
- **Admin Authentication**: Threat alert requires password to dismiss

---

## ⚙️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Flask + Flask-SocketIO |
| Frontend | React + Vite |
| Network AI | XGBoost (binary 0.70 + multi-class 0.50) |
| Host AI | XGBoost (0.65) + Random Forest |
| Sniffer | Scapy (52 features per window) |
| Database | SQLite |
| Real-time | Socket.IO |
| Alert UI | pywebview (HTML/CSS) |
