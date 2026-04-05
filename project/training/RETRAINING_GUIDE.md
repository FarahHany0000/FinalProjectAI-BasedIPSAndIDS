# Network IDS — Model Retraining Guide

## Who This Is For

This guide is for the person responsible for training the XGBoost network detection models
on the **workstation** (training machine). The data has already been captured and prepared
on the laptop — you just need to train.

---

## Quick Start (TL;DR)

Everything is already prepared. On the workstation:

```bash
# 1. Install dependencies
pip install xgboost scikit-learn pandas numpy scipy scapy joblib

# 2. Navigate to the network module
cd project/backend/src/infra/network_module

# 3. (Optional) Verify data quality
python data_pipeline/verify_data.py

# 4. Train both models
python data_pipeline/train.py

# 5. Done! Copy these 4 files back to the laptop:
#    project/backend/ai_models/network_xgb/binary_model.json
#    project/backend/ai_models/network_xgb/attack_model.json
#    project/backend/ai_models/network_xgb/scaler.pkl
#    project/backend/ai_models/network_xgb/feature_names.json
```

That's it. The rest of this guide explains the details.

---

## 1. System Architecture

### 1.1 Two-Stage XGBoost Pipeline

The IDS uses a two-stage model for network attack detection:

- **Stage 1 — Binary model** (`binary_model.json`): Normal vs Attack (threshold 0.70)
- **Stage 2 — Attack-type model** (`attack_model.json`): Which attack type (5 classes)

Both models operate on **10-packet sliding windows**. Every 10 packets are converted
into **56 behavioral features** (TCP flag ratios, port entropy, packet size stats,
protocol distribution, etc.) by `feature_engineer.py`.

### 1.2 The 5 AI-Trained Attack Classes

| Class | Attack | Tool used to capture |
|-------|--------|---------------------|
| `PortScan` | TCP SYN scan | `nmap -sS -p 1-65535` |
| `SSHBrute` | SSH brute force | `hydra` targeting port 22 |
| `FTPBrute` | FTP brute force | `hydra` targeting port 21 |
| `SYNFlood` | TCP SYN flood | `hping3 -S --flood -p 80` |
| `ARPSpoof` | ARP spoofing | Scapy ARP reply/request flood |

**DoS/DDoS types** (ICMP Flood, DDoS UDP, DDoS RAW, DDoS) are handled by heuristic
rules in `live_capture.py`, not by the AI model. This is intentional.

### 1.3 Network Environment

- **Attacker**: Kali Linux VM at `192.168.253.129` on VMware VMnet1 (host-only)
- **Target**: Windows host at `192.168.253.1` on VMnet1
- **Interface**: `VMware Network Adapter VMnet1` — isolated, no internet

---

## 2. What's Already Done

All data has been captured, processed, and balanced on the laptop. These files are
included in the project and ready to use:

### 2.1 PCAP Files (Raw Captures)

Located in `project/backend/src/infra/network_module/captures/`:

| File | Packets | Description |
|------|---------|-------------|
| `normal.pcap` | 2,478 | Clean traffic: pings + idle + HTTP |
| `portscan.pcap` | 344,941 | Filtered SYN probes from Kali |
| `sshbrute.pcap` | 130,697 | Hydra SSH brute force |
| `synflood.pcap` | 192,314 | hping3 SYN flood |
| `arpspoof.pcap` | 6,200 | Scapy ARP flood |
| `ftpbrute.pcap` | 25,325 | Hydra FTP brute force |

### 2.2 Processed CSVs

Located in `project/backend/src/infra/network_module/data_pipeline/`:

| File | Content |
|------|---------|
| `training_data_live.csv` | Raw converted data: 70,193 windows (unbalanced) |
| `training_data_balanced.csv` | Balanced data: 30,000 windows (5,000 per class) |

### 2.3 Training Scripts

All scripts are in `project/backend/src/infra/network_module/data_pipeline/`:

| Script | What it does |
|--------|-------------|
| `pcap_to_csv.py` | Converts PCAPs to CSV using same feature pipeline as live capture |
| `balance_data.py` | Filters ambiguous PortScan windows + balances to 5,000 per class |
| `verify_data.py` | Runs quality checks on the balanced data |
| `train.py` | Trains both XGBoost models (binary + attack classifier) |

---

## 3. Training on the Workstation

### 3.1 Requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| OS | Windows 10/11 or Linux | Both work |
| Python | 3.10+ | 3.12 also works |
| RAM | 8 GB | 16 GB preferred |
| Storage | 5 GB free | For CSVs and model files |
| GPU | Not required | Auto-detected if CUDA available |

### 3.2 Install Dependencies

```bash
pip install xgboost scikit-learn pandas numpy scipy scapy joblib
```

For GPU acceleration (optional):
```bash
pip install xgboost[cuda]
```

### 3.3 Copy the Project

Copy the **entire** `FinalProjectAI-BasedIPSAndIDS/` folder to the workstation.
USB drive or network share — doesn't matter. Everything needed is inside the project.

### 3.4 Run Training

```bash
cd project/backend/src/infra/network_module
python data_pipeline/train.py
```

The script will:
1. Load `training_data_balanced.csv` (30,000 samples, 56 features, 6 classes)
2. Auto-detect GPU (uses CUDA if available, falls back to CPU)
3. Train Stage 1: Binary model (Normal vs Attack)
4. Train Stage 2: Attack classifier (5 attack types)
5. Evaluate on held-out test set
6. Save 4 files to `project/backend/ai_models/network_xgb/`

**Expected output:**
```
============================================================
  XGBoost Network IDS - Training
============================================================

  Training data: 30,000 samples
  Features: 56

  Train: 20,400  Val: 3,600  Test: 6,000

  Stage 1: Binary Model (Normal vs Attack)
  Accuracy: 100.0%

  Stage 2: Attack Classifier (5 classes)

  Per-Class Results:
  Normal           100.0%
  ARPSpoof         100.0%  [PASS]
  FTPBrute         100.0%  [PASS]
  PortScan         100.0%  [PASS]
  SSHBrute          99.9%  [PASS]
  SYNFlood         100.0%  [PASS]
============================================================
```

**Training time:** ~4 seconds on GPU, ~2 minutes on CPU.

### 3.5 Expected Training Results

All classes should achieve 99%+ accuracy:

```
  Normal           100.0%
  ARPSpoof         100.0%
  FTPBrute         100.0%
  PortScan         100.0%
  SSHBrute          99.9%
  SYNFlood         100.0%
  Binary (Stage 1) 100.0%
```

**PortScan note:** The `balance_data.py` script automatically filters out ambiguous
PortScan windows where `unique_dst_ports=1` (nmap retries hitting the same port).
These windows are genuinely indistinguishable from SYNFlood at the packet level.
After filtering, all remaining PortScan windows clearly show port scanning behavior
(multiple destination ports per window), and the model achieves 100% accuracy.

### 3.6 Verify Data (Optional)

Before training, you can verify the balanced data:

```bash
python data_pipeline/verify_data.py
```

Expected: **6/6 checks pass.** The script checks the dominant port (mode) per window
for SSHBrute and FTPBrute, not the mean — so response traffic on ephemeral ports
does not cause false failures.

---

## 4. After Training

### 4.1 Files to Copy Back

Copy these 4 files from the workstation back to the laptop:

```
project/backend/ai_models/network_xgb/binary_model.json    <- Stage 1 model
project/backend/ai_models/network_xgb/attack_model.json    <- Stage 2 model
project/backend/ai_models/network_xgb/scaler.pkl           <- Feature normalizer
project/backend/ai_models/network_xgb/feature_names.json   <- Feature name list
```

Place them in the **same paths** on the laptop, replacing existing files.

### 4.2 Test on the Laptop

1. Restart the backend (kill old process, run `START_SYSTEM.bat` or `python app.py`)
2. The backend will load the new models automatically
3. Run attacks from Kali to verify:

```bash
# From Kali VM (192.168.253.129):
sudo nmap -sS -p 1-65535 192.168.253.1 -T4              # expect: PortScan
sudo hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.253.1 -t 16   # expect: SSHBrute
sudo hping3 -S --flood -p 80 192.168.253.1              # expect: SYNFlood
sudo hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://192.168.253.1 -t 8   # expect: FTPBrute
# ARPSpoof: use arpspoof or Scapy script                 # expect: ARPSpoof
```

Check detections on the frontend: `http://127.0.0.1:3000` -> Network page.

---

## 5. Re-Running the Full Pipeline (If Needed)

If you need to recapture PCAPs and rebuild from scratch, run the scripts in order:

```bash
cd project/backend/src/infra/network_module

# Step 1: Convert PCAPs to CSV (requires PCAP files in captures/)
python data_pipeline/pcap_to_csv.py

# Step 2: Balance the classes
python data_pipeline/balance_data.py

# Step 3: Verify data quality
python data_pipeline/verify_data.py

# Step 4: Train the models
python data_pipeline/train.py
```

### 5.1 Capturing New PCAPs (Laptop Only)

If you need to recapture traffic, here's how each PCAP was captured:

**Normal traffic** — On Windows, start Wireshark on VMnet1. From Kali:
```bash
# Kill any residual attack processes first!
sudo pkill -f nmap; sudo pkill -f hping3; sudo pkill -f hydra; sudo pkill -f arpspoof

# Wait 10 seconds for connections to close
sleep 10

# Generate normal activity
ping -c 500 -i 0.2 192.168.253.1     # slow pings
curl -s http://192.168.253.1:5000/api/agent/health  # HTTP request
# Wait 60 seconds (idle VMware traffic)
ping -c 300 -i 0.2 192.168.253.1     # more pings
```
Save as `normal.pcap`. Verify SYN-only ratio < 5%.

**PortScan:**
```bash
sudo nmap -sS -p 1-65535 192.168.253.1 --max-retries 1 -T4
```
Run 2-3 times. Save as `portscan.pcap`.

**SSHBrute:**
```bash
sudo hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.253.1 -t 32
```
Run 5-10 minutes. Save as `sshbrute.pcap`.

**SYNFlood:**
```bash
sudo hping3 -S --flood -p 80 192.168.253.1
```
Run 20-30 seconds ONLY. Save as `synflood.pcap`.

**ARPSpoof** — Use a Scapy script on Kali (arpspoof tool is too slow):
```python
from scapy.all import *
target_ip = "192.168.253.1"
target_mac = "ff:ff:ff:ff:ff:ff"
gateway_ip = "192.168.253.2"
# Send 1500 ARP replies + 1500 ARP requests + 1000 gratuitous ARP
for i in range(1500):
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=0)
for i in range(1500):
    send(ARP(op=1, pdst=target_ip, psrc=gateway_ip), verbose=0)
for i in range(1000):
    send(ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip, hwsrc=get_if_hwaddr(conf.iface)), verbose=0)
```
Save as `arpspoof.pcap`.

**FTPBrute** — Start an FTP server on Windows first (pyftpdlib or FileZilla), then:
```bash
sudo hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://192.168.253.1 -t 32
```
Run 5-10 minutes. Save as `ftpbrute.pcap`.

---

## 6. Important Files Reference

| File | Purpose | Modify? |
|------|---------|---------|
| `ai_models/network_xgb/binary_model.json` | Stage 1 model | Replace after training |
| `ai_models/network_xgb/attack_model.json` | Stage 2 model | Replace after training |
| `ai_models/network_xgb/scaler.pkl` | Feature normalizer | Replace after training |
| `ai_models/network_xgb/feature_names.json` | Feature names | Replace after training |
| `data_pipeline/pcap_to_csv.py` | PCAP to CSV converter | No |
| `data_pipeline/balance_data.py` | Class balancing | No |
| `data_pipeline/verify_data.py` | Data quality checks | No |
| `data_pipeline/train.py` | Model training | No |
| `data_pipeline/training_data_balanced.csv` | Ready-to-train data | No (auto-generated) |
| `sniffer/packet_parser.py` | Per-packet feature extraction | **Never modify** |
| `data_pipeline/feature_engineer.py` | Window feature computation | **Never modify** |
| `config/settings.py` | Attack classes, XGBoost params | Only `device: cpu/cuda` |
| `sniffer/live_capture.py` | Live sniffer + heuristic rules | **Never modify** |

---

## 7. Heuristic Rules — Do Not Touch

The file `live_capture.py` contains `_heuristic_override()` with rules for DoS/DDoS
types that are NOT in the training data. These must stay as-is:

- ICMP Flood (icmp_cnt >= 6, icmp_ratio >= 0.25)
- DDoS UDP (udp_ratio >= 0.5, pkt_cnt >= 12)
- PortScan (unique_dst_ports_low >= 3)
- SSHBrute (dport_min == 22, tcp_ratio > 0.3)
- FTPBrute (dport_min == 21, tcp_ratio > 0.3)
- SYNFlood (syn_ratio > 0.40)
- DDoS RAW (pkt_cnt >= 15, proto_entropy >= 1.0)
- DDoS (pkt_cnt >= 18, unique_ports >= 4)
- ARPSpoof (arp_ratio >= 0.10, arp_cnt >= 1)

These rules provide fallback detection. After retraining, the AI model handles the
5 trained classes with high confidence, and the rules catch edge cases and DoS/DDoS types.

---

## 8. Checklist

### On the Workstation

- [ ] Project folder copied from laptop
- [ ] Python 3.10+ installed
- [ ] Dependencies installed: `pip install xgboost scikit-learn pandas numpy scipy scapy joblib`
- [ ] Run `python data_pipeline/train.py` (from `network_module/` directory)
- [ ] Training completes without errors
- [ ] All classes 99%+ accuracy (including PortScan)
- [ ] 4 model files produced in `ai_models/network_xgb/`

### Back on the Laptop

- [ ] 4 model files copied to `project/backend/ai_models/network_xgb/`
- [ ] Backend restarted
- [ ] Live attack tests pass from Kali VM
