# Network Module — IDS/IPS Network Layer Detection

## Overview

The `network_module` provides real-time network intrusion detection using AI-powered sliding-window feature extraction and XGBoost/RandomForest/Neural Network models.

**Detects 5 attack types:**
- **PortScan** — TCP SYN port scanning (nmap)
- **SSHBrute** — SSH brute force attacks
- **FTPBrute** — FTP brute force attacks
- **ARPSpoof** — ARP spoofing / MITM attacks
- **SYNFlood** — TCP SYN flood DoS attacks

## Architecture

```
Live Network Traffic
    ↓ (Scapy)
Packet Parser
    ↓
Sliding Window (10 packets)
    ↓
Feature Engine (48 features)
    ↓
Model Inference (XGBoost)
    ↓
Alert (confidence > threshold)
```

## Key Features

- **48 Behavioral Features** per 10-packet window:
  - Packet size stats (mean, std, min, max, sum)
  - IP/TCP/UDP/ICMP header fields
  - TCP flags (SYN/ACK/FIN/RST) counts & ratios
  - Port diversity & entropy
  - Protocol ratios and distribution
  - TTL, DSCP, ARP/ICMP specific features

- **2-Stage Detection Pipeline:**
  1. Binary classification: Attack or Normal (confidence threshold: 0.70)
  2. Multi-class classification: Which attack type (5 classes)

- **Thread-Safe Live Capture:**
  - Background thread for packet sniffing
  - Sliding window buffering with 5-second timeout
  - Result queue: up to 10,000 results
  - No blocking on main application

## Directory Structure

```
network_module/
├── __init__.py
├── config/
│   ├── __init__.py
│   └── settings.py              # Central configuration
├── sniffer/
│   ├── __init__.py
│   ├── packet_parser.py         # Scapy → feature dict
│   ├── live_capture.py          # Real-time capture engine
│   └── pcap_replay.py           # PCAP file analysis
├── data_pipeline/
│   ├── __init__.py
│   └── feature_engineer.py      # Window feature extraction
└── README.md (this file)
```

## Usage

### 1. Live Network Monitoring

```python
from network_module.sniffer.live_capture import LiveSniffer
from backend.utils.model_loader import load_xgboost_model

# Load a pre-trained model
model_engine = load_xgboost_model()

# Create sniffer
sniffer = LiveSniffer(
    engine=model_engine,
    iface="Realtek PCIe 2.5GbE Family Controller",  # Change to your interface
    threshold=0.70
)

# Start capturing
sniffer.start()

# Get detection results
while True:
    results = sniffer.get_results(max_items=10)
    for result in results:
        if result["alert"]:
            print(f"ATTACK: {result['label']} (conf={result['confidence']:.3f})")
        else:
            print(f"Normal window #{result['window_id']}")

    # Show stats
    stats = sniffer.get_stats()
    print(f"Packets: {stats['total_packets']} | Windows: {stats['total_windows']} | Attacks detected: {stats['attacks_detected']}")

# Stop
sniffer.stop()
```

### 2. Analyze a PCAP File

```python
from network_module.sniffer.pcap_replay import PcapPlayer
from backend.utils.model_loader import load_xgboost_model

model_engine = load_xgboost_model()
player = PcapPlayer(engine=model_engine, threshold=0.70)

results = player.process_pcap(
    "capture.pcap",
    realtime_pace=False,  # Process as fast as possible
    max_packets=10000     # Optional: limit packets
)

# Analyze results
attacks = [r for r in results if r["alert"]]
print(f"Attacks detected: {len(attacks)}/{len(results)} windows")
```

### 3. Test with Network Sensor Agent

```python
from agents.network_sensor.network_sensor import NetworkSensorAgent
from backend.utils.model_loader import load_xgboost_model

model_engine = load_xgboost_model()
agent = NetworkSensorAgent(
    model_engine=model_engine,
    hostname="NetworkSensor-1"
)

# Run for 60 seconds
agent.run_loop(duration=60)
```

## Configuration

Edit `network_module/config/settings.py`:

| Setting | Default | Purpose |
|---------|---------|---------|
| `WINDOW_SIZE` | 10 | Packets per sliding window |
| `WINDOW_TIMEOUT` | 5.0 | Seconds before flushing partial windows |
| `CONFIDENCE_THRESHOLD` | 0.70 | Min confidence to classify as attack |
| `DEFAULT_IFACE` | "Realtek PCIe 2.5GbE Family Controller" | Network interface (change to yours!) |
| `PROTOCOL_MAP` | {...} | Protocol encoding (TCP=1, UDP=2, etc.) |
| `ATTACK_CLASSES` | [...] | Detected attack types |

## Testing on Kali VM

### Setup

1. **VMware configuration:**
   - Create Host-Only network (VMnet1)
   - Windows: Connect to VMnet1
   - Kali: Connect to VMnet1
   - Install Npcap on Windows: https://npcap.com (check "WinPcap API-compatible Mode")

2. **Find your interface name:**
   ```bash
   ipconfig  # Windows
   # Look for VMnet1 adapter
   ```

3. **Update settings:**
   ```python
   # network_module/config/settings.py
   DEFAULT_IFACE = "Your VMnet1 Adapter Name"
   ```

### Attack Commands (run on Kali)

```bash
# Get Windows host IP on VMnet1 first
# Example: 192.168.253.1

# Port Scan
sudo nmap -sS -T4 --top-ports 100 --min-rate 50 -Pn 192.168.253.1

# SYN Flood
sudo hping3 -S -i u10 -p 80 192.168.253.1

# SSH Brute Force
sudo hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.253.1

# FTP Brute Force
sudo hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://192.168.253.1

# ARP Spoofing
sudo arpspoof -i eth0 -t 192.168.253.1 <gateway_ip>
```

## Dependencies

```
scapy>=2.5.0
numpy>=1.21.0
pandas>=1.3.0
scipy>=1.7.0
xgboost>=1.5.0
```

Install with:
```bash
pip install -r network_module/requirements.txt
```

## Performance

- **Latency:** ~5-10ms per window (10 packets)
- **Memory:** ~500MB for live capture
- **CPU:** ~15-25% per core on i7, depending on traffic volume
- **Detection Rate:** 80-100% depending on attack type
- **False Positive Rate:** <5% on normal traffic

## Integration with Backend

The `NetworkSensorAgent` sends alerts to the backend:

```python
POST http://127.0.0.1:5000/alert
{
    "source": "NetworkSensor-1",
    "timestamp": "2024-04-03 12:34:56",
    "attack_type": "SYNFlood",       # or PortScan, SSHBrute, etc.
    "confidence": 0.987,
    "n_packets": 10
}
```

## Troubleshooting

**"No module named 'scapy'"**
```bash
pip install scapy
```

**"Permission denied" (packet capture)**
- Linux: Run with `sudo` or add user to pcap group
- Windows: Run as Administrator
- macOS: Grant network permissions in System Preferences

**"Interface not found"**
```python
# List available interfaces
from scapy.all import get_if_list
print(get_if_list())

# Update settings.py with correct name
DEFAULT_IFACE = "your_interface_name"
```

**"Model inference is slow"**
- Check GPU availability: `python -c "import xgboost; print(xgboost.get_config())"`
- Ensure CUDA is installed for GPU acceleration
- Verify model file exists at expected path

## Future Enhancements

- [ ] Multi-interface monitoring
- [ ] Custom BPF filters (e.g., "tcp port 22" for SSH only)
- [ ] Distributed packet capture across multiple agents
- [ ] Real-time model retraining
- [ ] Anomaly detection mode (unsupervised)
- [ ] HTTPS/DNS tunnel detection
- [ ] Protocol-specific heuristics (DNS amplification, etc.)

## References

- **LSNM2024 Dataset:** Network layer attack dataset
- **Scapy:** Packet manipulation library
- **XGBoost:** Gradient boosted trees with GPU support
- **Sliding Windows:** 10-packet windows for behavioral feature extraction

## Author Notes

This network module was integrated from the `AI_IDS_ForFriend` project with modifications for the main project architecture. The original code demonstrates excellent packet feature engineering and real-time inference patterns suitable for security monitoring applications.

Key improvements in this integration:
- Modular structure for flexible plugin architecture
- Path-agnostic imports for different project structures
- Thread-safe result queuing for non-blocking operation
- Support for both live and offline (PCAP) analysis
