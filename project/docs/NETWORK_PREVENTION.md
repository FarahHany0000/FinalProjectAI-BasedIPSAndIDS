# Network IPS Prevention Methodology

> **Last Updated**: April 9, 2026

## Overview

The Network IPS (Intrusion Prevention System) uses a multi-layered approach to detect and block network attacks:

1. **AI-Based Detection** - Hierarchical 2-stage XGBoost model trained on 5 attack types
2. **Heuristic Rules** - Pattern-based detection for untrained attack types (DDoS variants)
3. **Severity-Based Auto-Block** - Different alert thresholds per attack severity
4. **Windows Firewall Integration** - All blocks enforced via `netsh advfirewall` rules
5. **Smart Whitelisting** - Local IPs and server responses never flagged

---

## Architecture

```
                        +---------------------+
    Network Traffic --->|   Scapy Sniffer     |
                        |  (configurable NIC)  |
                        +--------+------------+
                                 |
                    +------------+------------+
                    |                         |
              +-----+-----+           +------+------+
              | TCP/IP    |           | ARP Buffer  |
              | Buffer    |           | (separate)  |
              | (10 pkts) |           | (min 5 pkts)|
              +-----+-----+           +------+------+
                    |                         |
                    +------------+------------+
                                 |
                    +------------+------------+
                    |   Whitelist Check       |
                    |  (skip local src IPs)   |
                    |  (skip server responses)|
                    +------------+------------+
                                 |
                    +------------+------------+
                    |  Feature Engineering    |
                    |  (52 features per       |
                    |   10-packet window)     |
                    +------------+------------+
                                 |
                    +------------+------------+
                    |   Stage 1: Binary Model |
                    |   "Is it an attack?"    |
                    |   (threshold: 0.70)     |
                    +------------+------------+
                                 | YES (>= 0.70)
                    +------------+------------+
                    |  Stage 2: Classification|
                    |  "What type of attack?" |
                    |  (threshold: 0.50)      |
                    +------------+------------+
                                 |
                    +------------+------------+
                    |  Heuristic Override     |
                    |  (for untrained types)  |
                    +------------+------------+
                                 |
                    +------------+------------+
                    |   Alert Created         |
                    |   DB + Socket.IO        |
                    +------------+------------+
                                 |
                    +------------+------------+
                    |   Auto-Block Check      |
                    |   (severity threshold)  |
                    +------------+------------+
                                 | THRESHOLD MET
                    +------------+------------+
                    |   Windows Firewall      |
                    |   Block IN + OUT        |
                    +-------------------------+
```

---

## Packet Capture & Buffering

**File**: `project/backend/src/infra/network_module/sniffer/live_capture.py`

### Capture Technology
- **Library**: Scapy (`scapy.all.sniff`)
- **Interface**: Configurable (default: VMware Network Adapter VMnet1)
- **Mode**: Promiscuous, store=False (memory efficient)
- **Filter**: Optional BPF filter support

### Two Separate Buffers

| Buffer | Size | Timeout | Min Packets | Purpose |
|--------|------|---------|-------------|---------|
| **TCP/IP** | 10 packets | 5 seconds | > 0 | Normal traffic analysis |
| **ARP** | 10 packets | 5 seconds | >= 5 | ARP spoofing detection (isolated) |

**Why separate buffers?** ARP resolution traffic would contaminate SSH/PortScan detection windows. Keeping ARP isolated ensures clean analysis for both protocol types.

---

## Feature Engineering (52 Features)

**File**: `project/backend/src/infra/network_module/data_pipeline/feature_engineer.py`

| Category | Features | Count |
|----------|----------|-------|
| **Packet Size** | pkt_len_mean, pkt_len_std, pkt_len_min, pkt_len_max, pkt_len_sum | 5 |
| **IP Layer** | ip_len_mean/std/min/max, ttl_mean/std/min/max, ip_flags_mean | 9 |
| **TCP Flags** | syn/ack/fin/rst count+ratio, syn_ack_count, syn_only_ratio, rst_to_syn_ratio | 7 |
| **Payload** | payload_pkt_ratio, avg_payload_size, tcp_len_mean, tcp_len_std | 3 |
| **Port Distribution** | unique_src/dst_ports, dst_port_entropy, dst_port_to_pkt_ratio, unique_connections, tcp_dport_mode/min, unique_dst_ports_low | 8 |
| **Protocol** | proto_tcp/udp/icmp/arp_ratio, proto_entropy | 5 |
| **ARP** | arp_present, arp_pkt_count, MAC-IP consistency | 3 |
| **ICMP** | icmp_count, icmp_type_mode | 2 |
| **Other** | ip_frag_count, dscp_mean, ip_proto_mode | 3 |
| **Total** | | **52** |

---

## AI Model Detection

**File**: `project/backend/src/infra/model_loader.py`

### Hierarchical Two-Stage XGBoost

```
Stage 1: Binary Classification
|- Model: binary_model.json
|- Input: 52-D scaled feature vector
|- Output: P(attack) vs P(normal)
|- Threshold: 0.70 (configurable)
+- Gate: if P(attack) < 0.70 -> "Normal" (skip Stage 2)

Stage 2: Multi-Class Attack Type (if Stage 1 >= 0.70)
|- Model: attack_model.json
|- Classes: [ARPSpoof, FTPBrute, PortScan, SSHBrute, SYNFlood]
|- Output: probability per class
|- Threshold: 0.50 (minimum confidence)
+- If max_prob < 0.50 -> "Normal" (low confidence)
```

### Model Files

| File | Location | Purpose |
|------|----------|---------|
| `binary_model.json` | `ai_models/network_xgb/` | Stage 1 - attack vs normal |
| `attack_model.json` | `ai_models/network_xgb/` | Stage 2 - 5 attack type classification |
| `scaler.pkl` | `ai_models/network_xgb/` | StandardScaler for feature normalization |
| `feature_names.json` | `ai_models/network_xgb/` | Feature ordering (52 names) |

### 5 AI-Trained Attack Classes

| Attack Type | Key Indicators | Typical Confidence |
|-------------|---------------|-------------------|
| **SYNFlood** | High TCP SYN ratio, no handshake completion | 96-99.9% |
| **PortScan** | Many unique destination ports, high port entropy | 98-99.9% |
| **SSHBrute** | Repeated TCP connections to port 22 | 85-99.9% |
| **FTPBrute** | Repeated TCP connections to port 21 | 85-99.9% |
| **ARPSpoof** | Unsolicited ARP replies, MAC-IP inconsistency | 99-99.9% |

---

## Heuristic Rule Detection (Untrained Attacks)

**File**: `project/backend/src/infra/network_module/sniffer/live_capture.py`

These attacks are NOT in the training data. Pattern-based rules detect them:

| Attack Type | Rule Condition | Fixed Confidence |
|-------------|---------------|-----------------|
| **ICMP Flood** | ICMP count >= 8 AND ICMP ratio >= 60% | 0.92 |
| **DDoS UDP** | UDP ratio >= 50%, >= 12 packets, >= 3 unique dest ports | 0.90 |
| **DDoS RAW** | >= 15 packets, protocol entropy >= 1.0 (mixed protocols) | 0.88 |
| **DDoS General** | >= 18 packets, >= 4 unique dest ports (TCP+UDP) | 0.87 |

**Priority**: AI model predictions take priority. Heuristic rules only apply when the model does not identify a trained attack type.

**Total Coverage**: 8+ attack types (5 AI-trained + 4 rule-based)

---

## Severity-Based Auto-Block

**File**: `project/backend/controllers/network_alert_controller.py`

### Severity Mapping

| Severity | Attack Types |
|----------|-------------|
| **Critical** | SYNFlood, ARPSpoof, DDoS, DDoS UDP, DDoS RAW |
| **High** | SSHBrute, FTPBrute, ICMP Flood |
| **Medium** | PortScan |

### Auto-Block Thresholds

| Severity | Alerts Before Block | Window | Estimated Time to Block |
|----------|-------------------|--------|------------------------|
| **Critical** | 3 alerts | 60 seconds | ~1-3 seconds (floods fill windows instantly) |
| **High** | 10 alerts | 60 seconds | ~10-25 seconds |
| **Medium** | 15 alerts | 60 seconds | ~5-15 seconds depending on scan speed |

**Why different thresholds?**
- **Critical**: DoS/ARP poisoning causes immediate damage -> fast block
- **High**: Brute force needs time to succeed -> more alerts so admin can see detection first
- **Medium**: Port scanning is reconnaissance, not immediate threat -> most alerts before block

---

## Per-Attack Prevention Details

### SYN Flood (AI Model | Critical)
| Parameter | Value |
|-----------|-------|
| **Detection** | AI XGBoost - high TCP SYN ratio in 10-packet window |
| **Severity** | Critical - 3 alerts to block |
| **Time to Block** | ~1-3 seconds (10,000+ pkts/sec fills windows instantly) |
| **Firewall Rule** | `IDS_BLOCK_{IP}_IN/OUT` - block all protocols |
| **Effect** | SYN packets dropped, TCP handshake impossible |

### Port Scan (AI Model | Medium)
| Parameter | Value |
|-----------|-------|
| **Detection** | AI XGBoost - many unique destination ports, high entropy |
| **Severity** | Medium - 15 alerts to block |
| **Time to Block** | ~5-15 seconds (depends on nmap rate) |
| **Firewall Rule** | `IDS_BLOCK_{IP}_IN/OUT` - block all traffic from scanner |
| **Effect** | All ports appear "filtered", reconnaissance fails |

### SSH Brute Force (AI Model | High)
| Parameter | Value |
|-----------|-------|
| **Detection** | AI XGBoost - repeated TCP to port 22 |
| **Severity** | High - 10 alerts to block |
| **Time to Block** | ~10-25 seconds |
| **Smart Filter** | Server responses (src_port=22) are NOT flagged |
| **Effect** | SSH connections from attacker timeout |

### FTP Brute Force (AI Model | High)
| Parameter | Value |
|-----------|-------|
| **Detection** | AI XGBoost - repeated TCP to port 21 |
| **Severity** | High - 10 alerts to block |
| **Time to Block** | ~10-25 seconds |
| **Smart Filter** | Server responses (src_port=21) are NOT flagged |
| **Effect** | FTP connections from attacker timeout |

### ARP Spoofing (AI Model | Critical)
| Parameter | Value |
|-----------|-------|
| **Detection** | AI XGBoost - abnormal ARP replies in separate ARP buffer |
| **Severity** | Critical - 3 alerts to block |
| **ARP Buffer** | Separate from TCP/IP, 5-second timeout, minimum 5 packets |
| **Time to Block** | ~15-20 seconds (~1 pkt/sec -> ARP flush every 5s) |
| **Firewall Rule** | Blocks all IP (Layer 3) traffic from attacker |
| **Limitation** | ARP is Layer 2; raw ARP frames may still arrive. Full protection requires static ARP entries or 802.1X |

### ICMP Flood (Heuristic | High)
| Parameter | Value |
|-----------|-------|
| **Detection** | Rule: ICMP count >= 8 AND ratio >= 60% |
| **Confidence** | Fixed 0.92 |
| **Time to Block** | ~1-3 seconds (high packet rate) |
| **Effect** | All ICMP and other traffic from attacker dropped |

### DDoS UDP (Heuristic | Critical)
| Parameter | Value |
|-----------|-------|
| **Detection** | Rule: UDP ratio >= 50%, >= 12 packets, >= 3 unique dest ports |
| **Confidence** | Fixed 0.90 |
| **Time to Block** | ~1-5 seconds |
| **Note** | In distributed DDoS, each source IP blocked individually |

### DDoS RAW (Heuristic | Critical)
| Parameter | Value |
|-----------|-------|
| **Detection** | Rule: >= 15 packets, protocol entropy >= 1.0 (mixed protocols) |
| **Confidence** | Fixed 0.88 |
| **Time to Block** | ~1-5 seconds |

---

## Smart Whitelisting (False Positive Prevention)

### 1. Local IP Whitelist
Traffic originating from the local machine is never flagged:
```python
Local IPs: {127.0.0.1, 192.168.253.1, ...}  # Auto-detected at startup
```

### 2. Server Response Filter
Packets where `src_port = service_port` are server responses, not attacks:
- `src_port=22` -> SSH server responding (not SSHBrute)
- `src_port=21` -> FTP server responding (not FTPBrute)

### 3. Slow Traffic Filter
Windows filling slower than 10 seconds are skipped (background noise, not attacks).

### 4. Protected IPs (Never Blocked)
- All local machine IPs
- Gateway addresses: `*.1`, `*.254`, `*.0`, `*.255`
- Loopback: `127.0.0.1`

### 5. ARP/TCP Buffer Separation
ARP packets go to a separate buffer to prevent normal ARP resolution from contaminating attack detection windows.

---

## Firewall Technical Details

### Block Commands (Auto-Applied)
```powershell
# Block inbound from attacker
netsh advfirewall firewall add rule name=IDS_BLOCK_{IP}_IN dir=in action=block remoteip={IP} protocol=any enable=yes

# Block outbound to attacker
netsh advfirewall firewall add rule name=IDS_BLOCK_{IP}_OUT dir=out action=block remoteip={IP} protocol=any enable=yes
```

### Unblock Commands (via API or Dashboard)
```powershell
netsh advfirewall firewall delete rule name=IDS_BLOCK_{IP}_IN
netsh advfirewall firewall delete rule name=IDS_BLOCK_{IP}_OUT
```

### Rule Naming Convention
- Network blocks: `IDS_BLOCK_{ip}_IN` / `IDS_BLOCK_{ip}_OUT`
- Host blocks: `IPS_HOST_BLOCK_{ip}_IN` / `IPS_HOST_BLOCK_{ip}_OUT`
- IP dots replaced with underscores: `192.168.253.129` -> `192_168_253_129`

### Important Notes
- Rules require **administrator privileges**
- Rules **persist across system reboot** (Windows Firewall rules are permanent)
- On backend startup, all old IDS/IPS rules are **automatically cleaned up**
- Prevention state is persisted in `threshold_config.json`

---

## Dashboard Controls

| Control | Location | Function |
|---------|----------|----------|
| **Enable/Disable IPS** | Controls page | Toggles auto-blocking on/off |
| **Reset All Rules** | Controls page - Quick Actions | Removes ALL firewall rules + clears blocked list |
| **Archive Alerts** | Controls page - Quick Actions | Moves current alerts to archive + clears DB |
| **Unblock IP** | Blocked IPs panel - button | Removes specific IP firewall rules |
| **Binary Threshold** | Stage 1 slider (default: **0.70**) | Higher = fewer false positives, lower = more detections |
| **Classification Threshold** | Stage 2 slider (default: **0.50**) | Minimum confidence for attack type identification |

---

## Network Configuration

### Changing Network/Interface
1. **Update interface name** in `project/backend/src/infra/network_module/config/settings.py`:
   ```python
   DEFAULT_IFACE = "VMware Network Adapter VMnet1"  # Change this
   ```
2. Run `python FIND_NETWORK_INTERFACE.py` to discover available interfaces
3. Local IPs are **detected automatically** at startup
4. Thresholds are persisted in `threshold_config.json`

### Lab Setup Example
- **Windows (IDS/IPS Server):** 192.168.253.1 on VMnet1
- **Kali Linux (Attacker VM):** 192.168.253.129 on VMnet1
- **Interface:** VMware Network Adapter VMnet1 (Host-Only)

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/network/alerts` | GET | Get current network alerts |
| `/api/network/stats` | GET | Network alert statistics |
| `/api/network/prevention` | GET/POST | Get/set prevention state |
| `/api/network/prevention/block` | POST | Manually block IP |
| `/api/network/prevention/unblock` | POST | Unblock specific IP |
| `/api/network/prevention/reset` | POST | Reset all rules + clear blocks |
| `/api/network/threshold` | GET/POST | Get/set detection thresholds |
| `/api/alerts/archive` | POST | Archive all alerts to JSON |
| `/api/alerts/archives` | GET | List archive files |
| `/api/alerts/archives/<file>` | GET | Get archive contents |
