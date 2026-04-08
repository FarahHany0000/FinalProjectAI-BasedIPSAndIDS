# Network IPS Prevention Methodology

## Overview

The Network IPS (Intrusion Prevention System) uses a multi-layered approach to detect and block attacks:

1. **AI-Based Detection** — XGBoost model trained on 5 attack types
2. **Heuristic Rules** — Pattern-based detection for untrained attack types (DDoS variants)
3. **Severity-Based Auto-Block** — Different thresholds per severity level
4. **Windows Firewall Integration** — All blocks enforced via `netsh advfirewall` rules
5. **Smart Whitelisting** — Local IPs and server responses never flagged

## Architecture

```
                        ┌─────────────────────┐
    Network Traffic ───>│   Scapy Sniffer     │
                        │  (VMnet1 interface)  │
                        └────────┬────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
              ┌─────┴─────┐           ┌───────┴──────┐
              │ TCP/IP    │           │ ARP Buffer   │
              │ Buffer    │           │ (separate)   │
              │ (10 pkts) │           │ (timeout 5s) │
              └─────┬─────┘           └───────┬──────┘
                    │                         │
                    └────────────┬────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │   Whitelist Check       │
                    │  (skip local src IPs)   │
                    │  (skip server responses)│
                    └────────────┬────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │   Stage 1: Binary Model │
                    │   "Is it an attack?"    │
                    │   (threshold: 0.95)     │
                    └────────────┬────────────┘
                                 │ YES
                    ┌────────────┴────────────┐
                    │  Stage 2: Classification│
                    │  "What type of attack?" │
                    │  (threshold: 0.85)      │
                    └────────────┬────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │  Heuristic Override     │
                    │  (for untrained types)  │
                    └────────────┬────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │   Alert Created         │
                    │   DB + Socket.IO        │
                    └────────────┬────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │   Auto-Block Check      │
                    │   (severity threshold)  │
                    └────────────┬────────────┘
                                 │ THRESHOLD MET
                    ┌────────────┴────────────┐
                    │   Windows Firewall      │
                    │   Block IN + OUT        │
                    └─────────────────────────┘
```

## Detection Methods

### 🤖 AI Model Detection (XGBoost — 5 Trained Attack Classes)

These attacks are detected purely by the XGBoost machine learning model, trained on labeled network traffic data:

| Attack Type | Model Confidence | Description |
|-------------|-----------------|-------------|
| **SYNFlood** | 96-99.9% | High volume of TCP SYN packets without completing handshake |
| **PortScan** | 98-99.9% | Multiple connections to different ports on same target |
| **SSHBrute** | 85-99.9% | Repeated SSH authentication attempts (port 22) |
| **FTPBrute** | 85-99.9% | Repeated FTP authentication attempts (port 21) |
| **ARPSpoof** | 99-99.9% | Fake ARP replies to poison the ARP table |

**How the AI Model Works:**
- **Stage 1 (Binary):** XGBoost binary classifier determines if traffic is attack or normal
- **Stage 2 (Classification):** XGBoost multi-class classifier identifies the specific attack type
- Both stages run on a **sliding window of 10 packets**
- Features extracted: packet lengths, TCP flags, port numbers, protocol types, timing, etc.
- Model files: `models/binary_xgb.pkl` + `models/attack_xgb.pkl`

### 📏 Heuristic Rule Detection (Untrained Attack Types)

These attacks are NOT in the training data. The system uses pattern-based rules to detect them:

| Attack Type | Rule | Condition |
|-------------|------|-----------|
| **ICMP Flood** | ICMP packet count ≥ 8 AND ratio ≥ 60% | Confidence: 0.92 |
| **DDoS UDP** | UDP ratio ≥ 50%, ≥ 12 packets, ≥ 3 unique dest ports | Confidence: 0.90 |
| **DDoS RAW** | ≥ 15 packets, protocol entropy ≥ 1.0 | Confidence: 0.88 |
| **DDoS General** | ≥ 18 packets, ≥ 4 unique dest ports | Confidence: 0.87 |

**Important:** Heuristic rules are applied ONLY when the AI model doesn't identify a trained attack type. The 5 trained classes always take priority.

## Severity-Based Auto-Block Thresholds

Different attack severities have different blocking speeds:

| Severity | Alerts Before Block | Window | Attack Types |
|----------|-------------------|--------|-------------|
| **Critical** | 3 alerts | 60 seconds | SYNFlood, ARPSpoof, DDoS, DDoS UDP, DDoS RAW |
| **High** | 10 alerts | 60 seconds | SSHBrute, FTPBrute, ICMP Flood |
| **Medium** | 15 alerts | 60 seconds | PortScan |

**Why different thresholds?**
- **Critical:** These attacks cause immediate damage (DoS, network poisoning) → fast block
- **High:** Brute force needs time to succeed → more alerts so admin can see detection first
- **Medium:** Scanning is reconnaissance, not immediate threat → most alerts before block

## Per-Attack Prevention Details

### SYN Flood (AI Model | Critical)
| Parameter | Value |
|-----------|-------|
| **Detection Method** | AI XGBoost model — identifies high TCP SYN flag ratio in 10-packet window |
| **Severity** | Critical |
| **Rate Limit Window** | 60 seconds (sliding window) |
| **Alerts Before Block** | 3 alerts within 60 seconds |
| **Estimated Time to Block** | ~1-3 seconds (SYN flood sends 10,000+ pkts/sec → fills windows instantly) |
| **Firewall Rule** | `netsh advfirewall firewall add rule name=IDS_BLOCK_{IP}_IN dir=in action=block remoteip={IP} protocol=any` |
| **Firewall Rule (OUT)** | `netsh advfirewall firewall add rule name=IDS_BLOCK_{IP}_OUT dir=out action=block remoteip={IP} protocol=any` |
| **Effect** | All TCP SYN packets from attacker silently dropped — TCP handshake impossible, connection timeouts |
| **Why Critical?** | SYN flood exhausts server resources immediately — every second counts |

### Port Scan (AI Model | Medium)
| Parameter | Value |
|-----------|-------|
| **Detection Method** | AI XGBoost model — detects connections to many different destination ports |
| **Severity** | Medium |
| **Rate Limit Window** | 60 seconds (sliding window) |
| **Alerts Before Block** | 15 alerts within 60 seconds |
| **Estimated Time to Block** | ~5-15 seconds depending on scan speed (nmap --min-rate 500 → ~5s) |
| **Firewall Rule** | Both IN + OUT rules blocking all traffic from scanner IP |
| **Effect** | Scanner sees all ports as "filtered", reconnaissance becomes useless |
| **Why Medium?** | Port scanning is reconnaissance — not immediately destructive, admin should see it first |

### SSH Brute Force (AI Model | High)
| Parameter | Value |
|-----------|-------|
| **Detection Method** | AI XGBoost model — detects repeated TCP connections to port 22 with brute force pattern |
| **Severity** | High |
| **Rate Limit Window** | 60 seconds (sliding window) |
| **Alerts Before Block** | 10 alerts within 60 seconds |
| **Estimated Time to Block** | ~10-25 seconds (hydra -t 16 → generates ~10 windows in 20s) |
| **Firewall Rule** | Both IN + OUT rules blocking all traffic from attacker IP |
| **Effect** | SSH connections from attacker time out, brute force impossible |
| **Smart Filter** | Normal SSH sessions (server responses with src_port=22) are **NOT** flagged — only incoming attack traffic (dst_port=22) triggers detection |
| **Why High (not Critical)?** | Brute force needs many attempts to succeed — 10 alerts gives admin ~20s to see "SSHBrute" on dashboard before block |

### FTP Brute Force (AI Model | High)
| Parameter | Value |
|-----------|-------|
| **Detection Method** | AI XGBoost model — detects repeated TCP connections to port 21 |
| **Severity** | High |
| **Rate Limit Window** | 60 seconds (sliding window) |
| **Alerts Before Block** | 10 alerts within 60 seconds |
| **Estimated Time to Block** | ~10-25 seconds (similar to SSH brute force) |
| **Firewall Rule** | Both IN + OUT rules blocking all traffic from attacker IP |
| **Effect** | FTP connections from attacker time out, brute force impossible |
| **Smart Filter** | Normal FTP responses (src_port=21) are **NOT** flagged |
| **Why High?** | Same reasoning as SSHBrute — admin needs time to see detection |

### ARP Spoofing (AI Model | Critical)
| Parameter | Value |
|-----------|-------|
| **Detection Method** | AI XGBoost model — detects abnormal ARP reply patterns in **separate ARP buffer** |
| **Severity** | Critical |
| **Rate Limit Window** | 60 seconds (sliding window) |
| **Alerts Before Block** | 3 alerts within 60 seconds |
| **Estimated Time to Block** | ~15-20 seconds (arpspoof sends ~1 pkt/sec → ARP buffer timeout flushes every 5s → 3 windows = ~15s) |
| **ARP Buffer** | ARP packets go to a separate buffer from TCP/IP with 5-second timeout flush (minimum 2 packets) |
| **Firewall Rule** | Both IN + OUT rules blocking all IP traffic from attacker |
| **Effect** | All IP-level communication with attacker blocked |
| **Limitation** | ARP is Layer 2; Windows Firewall works at Layer 3 — blocks IP traffic but raw ARP frames may still arrive |
| **Full Protection** | Requires static ARP entries (`arp -s`) or 802.1X port security at switch level |
| **Why Critical?** | ARP spoofing enables man-in-the-middle attacks — all network traffic can be intercepted |

### ICMP Flood (Heuristic Rule | High)
| Parameter | Value |
|-----------|-------|
| **Detection Method** | Heuristic rule: ICMP packet count ≥ 8 AND ICMP ratio ≥ 60% in window |
| **Confidence** | Fixed at 0.92 (rule-based, not model prediction) |
| **Severity** | High |
| **Rate Limit Window** | 60 seconds (sliding window) |
| **Alerts Before Block** | 10 alerts within 60 seconds |
| **Estimated Time to Block** | ~1-3 seconds (ICMP flood sends 100,000+ pkts/sec → fills windows instantly) |
| **Firewall Rule** | Both IN + OUT rules blocking all traffic from attacker IP |
| **Effect** | All ICMP (ping) and other traffic from attacker is dropped |
| **Why Heuristic?** | ICMP Flood was not in the AI training dataset — detected by packet counting rule |

### DDoS UDP (Heuristic Rule | Critical)
| Parameter | Value |
|-----------|-------|
| **Detection Method** | Heuristic rule: UDP ratio ≥ 50%, ≥ 12 packets, ≥ 3 unique destination ports |
| **Confidence** | Fixed at 0.90 (rule-based) |
| **Severity** | Critical |
| **Rate Limit Window** | 60 seconds (sliding window) |
| **Alerts Before Block** | 3 alerts within 60 seconds |
| **Estimated Time to Block** | ~1-5 seconds depending on flood rate |
| **Firewall Rule** | Both IN + OUT rules blocking all traffic from attacker IP |
| **Note** | In distributed DDoS, each source IP must be blocked individually |
| **Why Heuristic?** | DDoS UDP was not in the AI training dataset |

### DDoS RAW (Heuristic Rule | Critical)
| Parameter | Value |
|-----------|-------|
| **Detection Method** | Heuristic rule: ≥ 15 packets with protocol entropy ≥ 1.0 (mixed protocols) |
| **Confidence** | Fixed at 0.88 (rule-based) |
| **Severity** | Critical |
| **Rate Limit Window** | 60 seconds (sliding window) |
| **Alerts Before Block** | 3 alerts within 60 seconds |
| **Firewall Rule** | Both IN + OUT rules blocking all traffic from attacker IP |
| **Why Heuristic?** | DDoS RAW was not in the AI training dataset |

### DDoS General (Heuristic Rule | Critical)
| Parameter | Value |
|-----------|-------|
| **Detection Method** | Heuristic rule: ≥ 18 packets, ≥ 4 unique destination ports across TCP+UDP |
| **Confidence** | Fixed at 0.87 (rule-based) |
| **Severity** | Critical |
| **Rate Limit Window** | 60 seconds (sliding window) |
| **Alerts Before Block** | 3 alerts within 60 seconds |
| **Firewall Rule** | Both IN + OUT rules blocking all traffic from attacker IP |
| **Why Heuristic?** | General DDoS pattern not in AI training dataset |
| Effect | All ICMP (ping) from attacker is dropped |

### DDoS UDP (Heuristic Rule | Critical)
| Step | Action |
|------|--------|
| Detection | Heuristic: UDP ratio ≥ 50%, ≥ 12 packets, ≥ 3 unique dest ports |
| Severity | **Critical** — blocks after 3 alerts |
| Prevention | Firewall blocks ALL inbound from attacker IP |
| Note | In distributed DDoS, each source IP must be blocked individually |

## Smart Whitelisting (False Positive Prevention)

The sniffer uses multiple layers to prevent false positives:

### 1. Local IP Whitelist
Traffic **originating from this machine** is never flagged as an attack:
```python
# Automatically detected at startup:
Local IPs: {127.0.0.1, 192.168.253.1, 192.168.1.6, ...}
```
**Why:** When you SSH to Kali from Windows, the outbound SSH traffic looks like SSHBrute to the model. The whitelist prevents your own connections from being flagged.

### 2. Server Response Filter
Packets where `src_port = service_port` are server responses, not attacks:
- `src_port=22` → SSH server responding (not SSHBrute)
- `src_port=21` → FTP server responding (not FTPBrute)

### 3. Slow Traffic Filter
Windows filling slower than 10 seconds are skipped (background noise, not attacks).

### 4. Protected IPs (Never Blocked)
- All local machine IPs
- Gateway addresses: `*.1`, `*.254`, `*.0`, `*.255`
- Loopback: `127.0.0.1`

### 5. ARP/TCP Buffer Separation
ARP packets go to a **separate buffer** from TCP/IP packets:
- Prevents ARP resolution traffic from contaminating SSH/PortScan detection windows
- ARP buffer uses timeout flush (5 seconds, minimum 2 packets)
- TCP/IP buffer uses standard window fill (10 packets) or timeout flush

## Firewall Technical Details

### Block Commands (Applied Automatically)
```powershell
# Block inbound traffic from attacker
netsh advfirewall firewall add rule name=IDS_BLOCK_{IP}_IN dir=in action=block remoteip={IP} protocol=any enable=yes

# Block outbound traffic to attacker
netsh advfirewall firewall add rule name=IDS_BLOCK_{IP}_OUT dir=out action=block remoteip={IP} protocol=any enable=yes
```

### Unblock Commands (via API or Dashboard)
```powershell
# Remove by name
netsh advfirewall firewall delete rule name=IDS_BLOCK_{IP}_IN
netsh advfirewall firewall delete rule name=IDS_BLOCK_{IP}_OUT

# Remove by IP (catches ALL rules for that IP)
netsh advfirewall firewall delete rule name=all dir=in remoteip={IP}
netsh advfirewall firewall delete rule name=all dir=out remoteip={IP}
```

### Rule Naming Convention
- Network blocks: `IDS_BLOCK_{IP}_IN` / `IDS_BLOCK_{IP}_OUT`
- Host blocks: `IPS_HOST_BLOCK_{IP}_IN` / `IPS_HOST_BLOCK_{IP}_OUT`
- IP dots replaced with underscores: `192.168.253.129` → `192_168_253_129`

### Important Notes
- Rules require **administrator privileges** — backend uses `Start-Process -Verb RunAs`
- Rules **persist across system reboot** (Windows Firewall rules are permanent)
- On backend startup, all old IDS/IPS rules are **automatically cleaned up**
- Prevention state is persisted in `threshold_config.json`

## Dashboard Controls

| Control | Location | Function |
|---------|----------|----------|
| **Enable/Disable IPS** | Controls page | Toggles auto-blocking on/off |
| **Reset All Rules** | Controls page | Removes ALL firewall rules + clears blocked list (keeps prevention ON) |
| **Archive Alerts** | Controls page | Moves current alerts to archive + clears DB |
| **Unblock IP** | Blocked IPs panel → "x" button | Removes specific IP's firewall rules + clears alert history |
| **Binary Threshold** | Stage 1 slider (default: 0.95) | Higher = fewer false positives, lower = more detections |
| **Classification Threshold** | Stage 2 slider (default: 0.85) | Minimum confidence for attack type identification |

## Network Configuration

### Changing Network/Interface
If you change the network or lab environment:

1. **Update interface name** in `project/backend/src/infra/network_module/config/settings.py`:
   ```python
   DEFAULT_IFACE = "VMware Network Adapter VMnet1"  # Change this
   ```
2. Run `python FIND_NETWORK_INTERFACE.py` to discover available interfaces
3. Local IPs are **detected automatically** at startup — no manual config needed
4. Thresholds are persisted in `threshold_config.json` — survive restart

### Current Lab Setup
- **Windows (IDS/IPS Server):** 192.168.253.1 on VMnet1
- **Kali Linux (Attacker VM):** 192.168.253.129 on VMnet1
- **Interface:** VMware Network Adapter VMnet1 (Host-Only)

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/network/alerts` | GET | Get current alerts |
| `/api/network/prevention` | GET/POST | Get/set prevention state |
| `/api/network/prevention/reset` | POST | Reset all rules + clear blocks |
| `/api/network/prevention/unblock` | POST | Unblock specific IP `{"ip": "x.x.x.x"}` |
| `/api/network/threshold` | GET/POST | Get/set detection thresholds |
| `/api/alerts/archive` | POST | Archive all alerts |
| `/api/agent/network-alert` | POST | Receive alert from network sensor |
