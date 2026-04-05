# IPS Prevention Methodology

## Overview

The IPS (Intrusion Prevention System) uses a multi-layered approach to block attacks:

1. **Auto-Block with Rate Limiting** — Automatically blocks IPs that trigger too many alerts
2. **Manual Block** — User can block any IP from the dashboard
3. **Windows Firewall Integration** — All blocks are enforced via `netsh advfirewall` rules

## Detection → Prevention Flow

```
Packet captured by sniffer (10-packet window)
    |
    v
Stage 1: Binary model → Is it an attack? (threshold check)
    |
    v
Stage 2: Classification model → What type? (classification_threshold check)
    |
    v
Alert stored in DB + sent to frontend via Socket.IO
    |
    v
Auto-Block check:
    - Is Prevention enabled?
    - Has this IP triggered 5+ alerts in 60 seconds?
    - If YES → netsh firewall rule added automatically
    |
    v
Windows Firewall DROPS all inbound traffic from blocked IP
```

## Prevention Methods

### 1. IP Blocking (Primary — Automatic)

When IPS is enabled, the system automatically blocks attacker IPs using Windows Firewall.

**How it works:**
- Each alert is tracked per source IP
- When an IP triggers 5+ alerts within 60 seconds → auto-blocked
- Rule: `netsh advfirewall firewall add rule name="IDS_BLOCK_<ip>" dir=in action=block remoteip=<ip>`
- Effect: ALL inbound traffic from that IP is dropped at the OS firewall level

**Configurable parameters (in `network_alert_controller.py`):**
- `RATE_LIMIT_WINDOW = 60` — seconds to count alerts in
- `RATE_LIMIT_MAX = 5` — max alerts before auto-block

### 2. Rate Limiting (Built into Auto-Block)

Instead of immediately blocking on first detection, the system uses rate-based triggering:

- **Window**: 60 seconds (sliding)
- **Threshold**: 5 alerts from same IP
- **Behavior**: First few alerts are logged. After rate limit exceeded → IP blocked.
- **Benefit**: Reduces false-positive blocks. A single misclassified window won't block a legitimate user.

### 3. Behavioral Shifting (via Rate-Based Escalation)

The system implements a form of behavioral response:
- **1-4 alerts**: Alert only (monitored)
- **5+ alerts in 60s**: IP auto-blocked
- **After block**: All connections from attacker are silently dropped (connection timeouts)

This increases the "cost" for the attacker — their tools see timeouts instead of rejections, making enumeration harder.

## Per-Attack Prevention

### SYN Flood
| Step | Action |
|------|--------|
| Detection | AI model identifies high SYN ratio in traffic window |
| Rate Check | 5+ SYNFlood windows from same IP in 60s |
| Prevention | Firewall blocks ALL inbound from attacker IP |
| Effect | SYN packets silently dropped, TCP handshake impossible |

### Port Scan
| Step | Action |
|------|--------|
| Detection | AI model detects high unique destination ports |
| Rate Check | 5+ PortScan windows from same IP in 60s |
| Prevention | Firewall blocks ALL inbound from scanner IP |
| Effect | Scanner sees all ports as "filtered", scan becomes useless |

### SSH Brute Force
| Step | Action |
|------|--------|
| Detection | AI model detects repeated TCP connections to port 22 |
| Rate Check | 5+ SSHBrute windows from same IP in 60s |
| Prevention | Firewall blocks ALL inbound from attacker IP |
| Effect | SSH connections from attacker time out, brute force impossible |

### FTP Brute Force
| Step | Action |
|------|--------|
| Detection | AI model detects repeated TCP connections to port 21 |
| Rate Check | 5+ FTPBrute windows from same IP in 60s |
| Prevention | Firewall blocks ALL inbound from attacker IP |
| Effect | FTP connections from attacker time out, brute force impossible |

### ARP Spoofing
| Step | Action |
|------|--------|
| Detection | AI model detects abnormal ARP packet ratio |
| Rate Check | 5+ ARPSpoof windows from same IP in 60s |
| Prevention | Firewall blocks ALL inbound IP traffic from attacker |
| Limitation | ARP is Layer 2; firewall (Layer 3) blocks IP traffic but not raw ARP frames |
| Note | Full ARP protection requires static ARP entries or 802.1X port security |

### ICMP Flood (Rule-Based)
| Step | Action |
|------|--------|
| Detection | Heuristic: ICMP count >= 8 AND ratio >= 60% |
| Rate Check | 5+ alerts from same IP in 60s |
| Prevention | Firewall blocks ALL inbound from attacker IP |
| Effect | All ICMP (ping) from attacker is dropped |

### DDoS UDP (Rule-Based)
| Step | Action |
|------|--------|
| Detection | Heuristic: UDP ratio >= 50% AND packet count >= 12 |
| Rate Check | 5+ alerts from same IP in 60s |
| Prevention | Firewall blocks ALL inbound from attacker IP |
| Note | In distributed DDoS, each source IP must be blocked individually |

## Dashboard Controls

| Control | Location | Function |
|---------|----------|----------|
| **Enable/Disable IPS** | Sidebar → Controls | Toggles auto-blocking on/off |
| **Reset All Rules** | Sidebar → Controls | Removes ALL IDS firewall rules + disables IPS |
| **Archive Alerts** | Sidebar → Controls | Saves current alerts to JSON file + clears DB |
| **Detection Threshold** | Main panel → Stage 1 slider | Controls binary model sensitivity (is it an attack?) |
| **Classification Threshold** | Main panel → Advanced Settings | Controls minimum type confidence (what type?) |
| **Unblock IP** | Blocked IPs panel → "x" button | Removes specific firewall rule |

## Technical Details

- Firewall rules named `IDS_BLOCK_<ip>` (dots replaced with underscores)
- Rules are inbound only — outbound traffic unaffected
- Rules persist across system reboot (Windows Firewall rules are permanent)
- Prevention state is in-memory — backend restart resets to disabled
- Auto-block uses sliding window: `_ip_alert_history` dict tracks timestamps per IP
- Rate limit counter resets after successful block
