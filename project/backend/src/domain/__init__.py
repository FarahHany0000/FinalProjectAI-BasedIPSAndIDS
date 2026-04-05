"""Domain layer - Core business entities"""

from datetime import datetime
from enum import Enum


class AlertSeverity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class AlertType(str, Enum):
    """Network attack types"""
    PORT_SCAN = "PortScan"
    SSH_BRUTE = "SSHBrute"
    FTP_BRUTE = "FTPBrute"
    ARP_SPOOF = "ARPSpoof"
    SYN_FLOOD = "SYNFlood"
    ICMP_FLOOD = "ICMPFlood"
    DDOS = "DDoS"
    DDOS_UDP = "DDoS-UDP"
    DDOS_RAW = "DDoS-RAW"
    DDOS_ICMP = "DDoS-ICMP"
    UNKNOWN = "Unknown"


class AlertSourceType(str, Enum):
    NETWORK = "network"
    HOST = "host"
    SYSTEM = "system"


class Alert:
    """Alert entity - core domain object"""

    def __init__(self, threat_type, severity, confidence,
                 source_type="network", host_name="", ip="",
                 action="Alert", details="", time=None):
        self.id = None
        self.threat_type = threat_type
        self.severity = severity
        self.confidence = confidence
        self.source_type = source_type
        self.host_name = host_name
        self.ip = ip
        self.action = action
        self.details = details
        self.time = time or datetime.utcnow()
        self.is_blocked = False

    def mark_blocked(self):
        """Mark this alert as blocked/prevented"""
        self.is_blocked = True

    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'threat_type': self.threat_type,
            'severity': self.severity,
            'confidence': self.confidence,
            'source_type': self.source_type,
            'host_name': self.host_name,
            'ip': self.ip,
            'action': self.action,
            'details': self.details,
            'time': self.time.isoformat() if self.time else None,
            'is_blocked': self.is_blocked,
        }
