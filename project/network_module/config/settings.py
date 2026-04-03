"""
Network IDS/IPS Configuration
=============================
Central configuration for network packet capture and attack detection.
"""
import os
import pathlib

# ── Paths ────────────────────────────────────────────────────────────────────
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
NETWORK_MODULE_ROOT = PROJECT_ROOT / "network_module"
CACHE_DIR = NETWORK_MODULE_ROOT / "cache"
LOG_DIR = NETWORK_MODULE_ROOT / "logs"

for d in [CACHE_DIR, LOG_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ── Attack Mapping ───────────────────────────────────────────────────────────
# Attack classes detected by the network IDS
ATTACK_MAPPING = {
    "Benign": (0, "Normal"),
    "syn flood": (1, "SYNFlood"),
    "Port Scanning": (1, "PortScan"),
    "SSH Brute Force": (1, "SSHBrute"),
    "FTP Brute Force": (1, "FTPBrute"),
    "ARP-spoof": (1, "ARPSpoof"),
}

DROPPED_ATTACKS = [
    "SQL injection", "XSS", "Exploiting FTP", "Remote Code Execution",
    "Fuzzing", "DDOS icmp", "DDOS RAW", "DDOS-UDP", "DOS", "ICMP Flood",
]

# Stage-2 label encoding (alphabetical order)
ATTACK_CLASSES = ["ARPSpoof", "FTPBrute", "PortScan", "SSHBrute", "SYNFlood"]
ATTACK_LABEL2ID = {c: i for i, c in enumerate(ATTACK_CLASSES)}
ATTACK_ID2LABEL = {i: c for c, i in ATTACK_LABEL2ID.items()}

# ── Raw CSV Columns ─────────────────────────────────────────────────────────
IDENTIFIER_COLS = [
    "No.", "Time", "Source", "Destination", "Info",
    "frame number", "Frame Time", "Ethernet Source", "Ethernet Destination",
    "IP Source", "IP Destination", "HTTP Request Method", "HTTP Request URI",
    "HTTP Request Version", "HTTP Full URI", "HTTP Response Code",
    "HTTP User-Agent", "HTTP Content-Length", "HTTP Content Type",
    "HTTP Cookie", "HTTP Host", "HTTP Referer", "HTTP Location",
    "HTTP Authorization", "HTTP Connection", "DNS Query Name", "DNS Query Type",
    "IP Checksum", "TCP Checksum", "UDP Checksum", "ICMP Checksum",
    "label", "deltatime",
]

NUMERIC_COLS = [
    "Length", "frame length", "Frame Time (Epoch)",
    "IP Length", "IP TTL", "IP Flags", "IP Fragment Offset",
    "IP Protocol", "IP Version", "IP DSCP Field",
    "TCP Source Port", "TCP Destination Port", "TCP Length",
    "TCP Sequence Number", "TCP Acknowledgment Number",
    "TCP SYN Flag", "TCP ACK Flag", "TCP FIN Flag", "TCP RST Flag",
    "TCP Window Size", "TCP Stream",
    "UDP Source Port", "UDP Destination Port", "UDP Length",
    "ICMP Type",
]

# Protocol encoding
PROTOCOL_MAP = {
    "TCP": 1, "UDP": 2, "ICMP": 3, "ICMPv6": 3,
    "ARP": 4, "DNS": 5, "HTTP": 6, "TLS": 7,
    "SSH": 8, "FTP": 9, "SSDP": 10, "MDNS": 11,
    "NBNS": 12, "DHCP": 13, "NTP": 14, "IGMP": 15,
}

PROTOCOL_COL = "Protocol"
FRAME_PROTOCOLS_COL = "Frame Protocols"
ETHERNET_TYPE_COL = "Ethernet Type"
TCP_FLAGS_COL = "TCP Flags"

# ── Sliding Window Config ────────────────────────────────────────────────────
WINDOW_SIZE = 10                # packets per window
WINDOW_TIMEOUT = 5.0            # seconds before flushing partial window

# ── Confidence Threshold ─────────────────────────────────────────────────────
CONFIDENCE_THRESHOLD = 0.70     # lowered to reduce false negatives

# ── Downsampling ─────────────────────────────────────────────────────────────
DOWNSAMPLE_RATIO = 3
MAX_SAMPLES_PER_CLASS = 200_000

# ── Chunk Loading ────────────────────────────────────────────────────────────
CSV_CHUNK_SIZE = 50_000

# ── Train / Val / Test Split ─────────────────────────────────────────────────
TRAIN_RATIO = 0.70
VAL_RATIO = 0.15
TEST_RATIO = 0.15

# ── XGBoost Hyperparameters ──────────────────────────────────────────────────
XGBOOST_PARAMS = dict(
    n_estimators=500,
    max_depth=8,
    learning_rate=0.1,
    tree_method="hist",
    device="cuda",
    subsample=0.8,
    colsample_bytree=0.8,
    min_child_weight=5,
    gamma=0.1,
    reg_alpha=0.1,
    reg_lambda=1.0,
    eval_metric="mlogloss",
    early_stopping_rounds=20,
    verbosity=1,
    n_jobs=-1,
)

# ── Random Forest Hyperparameters ────────────────────────────────────────────
RF_PARAMS = dict(
    n_estimators=300,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    class_weight="balanced",
    n_jobs=-1,
    verbose=1,
)

# ── Neural Network Hyperparameters ───────────────────────────────────────────
NN_PARAMS = dict(
    hidden_layers=[256, 128, 64],
    dropout_rates=[0.3, 0.25, 0.2],
    learning_rate=1e-3,
    weight_decay=1e-5,
    batch_size=2048,
    epochs=60,
    patience=10,
)

# ── Live Capture (default interface for Windows + Kali testing) ──────────────
# VMware Network Adapter VMnet1 (Host-Only Network for Kali testing)
# IPv4: 192.168.253.1
#
# DETECTED & CONFIGURED for your system!
# Run: python FIND_NETWORK_INTERFACE.py (to see all detected interfaces)

DEFAULT_IFACE = "VMware Network Adapter VMnet1"

# ── Streamlit ────────────────────────────────────────────────────────────────
STREAMLIT_PORT = 8501
