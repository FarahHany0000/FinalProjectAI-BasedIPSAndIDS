"""
Packet Parser — Scapy Packet -> Feature Vector
===============================================
Converts live Scapy packets to the same numeric representation
used by the training CSV data, ensuring alignment between
training and inference feature spaces.
"""
import numpy as np
import pandas as pd
import time
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from config.settings import PROTOCOL_MAP, WINDOW_SIZE
from data_pipeline.feature_engineer import compute_window_features, get_feature_names


def parse_scapy_packet(pkt) -> dict:
    """
    Extract raw numeric features from a single Scapy packet.
    Returns a dict matching the CSV numeric columns.
    """
    from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether

    # Build the packet so auto-computed fields (IP length, etc.) are filled
    try:
        pkt = pkt.__class__(bytes(pkt))
    except Exception:
        pass

    features = {
        "Length": 0.0,
        "frame length": 0.0,
        "Frame Time (Epoch)": time.time(),
        "IP Length": 0.0,
        "IP TTL": 0.0,
        "IP Flags": 0.0,
        "IP Fragment Offset": 0.0,
        "IP Protocol": 0.0,
        "IP Version": 0.0,
        "IP DSCP Field": 0.0,
        "TCP Source Port": 0.0,
        "TCP Destination Port": 0.0,
        "TCP Length": 0.0,
        "TCP Sequence Number": 0.0,
        "TCP Acknowledgment Number": 0.0,
        "TCP SYN Flag": 0.0,
        "TCP ACK Flag": 0.0,
        "TCP FIN Flag": 0.0,
        "TCP RST Flag": 0.0,
        "TCP Window Size": 0.0,
        "TCP Stream": 0.0,
        "UDP Source Port": 0.0,
        "UDP Destination Port": 0.0,
        "UDP Length": 0.0,
        "ICMP Type": 0.0,
        "protocol_encoded": 0.0,
    }

    # Packet length — apply Ethernet minimum frame padding (60 bytes)
    # Real NICs pad frames shorter than 60 bytes; Wireshark captures show padded length
    raw_len = float(len(pkt))
    features["Length"] = max(raw_len, 60.0)
    features["frame length"] = max(raw_len, 60.0)

    # Determine protocol name for encoding
    proto_name = "OTHER"

    # IP layer
    if pkt.haslayer(IP):
        ip = pkt[IP]
        features["IP Length"] = float(ip.len) if ip.len else float(len(ip))
        features["IP TTL"] = float(ip.ttl)
        # Shift left 5 to match Wireshark CSV encoding (DF=0x40=64, not Scapy's DF=2)
        features["IP Flags"] = float(int(ip.flags) << 5)
        features["IP Fragment Offset"] = float(ip.frag)
        features["IP Protocol"] = float(ip.proto)
        features["IP Version"] = float(ip.version)
        features["IP DSCP Field"] = float(ip.tos >> 2)  # DSCP is top 6 bits of TOS

    # TCP layer
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        proto_name = "TCP"
        features["TCP Source Port"] = float(tcp.sport)
        features["TCP Destination Port"] = float(tcp.dport)
        features["TCP Length"] = float(len(tcp.payload)) if tcp.payload else 0.0
        features["TCP Sequence Number"] = float(tcp.seq)
        features["TCP Acknowledgment Number"] = float(tcp.ack)
        features["TCP Window Size"] = float(tcp.window)

        # TCP flags
        flags = tcp.flags
        features["TCP SYN Flag"] = 1.0 if "S" in str(flags) else 0.0
        features["TCP ACK Flag"] = 1.0 if "A" in str(flags) else 0.0
        features["TCP FIN Flag"] = 1.0 if "F" in str(flags) else 0.0
        features["TCP RST Flag"] = 1.0 if "R" in str(flags) else 0.0

    # UDP layer
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        proto_name = "UDP"
        features["UDP Source Port"] = float(udp.sport)
        features["UDP Destination Port"] = float(udp.dport)
        features["UDP Length"] = float(udp.len) if udp.len else float(len(udp))

    # ICMP layer
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        proto_name = "ICMP"
        features["ICMP Type"] = float(icmp.type)

    # ARP layer
    elif pkt.haslayer(ARP):
        proto_name = "ARP"

    # Protocol encoding
    features["protocol_encoded"] = float(PROTOCOL_MAP.get(proto_name, 0))

    return features


def packets_to_feature_vector(packet_list: list) -> np.ndarray:
    """
    Convert a list of parsed packet dicts into a single window feature vector.
    Uses the SAME compute_window_features function as training.

    Parameters
    ----------
    packet_list : list of dicts from parse_scapy_packet()

    Returns
    -------
    np.ndarray of shape (1, n_features)
    """
    feature_names = get_feature_names()

    # Create DataFrame from parsed packets
    df = pd.DataFrame(packet_list)

    # Pad to window size if needed
    if len(df) < WINDOW_SIZE:
        pad = pd.DataFrame(
            np.zeros((WINDOW_SIZE - len(df), len(df.columns))),
            columns=df.columns
        )
        df = pd.concat([df, pad], ignore_index=True)

    # Compute window features (same function as training)
    feat_dict = compute_window_features(df)
    feat_vec = np.array([feat_dict.get(f, 0.0) for f in feature_names], dtype=np.float32)
    feat_vec = np.nan_to_num(feat_vec, nan=0.0, posinf=0.0, neginf=0.0)

    return feat_vec.reshape(1, -1)
