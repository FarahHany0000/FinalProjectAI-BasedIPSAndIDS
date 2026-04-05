"""
Feature Engineering Module
===========================
Converts raw packet-level data into sliding-window behavioural features.
Excludes all identifiers (IPs, MACs, timestamps) so the model learns
behavioural patterns only. Output aligns between CSV training data and
live Scapy capture.
"""
import numpy as np
import pandas as pd
from scipy import stats as scipy_stats
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from config.settings import WINDOW_SIZE, ATTACK_LABEL2ID


def _entropy(arr):
    """Shannon entropy of a discrete array."""
    if len(arr) == 0:
        return 0.0
    _, counts = np.unique(arr, return_counts=True)
    probs = counts / counts.sum()
    return float(-np.sum(probs * np.log2(probs + 1e-10)))


def _safe_stat(arr, func, default=0.0):
    """Safely compute a statistic, return default on empty/error."""
    try:
        if len(arr) == 0:
            return default
        result = func(arr)
        if np.isnan(result) or np.isinf(result):
            return default
        return float(result)
    except Exception:
        return default


def compute_window_features(window_df: pd.DataFrame) -> dict:
    """
    Compute behavioural features for a single sliding window of packets.

    Parameters
    ----------
    window_df : DataFrame with numeric packet columns

    Returns
    -------
    dict of feature_name -> float value
    """
    features = {}
    n = len(window_df)
    features["pkt_count"] = float(n)

    # ── Packet size stats ────────────────────────────────────────────────────
    pkt_len = window_df["Length"].values if "Length" in window_df else np.zeros(n)
    features["pkt_len_mean"] = _safe_stat(pkt_len, np.mean)
    features["pkt_len_std"]  = _safe_stat(pkt_len, np.std)
    features["pkt_len_min"]  = _safe_stat(pkt_len, np.min)
    features["pkt_len_max"]  = _safe_stat(pkt_len, np.max)
    features["pkt_len_sum"]  = _safe_stat(pkt_len, np.sum)

    # ── IP Length stats ──────────────────────────────────────────────────────
    ip_len = window_df["IP Length"].values if "IP Length" in window_df else np.zeros(n)
    features["ip_len_mean"] = _safe_stat(ip_len, np.mean)
    features["ip_len_std"]  = _safe_stat(ip_len, np.std)
    features["ip_len_min"]  = _safe_stat(ip_len, np.min)
    features["ip_len_max"]  = _safe_stat(ip_len, np.max)

    # ── TCP Length stats ─────────────────────────────────────────────────────
    tcp_len = window_df["TCP Length"].values if "TCP Length" in window_df else np.zeros(n)
    features["tcp_len_mean"] = _safe_stat(tcp_len, np.mean)
    features["tcp_len_std"]  = _safe_stat(tcp_len, np.std)

    # ── TCP Window Size stats ────────────────────────────────────────────────
    tcp_win = window_df["TCP Window Size"].values if "TCP Window Size" in window_df else np.zeros(n)
    features["tcp_win_mean"] = _safe_stat(tcp_win, np.mean)
    features["tcp_win_std"]  = _safe_stat(tcp_win, np.std)
    features["tcp_win_min"]  = _safe_stat(tcp_win, np.min)
    features["tcp_win_max"]  = _safe_stat(tcp_win, np.max)

    # ── TCP Flag counts & ratios ─────────────────────────────────────────────
    syn = window_df["TCP SYN Flag"].values if "TCP SYN Flag" in window_df else np.zeros(n)
    ack = window_df["TCP ACK Flag"].values if "TCP ACK Flag" in window_df else np.zeros(n)
    fin = window_df["TCP FIN Flag"].values if "TCP FIN Flag" in window_df else np.zeros(n)
    rst = window_df["TCP RST Flag"].values if "TCP RST Flag" in window_df else np.zeros(n)

    syn_count = float(syn.sum())
    ack_count = float(ack.sum())
    fin_count = float(fin.sum())
    rst_count = float(rst.sum())

    features["syn_count"]  = syn_count
    features["ack_count"]  = ack_count
    features["fin_count"]  = fin_count
    features["rst_count"]  = rst_count
    total_flags = syn_count + ack_count + fin_count + rst_count
    if total_flags > 0:
        features["syn_ratio"] = syn_count / total_flags
        features["ack_ratio"] = ack_count / total_flags
        features["fin_ratio"] = fin_count / total_flags
        features["rst_ratio"] = rst_count / total_flags
    else:
        features["syn_ratio"] = features["ack_ratio"] = features["fin_ratio"] = features["rst_ratio"] = 0.0

    # ── Discriminative features for attack detection ───────────────────────────
    # SYN+ACK count: packets with both SYN and ACK set (handshake completions)
    features["syn_ack_count"] = float((syn * ack).sum())

    # RST-to-SYN ratio: high for PortScan (many RSTs, few completed conns)
    features["rst_to_syn_ratio"] = rst_count / max(syn_count, 1.0)

    # Payload packet ratio: fraction of TCP packets carrying payload
    proto = window_df["protocol_encoded"].values if "protocol_encoded" in window_df else np.zeros(n)
    n_tcp = float(np.sum(proto == 1))
    tcp_payload_mask = tcp_len > 0
    n_with_payload = float(tcp_payload_mask.sum())
    features["payload_pkt_ratio"] = n_with_payload / max(n_tcp, 1.0)

    # Average payload size for packets that have payload
    if n_with_payload > 0:
        features["avg_payload_size"] = float(tcp_len[tcp_payload_mask].mean())
    else:
        features["avg_payload_size"] = 0.0

    # ── TTL stats ────────────────────────────────────────────────────────────
    ttl = window_df["IP TTL"].values if "IP TTL" in window_df else np.zeros(n)
    features["ttl_mean"] = _safe_stat(ttl, np.mean)
    features["ttl_std"]  = _safe_stat(ttl, np.std)
    features["ttl_min"]  = _safe_stat(ttl, np.min)
    features["ttl_max"]  = _safe_stat(ttl, np.max)

    # ── Port stats ───────────────────────────────────────────────────────────
    tcp_sport = window_df["TCP Source Port"].values if "TCP Source Port" in window_df else np.zeros(n)
    tcp_dport = window_df["TCP Destination Port"].values if "TCP Destination Port" in window_df else np.zeros(n)
    udp_sport = window_df["UDP Source Port"].values if "UDP Source Port" in window_df else np.zeros(n)
    udp_dport = window_df["UDP Destination Port"].values if "UDP Destination Port" in window_df else np.zeros(n)

    # Combine TCP+UDP ports
    src_ports = np.concatenate([tcp_sport[tcp_sport > 0], udp_sport[udp_sport > 0]])
    dst_ports = np.concatenate([tcp_dport[tcp_dport > 0], udp_dport[udp_dport > 0]])

    features["unique_src_ports"] = float(len(np.unique(src_ports))) if len(src_ports) > 0 else 0.0
    features["unique_dst_ports"] = float(len(np.unique(dst_ports))) if len(dst_ports) > 0 else 0.0
    features["dst_port_entropy"] = _entropy(dst_ports)

    # ── Port/connection diversity features (PortScan discriminator) ──────────
    # dst_port_to_pkt_ratio: ~1.0 for PortScan (each pkt hits diff port), ~0.1 for DoS
    features["dst_port_to_pkt_ratio"] = features["unique_dst_ports"] / max(float(n), 1.0)
    # unique connections: (src_port, dst_port) pairs — high for PortScan, low for DoS
    if len(tcp_sport) > 0 and len(tcp_dport) > 0:
        tcp_conns = set(zip(tcp_sport.tolist(), tcp_dport.tolist()))
        # Filter out (0,0) pairs (non-TCP packets)
        tcp_conns.discard((0.0, 0.0))
        tcp_conns.discard((0, 0))
        features["unique_connections"] = float(len(tcp_conns))
    else:
        features["unique_connections"] = 0.0

    # syn_only_ratio: SYN set but ACK NOT set — bare SYN probe/flood separates PortScan from normal
    syn_only = syn * (1.0 - ack)  # SYN=1, ACK=0
    features["syn_only_ratio"] = float(syn_only.sum()) / max(float(n), 1.0)

    # ── Dominant port features (critical for SSH vs FTP vs SYNFlood) ────────
    tcp_dport_nz = tcp_dport[tcp_dport > 0]
    if len(tcp_dport_nz) > 0:
        features["tcp_dport_mode"] = float(scipy_stats.mode(tcp_dport_nz, keepdims=True).mode[0])
        features["tcp_dport_min"] = float(np.min(tcp_dport_nz))
        # Count of unique well-known destination ports (< 1024)
        low_ports = tcp_dport_nz[tcp_dport_nz < 1024]
        features["unique_dst_ports_low"] = float(len(np.unique(low_ports))) if len(low_ports) > 0 else 0.0
    else:
        features["tcp_dport_mode"] = 0.0
        features["tcp_dport_min"] = 0.0
        features["unique_dst_ports_low"] = 0.0

    # ── Protocol distribution ────────────────────────────────────────────────
    proto = window_df["protocol_encoded"].values if "protocol_encoded" in window_df else np.zeros(n)
    features["proto_tcp_ratio"]  = float(np.sum(proto == 1)) / n if n > 0 else 0.0
    features["proto_udp_ratio"]  = float(np.sum(proto == 2)) / n if n > 0 else 0.0
    features["proto_icmp_ratio"] = float(np.sum(proto == 3)) / n if n > 0 else 0.0
    features["proto_arp_ratio"]  = float(np.sum(proto == 4)) / n if n > 0 else 0.0
    features["proto_entropy"]    = _entropy(proto)

    # ── ARP-specific features (ARPSpoof discriminator) ───────────────────────
    # Binary flag: even 1 ARP packet in a window of 10 is suspicious
    n_arp = float(np.sum(proto == 4))
    features["arp_present"] = 1.0 if n_arp > 0 else 0.0
    features["arp_pkt_count"] = n_arp

    # ── ICMP stats ───────────────────────────────────────────────────────────
    icmp_type = window_df["ICMP Type"].values if "ICMP Type" in window_df else np.zeros(n)
    features["icmp_count"] = float(np.sum(icmp_type > 0))
    features["icmp_type_mode"] = float(scipy_stats.mode(icmp_type[icmp_type > 0], keepdims=True).mode[0]) if np.any(icmp_type > 0) else 0.0

    # ── UDP Length stats ─────────────────────────────────────────────────────
    udp_len = window_df["UDP Length"].values if "UDP Length" in window_df else np.zeros(n)
    features["udp_len_mean"] = _safe_stat(udp_len, np.mean)
    features["udp_len_std"]  = _safe_stat(udp_len, np.std)

    # ── IP fields ────────────────────────────────────────────────────────────
    ip_frag = window_df["IP Fragment Offset"].values if "IP Fragment Offset" in window_df else np.zeros(n)
    features["ip_frag_count"] = float(np.sum(ip_frag > 0))

    dscp = window_df["IP DSCP Field"].values if "IP DSCP Field" in window_df else np.zeros(n)
    features["dscp_mean"] = _safe_stat(dscp, np.mean)

    ip_flags = window_df["IP Flags"].values if "IP Flags" in window_df else np.zeros(n)
    features["ip_flags_mean"] = _safe_stat(ip_flags, np.mean)

    ip_proto = window_df["IP Protocol"].values if "IP Protocol" in window_df else np.zeros(n)
    features["ip_proto_mode"] = float(scipy_stats.mode(ip_proto, keepdims=True).mode[0]) if len(ip_proto) > 0 else 0.0

    return features


def get_feature_names() -> list:
    """Return ordered list of feature names produced by compute_window_features."""
    # Create a dummy window to get feature names
    dummy = pd.DataFrame({
        "Length": [0.0], "IP Length": [0.0], "TCP Length": [0.0],
        "TCP Window Size": [0.0], "TCP SYN Flag": [0.0], "TCP ACK Flag": [0.0],
        "TCP FIN Flag": [0.0], "TCP RST Flag": [0.0], "IP TTL": [0.0],
        "TCP Source Port": [0.0], "TCP Destination Port": [0.0],
        "UDP Source Port": [0.0], "UDP Destination Port": [0.0],
        "protocol_encoded": [0.0],
        "ICMP Type": [0.0], "UDP Length": [0.0],
        "IP Fragment Offset": [0.0], "IP DSCP Field": [0.0],
        "IP Flags": [0.0], "IP Protocol": [0.0],
    })
    features = compute_window_features(dummy)
    return sorted(features.keys())


def create_sliding_windows(df: pd.DataFrame,
                           window_size: int = WINDOW_SIZE) -> tuple:
    """
    Convert packet-level DataFrame into sliding-window feature arrays.

    Parameters
    ----------
    df : DataFrame with numeric packet columns + binary_label + attack_class
    window_size : int, number of packets per window

    Returns
    -------
    (X, y_binary, y_attack, feature_names)
    X : np.ndarray of shape (n_windows, n_features)
    y_binary : np.ndarray of shape (n_windows,) — 0=Normal, 1=Attack
    y_attack : np.ndarray of shape (n_windows,) — encoded attack class (-1 for Normal)
    feature_names : list of str
    """
    print("\n  Creating sliding windows ...")
    feature_names = get_feature_names()
    n_features = len(feature_names)

    # Group by attack_class to maintain label consistency within windows
    all_X = []
    all_y_binary = []
    all_y_attack = []

    total_classes = df["attack_class"].nunique()

    for cls_idx, cls in enumerate(df["attack_class"].unique()):
        cls_df = df[df["attack_class"] == cls].reset_index(drop=True)

        # Sort by timestamp to create temporally coherent windows
        if "Frame Time (Epoch)" in cls_df.columns:
            cls_df = cls_df.sort_values("Frame Time (Epoch)").reset_index(drop=True)

        n_windows = len(cls_df) // window_size

        if n_windows == 0:
            continue

        binary_label = 0 if cls == "Normal" else 1
        attack_id = ATTACK_LABEL2ID.get(cls, -1)

        print(f"    [{cls_idx+1}/{total_classes}] {cls}: {len(cls_df):,} rows -> {n_windows:,} windows")

        # Process in batch chunks to show progress
        chunk_size = 5000  # windows per progress tick
        cls_features = []

        for i in range(n_windows):
            start = i * window_size
            end = start + window_size
            window = cls_df.iloc[start:end]

            feat_dict = compute_window_features(window)
            feat_vec = np.array([feat_dict.get(f, 0.0) for f in feature_names], dtype=np.float32)
            cls_features.append(feat_vec)

            # Print progress every chunk_size windows
            if (i + 1) % chunk_size == 0:
                print(f"      {i+1:>8,}/{n_windows:,} windows processed")

        cls_X = np.array(cls_features, dtype=np.float32)
        all_X.append(cls_X)
        all_y_binary.extend([binary_label] * n_windows)
        all_y_attack.extend([attack_id] * n_windows)

    X = np.vstack(all_X) if all_X else np.array([]).reshape(0, len(feature_names))
    y_binary = np.array(all_y_binary, dtype=np.int32)
    y_attack = np.array(all_y_attack, dtype=np.int32)

    print(f"\n  Windows created: {X.shape[0]:,}  Features: {X.shape[1]}")
    print(f"  Normal windows:  {np.sum(y_binary == 0):,}")
    print(f"  Attack windows:  {np.sum(y_binary == 1):,}")

    return X, y_binary, y_attack, feature_names
