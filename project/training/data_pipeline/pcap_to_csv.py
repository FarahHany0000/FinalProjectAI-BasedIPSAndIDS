"""
Convert labeled PCAP files to training CSV.

Uses the SAME feature pipeline as live capture (packet_parser.py +
feature_engineer.py), so training and inference features come from
the exact same code path. This eliminates domain mismatch.
"""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pandas as pd
import numpy as np
from scapy.all import PcapReader
from sniffer.packet_parser import parse_scapy_packet
from data_pipeline.feature_engineer import compute_window_features, get_feature_names
from config.settings import WINDOW_SIZE

# ── Configuration ────────────────────────────────────────────────────────────
PCAP_FILES = {
    "Normal":   "captures/normal.pcap",
    "PortScan": "captures/portscan.pcap",
    "SSHBrute": "captures/sshbrute.pcap",
    "SYNFlood": "captures/synflood.pcap",
    "ARPSpoof": "captures/arpspoof.pcap",
    "FTPBrute": "captures/ftpbrute.pcap",
}

OUTPUT_CSV = "data_pipeline/training_data_live.csv"
MAX_WINDOWS_PER_CLASS = 50_000


def pcap_to_windows(pcap_path, label, window_size=WINDOW_SIZE, max_windows=None):
    """Read a PCAP, parse each packet, aggregate into windows."""
    print(f"  Loading {pcap_path} ...")
    parsed_packets = []

    try:
        with PcapReader(str(pcap_path)) as reader:
            for pkt in reader:
                try:
                    p = parse_scapy_packet(pkt)
                    p.pop("_src_ip", None)
                    p.pop("_dst_ip", None)
                    parsed_packets.append(p)
                except Exception:
                    continue
    except Exception as e:
        print(f"  ERROR: Could not read {pcap_path}: {e}")
        return pd.DataFrame()

    total_pkts = len(parsed_packets)
    n_windows = total_pkts // window_size
    if max_windows:
        n_windows = min(n_windows, max_windows)

    print(f"  {total_pkts:,} packets  ->  {n_windows:,} windows  (label: {label})")

    if n_windows == 0:
        print(f"  WARNING: Need at least {window_size}, got {total_pkts}.")
        return pd.DataFrame()

    feature_names = get_feature_names()
    rows = []

    for i in range(n_windows):
        window = parsed_packets[i * window_size : (i + 1) * window_size]
        window_df = pd.DataFrame(window)
        feat = compute_window_features(window_df)
        feat_vec = [feat.get(f, 0.0) for f in feature_names]
        rows.append(feat_vec + [label])

        if (i + 1) % 2000 == 0:
            print(f"    {i + 1:>8,} / {n_windows:,} windows ...")

    return pd.DataFrame(rows, columns=feature_names + ["label"])


def main():
    print("=" * 60)
    print("  PCAP -> Training CSV")
    print("  Same feature pipeline as live capture")
    print("=" * 60)

    all_dfs = []

    for label, rel_path in PCAP_FILES.items():
        pcap_path = ROOT / rel_path
        print(f"\n[{label}]")

        if not pcap_path.exists():
            print(f"  SKIP — not found: {pcap_path}")
            continue

        df = pcap_to_windows(pcap_path, label, max_windows=MAX_WINDOWS_PER_CLASS)
        if not df.empty:
            all_dfs.append(df)
            print(f"  -> {len(df):,} windows added")

    if not all_dfs:
        print("\nERROR: No data collected.")
        return

    combined = pd.concat(all_dfs, ignore_index=True)
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)

    output_path = ROOT / OUTPUT_CSV
    output_path.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(str(output_path), index=False)

    print(f"\n{'=' * 60}")
    print(f"  Saved {len(combined):,} total windows")
    print(f"  Output: {output_path}")
    print(f"\n  Class distribution:")
    counts = combined["label"].value_counts()
    for cls, cnt in counts.items():
        print(f"    {cls:<15} {cnt:>8,} windows")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
