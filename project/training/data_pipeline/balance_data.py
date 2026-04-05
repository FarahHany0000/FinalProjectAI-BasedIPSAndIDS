"""
Balance the training CSV: downsample large classes, upsample small ones.
Produces a balanced CSV ready for training.
"""
import sys
import pathlib
import pandas as pd
import numpy as np

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

INPUT_CSV = ROOT / "data_pipeline" / "training_data_live.csv"
OUTPUT_CSV = ROOT / "data_pipeline" / "training_data_balanced.csv"

# Target: all classes have roughly the same number of windows.
# Strategy:
#   - Classes with more than TARGET → downsample
#   - Classes with less than TARGET → upsample (duplicate with noise)
# Use the median class size as target — avoids extreme up/downsampling
# Override: set to 0 to auto-detect from data
TARGET_WINDOWS = 5000


KEEP_EXACT = {
    "tcp_dport_min", "tcp_dport_mode", "unique_dst_ports_low",
    "arp_pkt_count", "arp_present", "icmp_type_mode", "ip_proto_mode",
    "syn_count", "ack_count", "fin_count", "rst_count",
    "pkt_count", "icmp_count", "ip_frag_count",
}


def add_noise(df, n_extra, noise_level=0.01):
    """Create synthetic samples by adding small Gaussian noise to existing ones.
    Port numbers, counts, and categorical features are kept exact."""
    if len(df) == 0:
        return df
    feature_cols = [c for c in df.columns if c != "label"]
    samples = df.sample(n=n_extra, replace=True, random_state=42).copy()
    for col in feature_cols:
        if col in KEEP_EXACT:
            continue
        std = df[col].std()
        if std > 0:
            noise = np.random.normal(0, std * noise_level, size=n_extra)
            samples[col] = samples[col].values + noise
    return samples


def filter_ambiguous_windows(df):
    """
    Remove PortScan windows that are indistinguishable from SYNFlood.

    Problem: nmap -sS retries the same port multiple times, creating
    10-packet windows where all packets hit port 80 with unique src ports.
    These windows have unique_dst_ports=1, tcp_dport_mode=80, and
    unique_src_ports=10 -- identical to SYNFlood.

    Fix: keep only PortScan windows with unique_dst_ports > 1, which
    clearly show port scanning behavior (multiple destination ports).
    """
    ps_mask = df["label"] == "PortScan"
    ps = df[ps_mask]
    ambiguous = ps["unique_dst_ports"] <= 1
    n_removed = ambiguous.sum()

    if n_removed > 0:
        # Keep non-PortScan rows + non-ambiguous PortScan rows
        df_clean = pd.concat([
            df[~ps_mask],
            ps[~ambiguous]
        ], ignore_index=True)
        print(f"\n  Filtered PortScan: removed {n_removed:,} ambiguous windows "
              f"(unique_dst_ports=1, looks like SYNFlood)")
        print(f"  Kept {(~ambiguous).sum():,} clear PortScan windows (unique_dst_ports > 1)")
        return df_clean

    return df


def main():
    print("=" * 60)
    print("  Balancing Training Data")
    print("=" * 60)

    df = pd.read_csv(str(INPUT_CSV))
    print(f"\n  Input: {len(df):,} total windows")
    print(f"\n  Original distribution:")
    for cls, cnt in df["label"].value_counts().items():
        print(f"    {cls:<15} {cnt:>8,}")

    # Remove ambiguous PortScan windows before balancing
    df = filter_ambiguous_windows(df)
    print(f"\n  After filtering: {len(df):,} total windows")
    print(f"  Filtered distribution:")
    for cls, cnt in df["label"].value_counts().items():
        print(f"    {cls:<15} {cnt:>8,}")

    # Auto-detect target: use median class size (fair balance)
    global TARGET_WINDOWS
    if TARGET_WINDOWS == 0:
        class_sizes = df["label"].value_counts().values
        TARGET_WINDOWS = int(np.median(class_sizes))
        print(f"\n  Auto target: {TARGET_WINDOWS:,} windows per class (median)")

    balanced_parts = []

    for cls in df["label"].unique():
        cls_df = df[df["label"] == cls].copy()
        n = len(cls_df)

        if n >= TARGET_WINDOWS:
            # Downsample
            sampled = cls_df.sample(n=TARGET_WINDOWS, random_state=42)
            print(f"\n  {cls:<15} {n:>6,} -> {TARGET_WINDOWS:,} (downsampled)")
        elif n < TARGET_WINDOWS:
            # Upsample with noise
            n_extra = TARGET_WINDOWS - n
            extra = add_noise(cls_df, n_extra)
            sampled = pd.concat([cls_df, extra], ignore_index=True)
            print(f"\n  {cls:<15} {n:>6,} -> {TARGET_WINDOWS:,} (upsampled +{n_extra:,} synthetic)")
        balanced_parts.append(sampled)

    balanced = pd.concat(balanced_parts, ignore_index=True)
    balanced = balanced.sample(frac=1, random_state=42).reset_index(drop=True)
    balanced.to_csv(str(OUTPUT_CSV), index=False)

    print(f"\n{'=' * 60}")
    print(f"  Balanced output: {len(balanced):,} total windows")
    print(f"  Output: {OUTPUT_CSV}")
    print(f"\n  Final distribution:")
    for cls, cnt in balanced["label"].value_counts().items():
        print(f"    {cls:<15} {cnt:>8,}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
