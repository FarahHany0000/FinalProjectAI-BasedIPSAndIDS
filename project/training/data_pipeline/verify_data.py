"""Verify training data quality."""
import sys, pathlib
import pandas as pd
import numpy as np

ROOT = pathlib.Path(__file__).resolve().parent.parent
CSV = ROOT / "data_pipeline" / "training_data_balanced.csv"

df = pd.read_csv(str(CSV))
feature_cols = [c for c in df.columns if c != "label"]

print("=" * 70)
print("  DATA QUALITY REPORT")
print("=" * 70)

# 1. Basic stats
print(f"\n  Total rows:    {len(df):,}")
print(f"  Total features: {len(feature_cols)}")
print(f"  NaN values:    {df[feature_cols].isna().sum().sum()}")
print(f"  Inf values:    {np.isinf(df[feature_cols].values).sum()}")

# 2. Class distribution
print(f"\n  Class distribution:")
for cls, cnt in df["label"].value_counts().items():
    print(f"    {cls:<15} {cnt:>6,}")

# 3. Key discriminative features per class
print(f"\n  Key features by class (mean values):")
print(f"  {'Class':<12} {'syn_rat':>8} {'ack_rat':>8} {'rst_syn':>8} {'dport_min':>10} {'udpl':>6} {'arp_cnt':>8} {'tcp_rat':>8} {'udp_rat':>8} {'icmp_rat':>8} {'pkt_cnt':>8}")
print(f"  {'-'*12} {'-'*8} {'-'*8} {'-'*8} {'-'*10} {'-'*6} {'-'*8} {'-'*8} {'-'*8} {'-'*8} {'-'*8}")

for cls in sorted(df["label"].unique()):
    sub = df[df["label"] == cls]
    syn_r = sub["syn_ratio"].mean()
    ack_r = sub["ack_ratio"].mean()
    rst_s = sub["rst_to_syn_ratio"].mean()
    dp_min = sub["tcp_dport_min"].mean()
    udpl = sub["unique_dst_ports_low"].mean()
    arp_c = sub["arp_pkt_count"].mean()
    tcp_r = sub["proto_tcp_ratio"].mean()
    udp_r = sub["proto_udp_ratio"].mean()
    icmp_r = sub["proto_icmp_ratio"].mean()
    pkt_c = sub["pkt_count"].mean()
    print(f"  {cls:<12} {syn_r:>8.3f} {ack_r:>8.3f} {rst_s:>8.3f} {dp_min:>10.1f} {udpl:>6.1f} {arp_c:>8.1f} {tcp_r:>8.3f} {udp_r:>8.3f} {icmp_r:>8.3f} {pkt_c:>8.1f}")

# 4. Sanity checks
print("\n  Sanity Checks:")
checks_passed = 0
checks_total = 0

# ARPSpoof should have high arp_pkt_count
checks_total += 1
arp_arp = df[df["label"] == "ARPSpoof"]["arp_pkt_count"].mean()
if arp_arp > 1.0:
    print(f"    [PASS] ARPSpoof has high arp_pkt_count: {arp_arp:.1f}")
    checks_passed += 1
else:
    print(f"    [FAIL] ARPSpoof arp_pkt_count too low: {arp_arp:.1f}")

# PortScan should have high unique_dst_ports
checks_total += 1
ps_udp = df[df["label"] == "PortScan"]["unique_dst_ports"].mean()
if ps_udp > 5.0:
    print(f"    [PASS] PortScan has high unique_dst_ports: {ps_udp:.1f}")
    checks_passed += 1
else:
    print(f"    [FAIL] PortScan unique_dst_ports too low: {ps_udp:.1f}")

# SSHBrute should target port 22 (use mode: most common dst port per window,
# since the PCAP also contains server response packets to ephemeral ports
# which inflate tcp_dport_min)
checks_total += 1
ssh_dp = df[df["label"] == "SSHBrute"]["tcp_dport_mode"].median()
if 20 <= ssh_dp <= 25:
    print(f"    [PASS] SSHBrute dominant port is ~22: {ssh_dp:.0f}")
    checks_passed += 1
else:
    print(f"    [FAIL] SSHBrute tcp_dport_mode unexpected: {ssh_dp:.0f}")

# FTPBrute should target port 21 (use mode for same reason as SSHBrute)
checks_total += 1
ftp_dp = df[df["label"] == "FTPBrute"]["tcp_dport_mode"].median()
if 19 <= ftp_dp <= 23:
    print(f"    [PASS] FTPBrute dominant port is ~21: {ftp_dp:.0f}")
    checks_passed += 1
else:
    print(f"    [FAIL] FTPBrute tcp_dport_mode unexpected: {ftp_dp:.0f}")

# SYNFlood should have high syn_ratio
checks_total += 1
sf_syn = df[df["label"] == "SYNFlood"]["syn_ratio"].mean()
if sf_syn > 0.3:
    print(f"    [PASS] SYNFlood has high syn_ratio: {sf_syn:.3f}")
    checks_passed += 1
else:
    print(f"    [FAIL] SYNFlood syn_ratio too low: {sf_syn:.3f}")

# Normal should have low attack features
checks_total += 1
norm_syn = df[df["label"] == "Normal"]["syn_ratio"].mean()
norm_arp = df[df["label"] == "Normal"]["arp_pkt_count"].mean()
if norm_syn < 0.3 and norm_arp < 2.0:
    print(f"    [PASS] Normal has low attack features (syn={norm_syn:.3f}, arp={norm_arp:.1f})")
    checks_passed += 1
else:
    print(f"    [FAIL] Normal attack features too high (syn={norm_syn:.3f}, arp={norm_arp:.1f})")

print(f"\n  Result: {checks_passed}/{checks_total} checks passed")
print("=" * 70)
