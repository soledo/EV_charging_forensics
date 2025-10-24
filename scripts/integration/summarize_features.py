#!/usr/bin/env python3
"""
Phase 4 - Task 4-3: Feature Summary
Summarize features across both datasets
"""

import pandas as pd
import json
from pathlib import Path
from datetime import datetime

base_dir = Path('/mnt/d/EV_charging_forensics')
stage4_dir = base_dir / 'processed' / 'stage4'

print("="*80)
print("PHASE 4 - TASK 4-3: FEATURE SUMMARY")
print("="*80)

# Load datasets
print("\n📂 Loading datasets...")
df_3layer = pd.read_csv(stage4_dir / 'dataset_3layer_dos_recon.csv', low_memory=False)
df_2layer = pd.read_csv(stage4_dir / 'dataset_2layer_benign_crypto.csv', low_memory=False)

print(f"✅ 3-layer: {len(df_3layer):,} records, {len(df_3layer.columns)} features")
print(f"✅ 2-layer: {len(df_2layer):,} records, {len(df_2layer.columns)} features")

# Feature categorization
print("\n📊 Feature Analysis:")

# 3-layer features
metadata_3 = ['time', 'State', 'Attack', 'Scenario', 'Label', 'interface', 'timestamp_normalized']
host_3 = [c for c in df_3layer.columns if c not in metadata_3 and not c.startswith('net_') and not c.startswith('power_')]
network_3 = [c for c in df_3layer.columns if c.startswith('net_') and c not in ['net_napi_gro_frags_entry', 'net_napi_gro_frags_exit', 'net_napi_gro_receive_entry', 'net_napi_gro_receive_exit', 'net_net_dev_queue', 'net_net_dev_start_xmit', 'net_net_dev_xmit', 'net_net_dev_xmit_timeout', 'net_netif_receive_skb', 'net_netif_receive_skb_entry', 'net_netif_receive_skb_exit', 'net_netif_receive_skb_list_entry', 'net_netif_receive_skb_list_exit', 'net_netif_rx', 'net_netif_rx_entry', 'net_netif_rx_exit', 'net_netif_rx_ni_entry', 'net_netif_rx_ni_exit']]
power_3 = [c for c in df_3layer.columns if c.startswith('power_')]

print(f"\n3-Layer Dataset (Network-Originated: DoS + Recon):")
print(f"   Host features: {len(host_3)}")
print(f"   Network features: {len(network_3)}")
print(f"   Power features: {len(power_3)}")
print(f"   Total: {len(host_3) + len(network_3) + len(power_3)}")

# 2-layer features
host_2 = [c for c in df_2layer.columns if c not in metadata_3 and not c.startswith('power_')]
power_2 = [c for c in df_2layer.columns if c.startswith('power_')]

print(f"\n2-Layer Dataset (Host-Originated: Benign + Crypto):")
print(f"   Host features: {len(host_2)}")
print(f"   Power features: {len(power_2)}")
print(f"   Total: {len(host_2) + len(power_2)}")

# Save summary
summary = {
    '3layer_dataset': {
        'scenarios': ['DoS', 'Recon'],
        'total_records': int(len(df_3layer)),
        'total_features': len(host_3) + len(network_3) + len(power_3),
        'host_features': len(host_3),
        'network_features': len(network_3),
        'power_features': len(power_3),
        'layer_composition': 'Host + Network + Power'
    },
    '2layer_dataset': {
        'scenarios': ['Benign', 'Cryptojacking'],
        'total_records': int(len(df_2layer)),
        'total_features': len(host_2) + len(power_2),
        'host_features': len(host_2),
        'network_features': 0,
        'power_features': len(power_2),
        'layer_composition': 'Host + Power (NO Network)'
    },
    'summary_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
}

output_file = stage4_dir / 'feature_summary.json'
with open(output_file, 'w') as f:
    json.dump(summary, f, indent=2)

print(f"\n💾 Summary saved: {output_file}")

print("\n" + "="*80)
print("✅ TASK 4-3 COMPLETE")
print("="*80)
print(f"\nℹ️  Next: Task 4-4 - Dataset Validation")
