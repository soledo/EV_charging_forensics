#!/usr/bin/env python3
"""
Phase 4 - Task 4-1: 3-Layer Feature Fusion (DoS + Recon)
Create integrated dataset combining Host + Network + Power features
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime

base_dir = Path('/mnt/d/EV_charging_forensics')
network_dir = base_dir / 'processed' / 'stage2'
host_path = base_dir / 'processed' / 'stage2' / 'host_scaled.csv'
power_path = base_dir / 'processed' / 'stage2' / 'power_scaled.csv'
stage3_dir = base_dir / 'processed' / 'stage3'
output_dir = base_dir / 'processed' / 'stage4'
output_dir.mkdir(exist_ok=True, parents=True)

print("="*80)
print("PHASE 4 - TASK 4-1: 3-LAYER FEATURE FUSION (DoS + Recon)")
print("="*80)

# Load alignment results
print("\n📂 Loading alignment results...")
with open(stage3_dir / 'host_segment_matching.json', 'r') as f:
    alignment_data = json.load(f)

with open(stage3_dir / 'recon_windows.json', 'r') as f:
    recon_data = json.load(f)

with open(stage3_dir / 'dos_windows.json', 'r') as f:
    dos_data = json.load(f)

print("✅ Loaded alignment data")

# Load data
print("\n📂 Loading data files...")
df_host = pd.read_csv(host_path, low_memory=False)
df_power = pd.read_csv(power_path, low_memory=False)
print(f"✅ Host: {len(df_host):,} records")
print(f"✅ Power: {len(df_power):,} records")

# ============================================================================
# STEP 1: Extract Network Features from Best Windows
# ============================================================================
print("\n" + "="*80)
print("STEP 1: EXTRACT NETWORK FEATURES")
print("="*80)

def extract_network_features(window_df, scenario_name):
    """Extract 20 network features from a traffic window"""

    features = {}

    # Traffic intensity (4 features)
    features['net_packet_count'] = len(window_df)
    features['net_bytes_total'] = window_df['bidirectional_bytes'].sum() if 'bidirectional_bytes' in window_df.columns else 0
    features['net_packet_rate'] = len(window_df) / 60.0  # per second over 60s window
    features['net_byte_rate'] = features['net_bytes_total'] / 60.0

    # Protocol distribution (4 features)
    if 'protocol' in window_df.columns:
        protocol_counts = window_df['protocol'].value_counts()
        features['net_tcp_ratio'] = protocol_counts.get(6, 0) / len(window_df) if len(window_df) > 0 else 0
        features['net_udp_ratio'] = protocol_counts.get(17, 0) / len(window_df) if len(window_df) > 0 else 0
        features['net_icmp_ratio'] = protocol_counts.get(1, 0) / len(window_df) if len(window_df) > 0 else 0
        features['net_protocol_diversity'] = len(protocol_counts) / max(len(window_df), 1)
    else:
        features['net_tcp_ratio'] = 0
        features['net_udp_ratio'] = 0
        features['net_icmp_ratio'] = 0
        features['net_protocol_diversity'] = 0

    # Port statistics (4 features)
    if 'dst_port' in window_df.columns:
        unique_ports = window_df['dst_port'].nunique()
        features['net_unique_dst_ports'] = unique_ports
        features['net_port_diversity'] = unique_ports / max(len(window_df), 1)

        # Port entropy
        port_counts = window_df['dst_port'].value_counts()
        port_probs = port_counts / port_counts.sum()
        features['net_port_entropy'] = -sum(port_probs * np.log2(port_probs + 1e-10))
        features['net_port_concentration'] = port_counts.max() / port_counts.sum()
    else:
        features['net_unique_dst_ports'] = 0
        features['net_port_diversity'] = 0
        features['net_port_entropy'] = 0
        features['net_port_concentration'] = 0

    # Connection patterns (4 features)
    if 'bidirectional_syn_packets' in window_df.columns:
        features['net_syn_ratio'] = window_df['bidirectional_syn_packets'].sum() / max(len(window_df), 1)
        features['net_fin_ratio'] = window_df['bidirectional_fin_packets'].sum() / max(len(window_df), 1) if 'bidirectional_fin_packets' in window_df.columns else 0
        features['net_rst_ratio'] = window_df['bidirectional_rst_packets'].sum() / max(len(window_df), 1) if 'bidirectional_rst_packets' in window_df.columns else 0
        features['net_ack_ratio'] = window_df['bidirectional_ack_packets'].sum() / max(len(window_df), 1) if 'bidirectional_ack_packets' in window_df.columns else 0
    else:
        features['net_syn_ratio'] = 0
        features['net_fin_ratio'] = 0
        features['net_rst_ratio'] = 0
        features['net_ack_ratio'] = 0

    # Temporal patterns (4 features)
    if 'timestamp_normalized' in window_df.columns and len(window_df) > 1:
        sorted_df = window_df.sort_values('timestamp_normalized')
        inter_arrival = sorted_df['timestamp_normalized'].diff().dropna()
        features['net_inter_arrival_mean'] = float(inter_arrival.mean()) if len(inter_arrival) > 0 else 0
        features['net_inter_arrival_std'] = float(inter_arrival.std()) if len(inter_arrival) > 0 else 0
        features['net_inter_arrival_min'] = float(inter_arrival.min()) if len(inter_arrival) > 0 else 0
        features['net_inter_arrival_max'] = float(inter_arrival.max()) if len(inter_arrival) > 0 else 0
    else:
        features['net_inter_arrival_mean'] = 0
        features['net_inter_arrival_std'] = 0
        features['net_inter_arrival_min'] = 0
        features['net_inter_arrival_max'] = 0

    return features

# Process Recon window
print("\n🔍 Processing Recon network window...")
recon_window = recon_data['selected_window']
recon_net_file = network_dir / recon_window['file']
df_recon_net = pd.read_csv(recon_net_file, low_memory=False)

recon_net_window = df_recon_net[
    (df_recon_net['timestamp_normalized'] >= recon_window['start_time']) &
    (df_recon_net['timestamp_normalized'] < recon_window['end_time'])
]

recon_net_features = extract_network_features(recon_net_window, 'Recon')
print(f"   ✅ Extracted {len(recon_net_features)} network features from Recon window")

# Process DoS window
print("\n🔍 Processing DoS network window...")
dos_window = dos_data['selected_window']
dos_net_file = network_dir / dos_window['file']
df_dos_net = pd.read_csv(dos_net_file, low_memory=False)

dos_net_window = df_dos_net[
    (df_dos_net['timestamp_normalized'] >= dos_window['start_time']) &
    (df_dos_net['timestamp_normalized'] < dos_window['end_time'])
]

dos_net_features = extract_network_features(dos_net_window, 'DoS')
print(f"   ✅ Extracted {len(dos_net_features)} network features from DoS window")

# ============================================================================
# STEP 2: Align Host + Network + Power Features
# ============================================================================
print("\n" + "="*80)
print("STEP 2: 3-LAYER FEATURE ALIGNMENT")
print("="*80)

# Get Recon Host segment
recon_host = df_host[df_host['Scenario'] == 'Recon'].copy()
print(f"\n📊 Recon Host: {len(recon_host):,} records")

# Add Network features to each Host record (broadcasting)
for feat_name, feat_value in recon_net_features.items():
    recon_host[feat_name] = feat_value

# Get Recon Power features (aggregate statistics)
recon_power_attacks = ['vuln-scan', 'syn-stealth']
recon_power = df_power[df_power['Attack'].isin(recon_power_attacks)]

if len(recon_power) > 0:
    recon_power_features = {
        'power_mean': recon_power['power_mW'].mean(),
        'power_std': recon_power['power_mW'].std(),
        'power_min': recon_power['power_mW'].min(),
        'power_max': recon_power['power_mW'].max()
    }

    for feat_name, feat_value in recon_power_features.items():
        recon_host[feat_name] = feat_value

    print(f"   ✅ Added {len(recon_power_features)} Power features to Recon")

# Get DoS Host segment
dos_host = df_host[df_host['Scenario'] == 'DoS'].copy()
print(f"\n📊 DoS Host: {len(dos_host):,} records")

# Add Network features
for feat_name, feat_value in dos_net_features.items():
    dos_host[feat_name] = feat_value

# Get DoS Power features
dos_power = df_power[df_power['Attack'].str.contains('flood', case=False, na=False)]

if len(dos_power) > 0:
    dos_power_features = {
        'power_mean': dos_power['power_mW'].mean(),
        'power_std': dos_power['power_mW'].std(),
        'power_min': dos_power['power_mW'].min(),
        'power_max': dos_power['power_mW'].max()
    }

    for feat_name, feat_value in dos_power_features.items():
        dos_host[feat_name] = feat_value

    print(f"   ✅ Added {len(dos_power_features)} Power features to DoS")

# ============================================================================
# STEP 3: Combine and Save 3-Layer Dataset
# ============================================================================
print("\n" + "="*80)
print("STEP 3: CREATE 3-LAYER INTEGRATED DATASET")
print("="*80)

# Combine Recon and DoS
df_3layer = pd.concat([recon_host, dos_host], ignore_index=True)

print(f"\n📊 3-Layer Dataset:")
print(f"   Total records: {len(df_3layer):,}")
print(f"   Recon: {len(recon_host):,} ({len(recon_host)/len(df_3layer)*100:.1f}%)")
print(f"   DoS: {len(dos_host):,} ({len(dos_host)/len(df_3layer)*100:.1f}%)")
print(f"   Total features: {len(df_3layer.columns)}")

# Identify feature categories
host_features = [col for col in df_3layer.columns if col not in ['time', 'State', 'Attack', 'Scenario', 'Label', 'interface', 'timestamp_normalized'] and not col.startswith('net_') and not col.startswith('power_')]
network_features = [col for col in df_3layer.columns if col.startswith('net_')]
power_features = [col for col in df_3layer.columns if col.startswith('power_')]

print(f"\n📊 Feature Breakdown:")
print(f"   Host features: {len(host_features)}")
print(f"   Network features: {len(network_features)}")
print(f"   Power features: {len(power_features)}")
print(f"   Total: {len(host_features) + len(network_features) + len(power_features)}")

# Save dataset
output_file = output_dir / 'dataset_3layer_dos_recon.csv'
df_3layer.to_csv(output_file, index=False)
print(f"\n💾 Saved: {output_file}")

# Save metadata
metadata = {
    'total_records': int(len(df_3layer)),
    'recon_records': int(len(recon_host)),
    'dos_records': int(len(dos_host)),
    'total_features': int(len(df_3layer.columns)),
    'host_features': len(host_features),
    'network_features': len(network_features),
    'power_features': len(power_features),
    'scenarios': ['Recon', 'DoS'],
    'creation_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
}

metadata_file = output_dir / 'dataset_3layer_metadata.json'
with open(metadata_file, 'w') as f:
    json.dump(metadata, f, indent=2)

print("="*80)
print("✅ TASK 4-1 COMPLETE")
print("="*80)
print(f"\n📊 3-Layer Dataset Created:")
print(f"   - Records: {len(df_3layer):,} (DoS: {len(dos_host):,}, Recon: {len(recon_host):,})")
print(f"   - Features: {len(host_features)} Host + {len(network_features)} Network + {len(power_features)} Power = {len(host_features) + len(network_features) + len(power_features)}")
print(f"   - File: {output_file}")
print(f"\nℹ️  Next: Task 4-2 - 2-Layer Feature Fusion (Benign + Crypto)")
