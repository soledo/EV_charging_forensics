#!/usr/bin/env python3
"""
Task R1-1: FORCED Timeline Generation
Strategy: "어떻게든 맞춥시다!" - Create synthetic timeline despite temporal incompatibility
WARNING: This is NOT true Event Reconstruction - it's scenario-based feature synthesis
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime

base_dir = Path('/mnt/d/EV_charging_forensics')
raw_dir = base_dir / 'CICEVSE2024_Dataset'
processed_dir = base_dir / 'processed' / 'stage2'
output_dir = base_dir / 'processed' / 'reconstruction'
output_dir.mkdir(exist_ok=True, parents=True)

print("="*80)
print("TASK R1-1: FORCED TIMELINE GENERATION")
print("="*80)
print("\n⚠️  WARNING: Creating SYNTHETIC timeline despite temporal incompatibility")
print("   This is NOT true Event Reconstruction!")
print("   Strategy: Use scenario-based feature aggregation")

# ============================================================================
# STEP 1: Load DoS Host Data (Ground Truth Timeline)
# ============================================================================
print("\n" + "="*80)
print("STEP 1: HOST LAYER (GROUND TRUTH TIMELINE)")
print("="*80)

print("\n📂 Loading Host DoS data...")
df_host = pd.read_csv(processed_dir / 'host_scaled.csv', low_memory=False)
df_host['time'] = pd.to_numeric(df_host['time'], errors='coerce')
dos_host = df_host[df_host['Scenario'] == 'DoS'].copy()

print(f"✅ DoS Host: {len(dos_host):,} records")
print(f"   Time range: {dos_host['time'].min():.1f} - {dos_host['time'].max():.1f} seconds")
print(f"   Duration: {dos_host['time'].max() - dos_host['time'].min():.1f} seconds")

# Create 1-second bins
time_min = int(np.floor(dos_host['time'].min()))
time_max = int(np.ceil(dos_host['time'].max()))
time_bins = np.arange(time_min, time_max + 1, 1)

print(f"\n📊 Timeline: {len(time_bins)-1} seconds (1-second resolution)")

# Select top Host features by variance
host_feature_cols = [col for col in dos_host.columns if col not in
                     ['time', 'State', 'Attack', 'Scenario', 'Label', 'interface', 'timestamp_normalized', 'Unnamed: 0']
                     and not col.startswith('net_') and not col.startswith('power_')]

numeric_cols = dos_host[host_feature_cols].select_dtypes(include=[np.number]).columns
if len(numeric_cols) > 20:
    variances = dos_host[numeric_cols].var()
    top_features = variances.nlargest(20).index.tolist()
    host_feature_cols = top_features

print(f"   Selected {len(host_feature_cols)} Host features")

# Resample to 1-second
dos_host['time_bin'] = pd.cut(
    dos_host['time'],
    bins=time_bins,
    labels=time_bins[:-1],
    include_lowest=True
)

host_timeline = []
for time_sec in time_bins[:-1]:
    window = dos_host[dos_host['time_bin'] == time_sec]

    if len(window) > 0:
        features = {'time': int(time_sec)}
        for col in host_feature_cols:
            if col in window.columns:
                features[f'host_{col}'] = float(window[col].mean())
            else:
                features[f'host_{col}'] = 0.0
    else:
        features = {'time': int(time_sec)}
        for col in host_feature_cols:
            features[f'host_{col}'] = 0.0

    host_timeline.append(features)

df_host_timeline = pd.DataFrame(host_timeline)
print(f"✅ Host timeline: {len(df_host_timeline)} rows × {len(df_host_timeline.columns)} columns")

# ============================================================================
# STEP 2: Create Network Synthetic Features (Representative DoS Pattern)
# ============================================================================
print("\n" + "="*80)
print("STEP 2: NETWORK LAYER (SYNTHETIC FEATURES)")
print("="*80)

print("\n⚠️  WARNING: Network data from different time period (Dec 21)")
print("   Strategy: Use representative DoS flood pattern")

# Load a representative flood file
network_files = sorted((raw_dir / 'Network Traffic' / 'EVSE-B' / 'csv').glob('*flood*.csv'))
print(f"\n📂 Found {len(network_files)} flood attack files")

if len(network_files) > 0:
    # Use tcp-flood as representative
    tcp_flood_file = [f for f in network_files if 'tcp-flood' in f.name.lower()]
    if tcp_flood_file:
        sample_file = tcp_flood_file[0]
    else:
        sample_file = network_files[0]

    print(f"   Using: {sample_file.name}")

    df_network = pd.read_csv(sample_file, low_memory=False)
    print(f"   Records: {len(df_network):,}")

    # Calculate representative network features (aggregate statistics)
    net_features = {
        'net_packet_rate': len(df_network) / 30.0,  # Assume 30-second window
        'net_bytes_rate': df_network['bidirectional_bytes'].sum() / 30.0 if 'bidirectional_bytes' in df_network.columns else 0.0,
    }

    # Protocol distribution
    if 'protocol' in df_network.columns:
        protocol_counts = df_network['protocol'].value_counts()
        total = len(df_network)
        net_features['net_tcp_ratio'] = float(protocol_counts.get(6, 0) / total)
        net_features['net_udp_ratio'] = float(protocol_counts.get(17, 0) / total)
        net_features['net_icmp_ratio'] = float(protocol_counts.get(1, 0) / total)
    else:
        net_features['net_tcp_ratio'] = 1.0  # Assume TCP for flood
        net_features['net_udp_ratio'] = 0.0
        net_features['net_icmp_ratio'] = 0.0

    # Port statistics
    if 'dst_port' in df_network.columns:
        net_features['net_unique_ports'] = int(df_network['dst_port'].nunique())
        net_features['net_port_diversity'] = float(net_features['net_unique_ports'] / total)
    else:
        net_features['net_unique_ports'] = 1
        net_features['net_port_diversity'] = 0.0

    # Connection patterns
    if 'bidirectional_syn_packets' in df_network.columns:
        net_features['net_syn_ratio'] = float(df_network['bidirectional_syn_packets'].sum() / total)
    else:
        net_features['net_syn_ratio'] = 0.5

    print(f"\n📊 Representative Network Features:")
    print(f"   Packet rate: {net_features['net_packet_rate']:.1f} pkt/s")
    print(f"   TCP ratio: {net_features['net_tcp_ratio']:.3f}")
    print(f"   Unique ports: {net_features['net_unique_ports']}")

    # Replicate features for entire timeline
    for feat_name, feat_value in net_features.items():
        df_host_timeline[feat_name] = feat_value

    print(f"✅ Network features broadcasted to {len(df_host_timeline)} seconds")
else:
    print(f"❌ No flood files found - skipping Network features")

# ============================================================================
# STEP 3: Create Power Synthetic Features (Representative DoS Pattern)
# ============================================================================
print("\n" + "="*80)
print("STEP 3: POWER LAYER (SYNTHETIC FEATURES)")
print("="*80)

print("\n⚠️  WARNING: Power data from different time period (Dec 24-30)")
print("   Strategy: Use representative DoS power consumption pattern")

df_power = pd.read_csv(processed_dir / 'power_scaled.csv', low_memory=False)

# Find flood attacks in Power data
dos_power = df_power[df_power['Attack'].str.contains('flood', case=False, na=False)]

if len(dos_power) > 0:
    print(f"\n📂 Found {len(dos_power):,} Power records with 'flood' attacks")

    # Calculate representative power features
    power_features = {
        'power_mean': float(dos_power['power_mW'].mean()),
        'power_std': float(dos_power['power_mW'].std()),
        'power_min': float(dos_power['power_mW'].min()),
        'power_max': float(dos_power['power_mW'].max())
    }

    print(f"\n📊 Representative Power Features:")
    print(f"   Mean: {power_features['power_mean']:.2f} mW")
    print(f"   Std: {power_features['power_std']:.2f} mW")
    print(f"   Range: {power_features['power_min']:.2f} - {power_features['power_max']:.2f} mW")

    # Replicate features for entire timeline
    for feat_name, feat_value in power_features.items():
        df_host_timeline[feat_name] = feat_value

    print(f"✅ Power features broadcasted to {len(df_host_timeline)} seconds")
else:
    print(f"❌ No flood attacks in Power data - using overall mean")

    power_features = {
        'power_mean': float(df_power['power_mW'].mean()),
        'power_std': float(df_power['power_mW'].std()),
        'power_min': float(df_power['power_mW'].min()),
        'power_max': float(df_power['power_mW'].max())
    }

    for feat_name, feat_value in power_features.items():
        df_host_timeline[feat_name] = feat_value

# ============================================================================
# STEP 4: Validate Synthetic Timeline
# ============================================================================
print("\n" + "="*80)
print("STEP 4: SYNTHETIC TIMELINE VALIDATION")
print("="*80)

df_timeline = df_host_timeline

print(f"\n📊 Timeline Shape: {df_timeline.shape[0]} rows × {df_timeline.shape[1]} columns")

# Check continuity
time_diffs = df_timeline['time'].diff()
gaps = time_diffs[time_diffs > 1]

print(f"\n⏱️  Time Continuity:")
print(f"   Start: {df_timeline['time'].min()} seconds")
print(f"   End: {df_timeline['time'].max()} seconds")
print(f"   Duration: {df_timeline['time'].max() - df_timeline['time'].min() + 1} seconds")
print(f"   Time gaps (>1s): {len(gaps)}")

# Feature breakdown
host_cols = [col for col in df_timeline.columns if col.startswith('host_')]
net_cols = [col for col in df_timeline.columns if col.startswith('net_')]
power_cols = [col for col in df_timeline.columns if col.startswith('power_')]

print(f"\n📊 Feature Breakdown:")
print(f"   Host features: {len(host_cols)} (time-varying)")
print(f"   Network features: {len(net_cols)} (synthetic - constant)")
print(f"   Power features: {len(power_cols)} (synthetic - constant)")
print(f"   Total: {len(host_cols) + len(net_cols) + len(power_cols)}")

# Missing data
missing = df_timeline.isnull().sum().sum()
total_cells = df_timeline.shape[0] * df_timeline.shape[1]

print(f"\n📊 Data Completeness:")
print(f"   Missing cells: {missing:,} / {total_cells:,} ({missing/total_cells*100:.2f}%)")

# Check zero-activity
host_zero = (df_timeline[host_cols].sum(axis=1) == 0).sum()
net_zero = (df_timeline[net_cols].sum(axis=1) == 0).sum() if len(net_cols) > 0 else 0
power_zero = (df_timeline[power_cols].sum(axis=1) == 0).sum() if len(power_cols) > 0 else 0

print(f"\n📊 Zero-Activity Seconds:")
print(f"   Host: {host_zero} / {len(df_timeline)} ({host_zero/len(df_timeline)*100:.1f}%)")
print(f"   Network: {net_zero} / {len(df_timeline)} ({net_zero/len(df_timeline)*100:.1f}%)")
print(f"   Power: {power_zero} / {len(df_timeline)} ({power_zero/len(df_timeline)*100:.1f}%)")

# ============================================================================
# STEP 5: Save Timeline
# ============================================================================
output_file = output_dir / 'timeline_dos_synthetic.csv'
df_timeline.to_csv(output_file, index=False)

print(f"\n💾 Synthetic timeline saved: {output_file}")

# Save metadata
metadata = {
    'type': 'synthetic_timeline',
    'warning': 'This is NOT true Event Reconstruction - features are scenario-based aggregates',
    'strategy': 'Host time-varying + Network/Power representative statistics',
    'temporal_compatibility': {
        'host': 'time-varying (actual DoS timestamps)',
        'network': 'synthetic (representative flood pattern from Dec 21)',
        'power': 'synthetic (representative flood pattern from Dec 24-30)'
    },
    'shape': {
        'rows': int(df_timeline.shape[0]),
        'columns': int(df_timeline.shape[1])
    },
    'features': {
        'host': len(host_cols),
        'network': len(net_cols),
        'power': len(power_cols)
    },
    'data_quality': {
        'missing_percentage': float(missing/total_cells*100),
        'host_zero_activity_pct': float(host_zero/len(df_timeline)*100),
        'network_constant': True,
        'power_constant': True
    },
    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
}

metadata_file = output_dir / 'timeline_dos_synthetic_metadata.json'
with open(metadata_file, 'w') as f:
    json.dump(metadata, f, indent=2)

print(f"💾 Metadata saved: {metadata_file}")

# ============================================================================
# VERDICT
# ============================================================================
print("\n" + "="*80)
print("VERDICT: FORCED TIMELINE GENERATION")
print("="*80)

print(f"\n✅ Timeline created: {len(df_timeline)} seconds × {len(df_timeline.columns)} features")

print(f"\n⚠️  CRITICAL LIMITATIONS:")
print(f"   1. Network features are CONSTANT (not time-varying)")
print(f"      → Representative flood pattern, not actual packet-by-packet")
print(f"   2. Power features are CONSTANT (not time-varying)")
print(f"      → Representative consumption, not actual measurement")
print(f"   3. Only Host features vary with time")
print(f"      → True temporal dynamics from Host layer only")

print(f"\n📊 What this timeline represents:")
print(f"   - Host: Actual kernel event dynamics during DoS attack")
print(f"   - Network: Typical flood attack characteristics")
print(f"   - Power: Typical DoS power consumption pattern")

print(f"\n✅ Can be used for:")
print(f"   - Feature-based classification")
print(f"   - Pattern recognition (with limitations)")
print(f"   - Preliminary modeling")

print(f"\n❌ Cannot be used for:")
print(f"   - True event reconstruction")
print(f"   - Precise temporal correlation analysis")
print(f"   - Cross-layer propagation lag measurement")

print("\n" + "="*80)
print("✅ TASK R1-1 COMPLETE (FORCED ALIGNMENT)")
print("="*80)
