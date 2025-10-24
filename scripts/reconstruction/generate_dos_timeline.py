#!/usr/bin/env python3
"""
Task R-1: Generate 1-second unified timeline for DoS scenario
CRITICAL VALIDATION: Can we actually reconstruct events at 1-second resolution?
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime

base_dir = Path('/mnt/d/EV_charging_forensics')
stage2_dir = base_dir / 'processed' / 'stage2'
stage3_dir = base_dir / 'processed' / 'stage3'
output_dir = base_dir / 'processed' / 'reconstruction'
output_dir.mkdir(exist_ok=True, parents=True)

print("="*80)
print("TASK R-1: DoS TIMELINE GENERATION (1-SECOND RESOLUTION)")
print("="*80)

# ============================================================================
# STEP 1: Load DoS window metadata
# ============================================================================
print("\n📂 Loading DoS window metadata...")
with open(stage3_dir / 'dos_windows.json', 'r') as f:
    dos_data = json.load(f)

dos_window = dos_data['selected_window']
dos_duration = dos_window['end_time'] - dos_window['start_time']
print(f"✅ DoS window: {dos_window['file']}")
print(f"   Duration: {dos_window['start_time']:.1f} - {dos_window['end_time']:.1f} seconds")
print(f"   Total duration: {dos_duration:.1f} seconds")

# ============================================================================
# STEP 2: Load and resample Network data (1-second resolution)
# ============================================================================
print("\n" + "="*80)
print("STEP 2: NETWORK LAYER - 1-SECOND RESAMPLING")
print("="*80)

net_file = stage2_dir / dos_window['file']
df_network_raw = pd.read_csv(net_file, low_memory=False)

# Filter to DoS window
df_network = df_network_raw[
    (df_network_raw['timestamp_normalized'] >= dos_window['start_time']) &
    (df_network_raw['timestamp_normalized'] < dos_window['end_time'])
].copy()

print(f"\n📊 Network data loaded: {len(df_network):,} packets in {dos_duration:.1f} seconds")

# Create time bins (1-second resolution)
start_second = int(np.floor(dos_window['start_time']))
end_second = int(np.ceil(dos_window['end_time']))
time_bins = np.arange(start_second, end_second + 1, 1)

print(f"   Time bins: {start_second} to {end_second} seconds ({len(time_bins)} bins)")

# Assign each packet to 1-second bin
df_network['time_bin'] = pd.cut(
    df_network['timestamp_normalized'],
    bins=time_bins,
    labels=time_bins[:-1],
    include_lowest=True
)

# Aggregate network features per second
net_features = []
for time_sec in time_bins[:-1]:
    window = df_network[df_network['time_bin'] == time_sec]

    if len(window) > 0:
        # Traffic intensity
        features = {
            'time': int(time_sec),
            'net_packet_count': len(window),
            'net_packet_rate': float(len(window)),  # Already per second
            'net_bytes_total': float(window['bidirectional_bytes'].sum()) if 'bidirectional_bytes' in window.columns else 0.0,
        }

        # Protocol distribution
        if 'protocol' in window.columns:
            protocol_counts = window['protocol'].value_counts()
            total = len(window)
            features['net_tcp_ratio'] = float(protocol_counts.get(6, 0) / total)
            features['net_udp_ratio'] = float(protocol_counts.get(17, 0) / total)
            features['net_icmp_ratio'] = float(protocol_counts.get(1, 0) / total)
        else:
            features['net_tcp_ratio'] = 0.0
            features['net_udp_ratio'] = 0.0
            features['net_icmp_ratio'] = 0.0

        # Port statistics
        if 'dst_port' in window.columns:
            features['net_unique_dst_ports'] = int(window['dst_port'].nunique())
            features['net_port_diversity'] = float(features['net_unique_dst_ports'] / total if total > 0 else 0)
        else:
            features['net_unique_dst_ports'] = 0
            features['net_port_diversity'] = 0.0

        # Connection patterns
        if 'bidirectional_syn_packets' in window.columns:
            features['net_syn_ratio'] = float(window['bidirectional_syn_packets'].sum() / total)
        else:
            features['net_syn_ratio'] = 0.0
    else:
        # No packets in this second
        features = {
            'time': int(time_sec),
            'net_packet_count': 0,
            'net_packet_rate': 0.0,
            'net_bytes_total': 0.0,
            'net_tcp_ratio': 0.0,
            'net_udp_ratio': 0.0,
            'net_icmp_ratio': 0.0,
            'net_unique_dst_ports': 0,
            'net_port_diversity': 0.0,
            'net_syn_ratio': 0.0,
        }

    net_features.append(features)

df_network_1s = pd.DataFrame(net_features)

print(f"\n✅ Network resampled to 1-second:")
print(f"   Rows: {len(df_network_1s)} (expected: {len(time_bins)-1})")
print(f"   Features: {len(df_network_1s.columns) - 1}")  # Exclude 'time'
print(f"   Missing seconds: {(df_network_1s['net_packet_count'] == 0).sum()}")

# ============================================================================
# STEP 3: Load and resample Host data (1-second resolution)
# ============================================================================
print("\n" + "="*80)
print("STEP 3: HOST LAYER - 1-SECOND RESAMPLING")
print("="*80)

df_host_raw = pd.read_csv(stage2_dir / 'host_scaled.csv', low_memory=False)
df_host = df_host_raw[df_host_raw['Scenario'] == 'DoS'].copy()

print(f"\n📊 Host data loaded: {len(df_host):,} records")
print(f"   Time range: {df_host['timestamp_normalized'].min():.1f} - {df_host['timestamp_normalized'].max():.1f} seconds")

# Check overlap with DoS window
overlap = df_host[
    (df_host['timestamp_normalized'] >= start_second) &
    (df_host['timestamp_normalized'] < end_second)
]

print(f"   Records in DoS window: {len(overlap):,}")

if len(overlap) == 0:
    print(f"\n⚠️ WARNING: No Host records overlap with DoS window!")
    print(f"   DoS window: {start_second} - {end_second}")
    print(f"   Host range: {df_host['timestamp_normalized'].min():.1f} - {df_host['timestamp_normalized'].max():.1f}")

    # Try to find closest Host records
    print(f"\n🔍 Attempting to use entire DoS Host segment...")
    df_host_window = df_host.copy()

    # Create new time bins based on Host data range
    host_start = int(np.floor(df_host['timestamp_normalized'].min()))
    host_end = int(np.ceil(df_host['timestamp_normalized'].max()))
    host_time_bins = np.arange(host_start, host_end + 1, 1)

    print(f"   Host time bins: {host_start} - {host_end} ({len(host_time_bins)} bins)")
else:
    df_host_window = overlap.copy()
    host_time_bins = time_bins

# Get key Host features (select numeric kernel event features)
host_feature_cols = [col for col in df_host_window.columns if col not in
                     ['time', 'State', 'Attack', 'Scenario', 'Label', 'interface', 'timestamp_normalized', 'Unnamed: 0']
                     and not col.startswith('net_') and not col.startswith('power_')]

# Select top features by variance (most informative)
numeric_cols = df_host_window[host_feature_cols].select_dtypes(include=[np.number]).columns
if len(numeric_cols) > 20:
    variances = df_host_window[numeric_cols].var()
    top_features = variances.nlargest(20).index.tolist()
    host_feature_cols = top_features

print(f"\n   Selected {len(host_feature_cols)} Host features (top by variance)")

# Assign to time bins
df_host_window['time_bin'] = pd.cut(
    df_host_window['timestamp_normalized'],
    bins=host_time_bins,
    labels=host_time_bins[:-1],
    include_lowest=True
)

# Aggregate per second (mean)
host_features = []
for time_sec in host_time_bins[:-1]:
    window = df_host_window[df_host_window['time_bin'] == time_sec]

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

    host_features.append(features)

df_host_1s = pd.DataFrame(host_features)

print(f"\n✅ Host resampled to 1-second:")
print(f"   Rows: {len(df_host_1s)}")
print(f"   Features: {len(df_host_1s.columns) - 1}")

# ============================================================================
# STEP 4: Load and resample Power data (1-second resolution)
# ============================================================================
print("\n" + "="*80)
print("STEP 4: POWER LAYER - 1-SECOND RESAMPLING")
print("="*80)

df_power_raw = pd.read_csv(stage2_dir / 'power_scaled.csv', low_memory=False)
df_power = df_power_raw[df_power_raw['Attack'].str.contains('flood', case=False, na=False)].copy()

print(f"\n📊 Power data loaded: {len(df_power):,} records")
print(f"   Time range: {df_power['timestamp_normalized'].min():.1f} - {df_power['timestamp_normalized'].max():.1f} seconds")

# Check overlap
overlap = df_power[
    (df_power['timestamp_normalized'] >= start_second) &
    (df_power['timestamp_normalized'] < end_second)
]

print(f"   Records in DoS window: {len(overlap):,}")

if len(overlap) == 0:
    print(f"\n⚠️ WARNING: No Power records overlap with DoS window!")

    # Use entire Power segment
    df_power_window = df_power.copy()
    power_start = int(np.floor(df_power['timestamp_normalized'].min()))
    power_end = int(np.ceil(df_power['timestamp_normalized'].max()))
    power_time_bins = np.arange(power_start, power_end + 1, 1)

    print(f"   Power time bins: {power_start} - {power_end} ({len(power_time_bins)} bins)")
else:
    df_power_window = overlap.copy()
    power_time_bins = time_bins

# Assign to time bins
df_power_window['time_bin'] = pd.cut(
    df_power_window['timestamp_normalized'],
    bins=power_time_bins,
    labels=power_time_bins[:-1],
    include_lowest=True
)

# Aggregate per second (mean)
power_features = []
for time_sec in power_time_bins[:-1]:
    window = df_power_window[df_power_window['time_bin'] == time_sec]

    if len(window) > 0:
        features = {
            'time': int(time_sec),
            'power_voltage_V': float(window['voltage_V'].mean()),
            'power_current_A': float(window['current_A'].mean()),
            'power_mW': float(window['power_mW'].mean()),
            'power_std': float(window['power_mW'].std()) if len(window) > 1 else 0.0
        }
    else:
        features = {
            'time': int(time_sec),
            'power_voltage_V': 0.0,
            'power_current_A': 0.0,
            'power_mW': 0.0,
            'power_std': 0.0
        }

    power_features.append(features)

df_power_1s = pd.DataFrame(power_features)

print(f"\n✅ Power resampled to 1-second:")
print(f"   Rows: {len(df_power_1s)}")
print(f"   Features: {len(df_power_1s.columns) - 1}")

# ============================================================================
# STEP 5: Merge into unified timeline
# ============================================================================
print("\n" + "="*80)
print("STEP 5: CREATE UNIFIED TIMELINE")
print("="*80)

# Merge all three layers on 'time'
print(f"\n🔗 Merging layers on 'time' column...")

# Start with Network (reference timeline)
df_timeline = df_network_1s.copy()
print(f"   Base (Network): {len(df_timeline)} rows")

# Merge Host
df_timeline = df_timeline.merge(df_host_1s, on='time', how='left')
print(f"   After Host merge: {len(df_timeline)} rows")

# Merge Power
df_timeline = df_timeline.merge(df_power_1s, on='time', how='left')
print(f"   After Power merge: {len(df_timeline)} rows")

# ============================================================================
# STEP 6: Validate timeline
# ============================================================================
print("\n" + "="*80)
print("STEP 6: TIMELINE VALIDATION")
print("="*80)

print(f"\n📊 Timeline Shape: {df_timeline.shape[0]} rows × {df_timeline.shape[1]} columns")

# Check time continuity
time_diffs = df_timeline['time'].diff()
gaps = time_diffs[time_diffs > 1]

print(f"\n⏱️ Time Continuity:")
print(f"   Start: {df_timeline['time'].min()} seconds")
print(f"   End: {df_timeline['time'].max()} seconds")
print(f"   Duration: {df_timeline['time'].max() - df_timeline['time'].min() + 1} seconds")
print(f"   Time gaps (>1s): {len(gaps)}")

if len(gaps) > 0:
    print(f"   ⚠️ WARNING: {len(gaps)} time gaps detected!")
    for idx, gap in gaps.items():
        print(f"      Gap at index {idx}: {gap} seconds")

# Check missing data per layer
net_cols = [col for col in df_timeline.columns if col.startswith('net_')]
host_cols = [col for col in df_timeline.columns if col.startswith('host_')]
power_cols = [col for col in df_timeline.columns if col.startswith('power_')]

net_missing = df_timeline[net_cols].isnull().sum().sum()
host_missing = df_timeline[host_cols].isnull().sum().sum()
power_missing = df_timeline[power_cols].isnull().sum().sum()

total_cells = len(df_timeline) * (len(net_cols) + len(host_cols) + len(power_cols))
total_missing = net_missing + host_missing + power_missing

print(f"\n📊 Missing Data Analysis:")
print(f"   Network: {net_missing:,} / {len(df_timeline) * len(net_cols):,} cells ({net_missing / (len(df_timeline) * len(net_cols)) * 100:.2f}%)")
print(f"   Host: {host_missing:,} / {len(df_timeline) * len(host_cols):,} cells ({host_missing / (len(df_timeline) * len(host_cols)) * 100:.2f}%)")
print(f"   Power: {power_missing:,} / {len(df_timeline) * len(power_cols):,} cells ({power_missing / (len(df_timeline) * len(power_cols)) * 100:.2f}%)")
print(f"   Total: {total_missing:,} / {total_cells:,} cells ({total_missing / total_cells * 100:.2f}%)")

# Check data availability per second
net_zero = (df_timeline[net_cols].sum(axis=1) == 0).sum()
host_zero = (df_timeline[host_cols].sum(axis=1) == 0).sum()
power_zero = (df_timeline[power_cols].sum(axis=1) == 0).sum()

print(f"\n📊 Zero-Activity Seconds:")
print(f"   Network: {net_zero} / {len(df_timeline)} ({net_zero / len(df_timeline) * 100:.1f}%)")
print(f"   Host: {host_zero} / {len(df_timeline)} ({host_zero / len(df_timeline) * 100:.1f}%)")
print(f"   Power: {power_zero} / {len(df_timeline)} ({power_zero / len(df_timeline) * 100:.1f}%)")

# Overall verdict
print(f"\n" + "="*80)
print("VERDICT: Event Reconstruction Feasibility")
print("="*80)

issues = []

if len(gaps) > 0:
    issues.append(f"⚠️ {len(gaps)} time gaps detected")

if total_missing > 0:
    issues.append(f"⚠️ {total_missing:,} missing cells ({total_missing / total_cells * 100:.2f}%)")

if net_zero > len(df_timeline) * 0.5:
    issues.append(f"⚠️ Network inactive for {net_zero / len(df_timeline) * 100:.1f}% of time")

if host_zero > len(df_timeline) * 0.5:
    issues.append(f"⚠️ Host inactive for {host_zero / len(df_timeline) * 100:.1f}% of time")

if power_zero > len(df_timeline) * 0.5:
    issues.append(f"⚠️ Power inactive for {power_zero / len(df_timeline) * 100:.1f}% of time")

if len(issues) == 0:
    print(f"\n✅ Event Reconstruction: FEASIBLE")
    print(f"   - Continuous timeline: ✅")
    print(f"   - All layers present: ✅")
    print(f"   - No critical gaps: ✅")
else:
    print(f"\n⚠️ Event Reconstruction: PROBLEMATIC")
    for issue in issues:
        print(f"   {issue}")

# ============================================================================
# STEP 7: Save timeline
# ============================================================================
output_file = output_dir / 'timeline_dos.csv'
df_timeline.to_csv(output_file, index=False)

print(f"\n💾 Timeline saved: {output_file}")
print(f"   Shape: {df_timeline.shape[0]} rows × {df_timeline.shape[1]} columns")

# Save validation report
validation_report = {
    'timeline_shape': {
        'rows': int(len(df_timeline)),
        'columns': int(len(df_timeline.columns))
    },
    'time_range': {
        'start': int(df_timeline['time'].min()),
        'end': int(df_timeline['time'].max()),
        'duration': int(df_timeline['time'].max() - df_timeline['time'].min() + 1)
    },
    'time_gaps': {
        'count': int(len(gaps)),
        'positions': gaps.index.tolist() if len(gaps) > 0 else []
    },
    'missing_data': {
        'network': {
            'cells': int(net_missing),
            'percentage': float(net_missing / (len(df_timeline) * len(net_cols)) * 100) if len(net_cols) > 0 else 0
        },
        'host': {
            'cells': int(host_missing),
            'percentage': float(host_missing / (len(df_timeline) * len(host_cols)) * 100) if len(host_cols) > 0 else 0
        },
        'power': {
            'cells': int(power_missing),
            'percentage': float(power_missing / (len(df_timeline) * len(power_cols)) * 100) if len(power_cols) > 0 else 0
        },
        'total': {
            'cells': int(total_missing),
            'percentage': float(total_missing / total_cells * 100)
        }
    },
    'zero_activity_seconds': {
        'network': int(net_zero),
        'host': int(host_zero),
        'power': int(power_zero)
    },
    'feasibility': {
        'status': 'feasible' if len(issues) == 0 else 'problematic',
        'issues': issues
    },
    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
}

report_file = output_dir / 'timeline_validation.json'
with open(report_file, 'w') as f:
    json.dump(validation_report, f, indent=2)

print(f"\n💾 Validation report: {report_file}")

print("\n" + "="*80)
print("✅ TASK R-1 COMPLETE")
print("="*80)
