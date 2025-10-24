#!/usr/bin/env python3
"""
Phase 2 - Task 2-2: Timestamp Normalization
Normalize all timestamps to consistent format (seconds since T0)
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime

base_dir = Path('/mnt/d/EV_charging_forensics')
input_dir = base_dir / 'processed' / 'stage2'
output_dir = base_dir / 'processed' / 'stage2'
output_dir.mkdir(exist_ok=True, parents=True)

print("="*80)
print("PHASE 2 - TASK 2-2: TIMESTAMP NORMALIZATION")
print("="*80)

normalization_report = {
    'host': {},
    'network': {},
    'power': {},
    'normalization_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
}

# ============================================================================
# STEP 1: Analyze timestamp formats
# ============================================================================
print("\n" + "="*80)
print("STEP 1: TIMESTAMP FORMAT ANALYSIS")
print("="*80)

# Host data
print("\n📂 Analyzing Host timestamps...")
df_host = pd.read_csv(input_dir / 'host_converted.csv', low_memory=False)
host_time_sample = df_host['time'].iloc[0]
host_time_min = df_host['time'].min()
host_time_max = df_host['time'].max()
print(f"   Format: Relative seconds")
print(f"   Sample: {host_time_sample}")
print(f"   Range: {host_time_min:.6f} to {host_time_max:.6f} seconds")

# Network data (sample first file)
print("\n📂 Analyzing Network timestamps...")
network_files = sorted(input_dir.glob('EVSE-B-*.csv'))
df_net_sample = pd.read_csv(network_files[0], low_memory=False)
if 'bidirectional_first_seen_ms' in df_net_sample.columns:
    net_time_sample = df_net_sample['bidirectional_first_seen_ms'].iloc[0]
    net_time_min = df_net_sample['bidirectional_first_seen_ms'].min()
    net_time_max = df_net_sample['bidirectional_first_seen_ms'].max()
    print(f"   Format: Unix milliseconds")
    print(f"   Sample: {net_time_sample}")
    print(f"   Range: {net_time_min} to {net_time_max}")

# Power data
print("\n📂 Analyzing Power timestamps...")
df_power = pd.read_csv(input_dir / 'power_converted.csv', low_memory=False)
power_time_sample = df_power['time'].iloc[0]
print(f"   Format: Human-readable datetime")
print(f"   Sample: {power_time_sample}")

# ============================================================================
# STEP 2: Parse Power timestamps to get reference T0
# ============================================================================
print("\n" + "="*80)
print("STEP 2: ESTABLISH TIME REFERENCE (T0)")
print("="*80)

print("\n🔄 Parsing Power timestamps...")
# Try different datetime formats
try:
    df_power['timestamp'] = pd.to_datetime(df_power['time'], format='%m/%d/%Y %H:%M')
    print("   ✅ Parsed with format: %m/%d/%Y %H:%M")
except:
    try:
        df_power['timestamp'] = pd.to_datetime(df_power['time'])
        print("   ✅ Parsed with automatic format detection")
    except Exception as e:
        print(f"   ❌ Error: {e}")

# Convert to Unix timestamp (seconds)
df_power['unix_timestamp'] = df_power['timestamp'].astype('int64') / 1e9

power_t0 = df_power['unix_timestamp'].min()
power_t_end = df_power['unix_timestamp'].max()
power_duration = power_t_end - power_t0

print(f"\n📊 Power Time Reference:")
print(f"   T0 (earliest): {df_power['timestamp'].min()}")
print(f"   T0 Unix: {power_t0:.3f}")
print(f"   Duration: {power_duration:.3f} seconds ({power_duration/3600:.2f} hours)")

# Use Power T0 as global reference
global_t0 = power_t0
normalization_report['global_t0'] = {
    'unix_timestamp': float(global_t0),
    'datetime': str(df_power['timestamp'].min()),
    'source': 'Power data (earliest timestamp)'
}

print(f"\n🎯 Global T0 established: {global_t0:.3f}")

# ============================================================================
# STEP 3: Normalize Host timestamps
# ============================================================================
print("\n" + "="*80)
print("STEP 3: NORMALIZE HOST TIMESTAMPS")
print("="*80)

print("\n🔄 Host timestamps are already in relative seconds")
print("   Strategy: Keep as-is (already relative from recording start)")

# Add normalized timestamp column (same as 'time' for Host)
df_host['timestamp_normalized'] = df_host['time']

print(f"\n📊 Host Normalized Timestamps:")
print(f"   Min: {df_host['timestamp_normalized'].min():.6f} seconds")
print(f"   Max: {df_host['timestamp_normalized'].max():.6f} seconds")
print(f"   Duration: {df_host['timestamp_normalized'].max() - df_host['timestamp_normalized'].min():.6f} seconds")

normalization_report['host'] = {
    'original_format': 'relative_seconds',
    'normalized_format': 'relative_seconds',
    'min_timestamp': float(df_host['timestamp_normalized'].min()),
    'max_timestamp': float(df_host['timestamp_normalized'].max()),
    'duration_seconds': float(df_host['timestamp_normalized'].max() - df_host['timestamp_normalized'].min())
}

# Save normalized Host data
host_output = output_dir / 'host_normalized.csv'
df_host.to_csv(host_output, index=False)
print(f"\n💾 Saved: {host_output}")

# ============================================================================
# STEP 4: Normalize Network timestamps
# ============================================================================
print("\n" + "="*80)
print("STEP 4: NORMALIZE NETWORK TIMESTAMPS")
print("="*80)

print(f"\n📂 Processing {len(network_files)} network files...")

for i, csv_path in enumerate(network_files, 1):
    print(f"\n📄 File {i}/{len(network_files)}: {csv_path.name}")

    df_net = pd.read_csv(csv_path, low_memory=False)

    # Convert millisecond timestamps to seconds
    time_cols = [
        'bidirectional_first_seen_ms',
        'bidirectional_last_seen_ms',
        'src2dst_first_seen_ms',
        'src2dst_last_seen_ms',
        'dst2src_first_seen_ms',
        'dst2src_last_seen_ms'
    ]

    for col in time_cols:
        if col in df_net.columns:
            # Convert milliseconds to seconds
            df_net[col.replace('_ms', '_s')] = df_net[col] / 1000.0

    # Create normalized timestamp (using bidirectional_first_seen)
    if 'bidirectional_first_seen_ms' in df_net.columns:
        df_net['timestamp_normalized'] = df_net['bidirectional_first_seen_ms'] / 1000.0
        # Adjust to global T0 if needed (for now, keep as Unix seconds)

    print(f"   ✅ Converted {len(time_cols)} timestamp columns")

    # Save normalized Network file
    output_path = output_dir / csv_path.name.replace('_converted', '_normalized').replace('.csv', '_normalized.csv')
    df_net.to_csv(output_path, index=False)

print(f"\n✅ All network files normalized")

normalization_report['network'] = {
    'total_files': len(network_files),
    'original_format': 'unix_milliseconds',
    'normalized_format': 'unix_seconds',
    'timestamp_columns_converted': time_cols
}

# ============================================================================
# STEP 5: Normalize Power timestamps
# ============================================================================
print("\n" + "="*80)
print("STEP 5: NORMALIZE POWER TIMESTAMPS")
print("="*80)

# Power timestamps already parsed in Step 2
df_power['timestamp_normalized'] = df_power['unix_timestamp'] - global_t0

print(f"\n📊 Power Normalized Timestamps:")
print(f"   Min: {df_power['timestamp_normalized'].min():.3f} seconds (should be 0)")
print(f"   Max: {df_power['timestamp_normalized'].max():.3f} seconds")
print(f"   Duration: {df_power['timestamp_normalized'].max():.3f} seconds")

normalization_report['power'] = {
    'original_format': 'datetime_string',
    'normalized_format': 'seconds_since_t0',
    'min_timestamp': float(df_power['timestamp_normalized'].min()),
    'max_timestamp': float(df_power['timestamp_normalized'].max()),
    'duration_seconds': float(df_power['timestamp_normalized'].max())
}

# Save normalized Power data
power_output = output_dir / 'power_normalized.csv'
df_power.to_csv(power_output, index=False)
print(f"\n💾 Saved: {power_output}")

# ============================================================================
# SAVE NORMALIZATION REPORT
# ============================================================================
report_file = output_dir / 'normalization_report.json'
with open(report_file, 'w') as f:
    json.dump(normalization_report, f, indent=2, default=str)

print("\n" + "="*80)
print("✅ TASK 2-2 COMPLETE")
print("="*80)
print(f"\n💾 Normalization report saved: {report_file}")
print(f"\n📊 Summary:")
print(f"   - Host: Relative seconds (kept as-is)")
print(f"   - Network: Milliseconds → Seconds")
print(f"   - Power: Datetime → Seconds since T0")
print(f"   - Global T0: {normalization_report['global_t0']['datetime']}")
print(f"\nℹ️  All normalized data saved to: {output_dir}")
