#!/usr/bin/env python3
"""
Phase 2 - Task 2-1: Data Type Conversion
Convert all data sources to consistent, appropriate types
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime

base_dir = Path('/mnt/d/EV_charging_forensics')
output_dir = base_dir / 'processed' / 'stage2'
output_dir.mkdir(exist_ok=True, parents=True)

print("="*80)
print("PHASE 2 - TASK 2-1: DATA TYPE CONVERSION")
print("="*80)

conversion_report = {
    'host': {},
    'network': {},
    'power': {},
    'conversion_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
}

# ============================================================================
# HOST DATA CONVERSION
# ============================================================================
print("\n" + "="*80)
print("HOST DATA TYPE CONVERSION")
print("="*80)

print("\n📂 Loading Host data...")
host_path = base_dir / 'CICEVSE2024_Dataset' / 'Host Events' / 'EVSE-B-HPC-Kernel-Events-Combined.csv'
df_host = pd.read_csv(host_path, low_memory=False)
print(f"✅ Loaded {len(df_host):,} records")

# Store original dtypes
original_dtypes = df_host.dtypes.value_counts().to_dict()
print(f"\n📊 Original Data Types:")
for dtype, count in original_dtypes.items():
    print(f"   {dtype}: {count} columns")

# Convert 'time' to float
print("\n🔄 Converting 'time' column to float...")
if 'time' in df_host.columns:
    df_host['time'] = pd.to_numeric(df_host['time'], errors='coerce')
    print(f"   ✅ Converted to float64")

# Convert numeric-looking string columns to numeric
print("\n🔄 Converting kernel event columns to numeric...")
conversion_count = 0
for col in df_host.columns:
    if col not in ['time', 'State', 'Attack', 'Scenario', 'Label', 'interface'] and 'Unnamed' not in col:
        if df_host[col].dtype == 'object':
            # Try to convert to numeric
            df_host[col] = pd.to_numeric(df_host[col], errors='coerce')
            conversion_count += 1

print(f"   ✅ Converted {conversion_count} columns")

# Fill NaN in numeric columns with 0 (kernel event counts)
numeric_cols = df_host.select_dtypes(include=[np.number]).columns
df_host[numeric_cols] = df_host[numeric_cols].fillna(0)

# New dtypes
new_dtypes = df_host.dtypes.value_counts().to_dict()
print(f"\n📊 New Data Types:")
for dtype, count in new_dtypes.items():
    print(f"   {dtype}: {count} columns")

conversion_report['host'] = {
    'total_records': int(len(df_host)),
    'total_columns': int(len(df_host.columns)),
    'original_dtypes': {str(k): int(v) for k, v in original_dtypes.items()},
    'new_dtypes': {str(k): int(v) for k, v in new_dtypes.items()},
    'conversions_made': conversion_count
}

# Save converted Host data
host_output = output_dir / 'host_converted.csv'
df_host.to_csv(host_output, index=False)
print(f"\n💾 Saved: {host_output}")

# ============================================================================
# NETWORK DATA CONVERSION
# ============================================================================
print("\n" + "="*80)
print("NETWORK DATA TYPE CONVERSION")
print("="*80)

network_dir = base_dir / 'CICEVSE2024_Dataset' / 'Network Traffic' / 'EVSE-B' / 'csv'
network_files = sorted(network_dir.glob('*.csv'))

print(f"\n📂 Processing {len(network_files)} network files...")

network_conversion_stats = []
for i, csv_path in enumerate(network_files, 1):
    print(f"\n📄 File {i}/{len(network_files)}: {csv_path.name}")

    df_net = pd.read_csv(csv_path, low_memory=False)

    # Store original dtype counts
    orig_dtypes = df_net.dtypes.value_counts().to_dict()

    # Ensure numeric columns are proper types
    conversion_count = 0
    for col in df_net.columns:
        if col not in ['id', 'expiration_id', 'src_ip', 'src_mac', 'src_oui',
                       'dst_ip', 'dst_mac', 'dst_oui', 'requested_server_name',
                       'user_agent', 'content_type', 'client_fingerprint',
                       'server_fingerprint'] and 'Unnamed' not in col:
            if df_net[col].dtype == 'object':
                df_net[col] = pd.to_numeric(df_net[col], errors='coerce')
                conversion_count += 1

    # New dtypes
    new_dtypes = df_net.dtypes.value_counts().to_dict()

    print(f"   Original: {orig_dtypes}")
    print(f"   New: {new_dtypes}")
    print(f"   Conversions: {conversion_count} columns")

    # Save converted file
    output_path = output_dir / csv_path.name
    df_net.to_csv(output_path, index=False)

    network_conversion_stats.append({
        'filename': csv_path.name,
        'records': int(len(df_net)),
        'original_dtypes': {str(k): int(v) for k, v in orig_dtypes.items()},
        'new_dtypes': {str(k): int(v) for k, v in new_dtypes.items()},
        'conversions_made': conversion_count
    })

print(f"\n✅ Converted and saved {len(network_files)} files")

conversion_report['network'] = {
    'total_files': len(network_files),
    'files': network_conversion_stats
}

# ============================================================================
# POWER DATA CONVERSION
# ============================================================================
print("\n" + "="*80)
print("POWER DATA TYPE CONVERSION")
print("="*80)

print("\n📂 Loading Power data...")
power_path = base_dir / 'CICEVSE2024_Dataset' / 'Power Consumption' / 'EVSE-B-PowerCombined.csv'
df_power = pd.read_csv(power_path, low_memory=False)
print(f"✅ Loaded {len(df_power):,} records")

# Store original dtypes
original_dtypes_power = df_power.dtypes.value_counts().to_dict()
print(f"\n📊 Original Data Types:")
for dtype, count in original_dtypes_power.items():
    print(f"   {dtype}: {count} columns")

# Ensure numeric columns are proper types
print("\n🔄 Converting numeric columns...")
numeric_power_cols = ['shunt_voltage', 'bus_voltage_V', 'current_mA', 'power_mW']
for col in numeric_power_cols:
    if col in df_power.columns:
        df_power[col] = pd.to_numeric(df_power[col], errors='coerce')

# New dtypes
new_dtypes_power = df_power.dtypes.value_counts().to_dict()
print(f"\n📊 New Data Types:")
for dtype, count in new_dtypes_power.items():
    print(f"   {dtype}: {count} columns")

conversion_report['power'] = {
    'total_records': int(len(df_power)),
    'total_columns': int(len(df_power.columns)),
    'original_dtypes': {str(k): int(v) for k, v in original_dtypes_power.items()},
    'new_dtypes': {str(k): int(v) for k, v in new_dtypes_power.items()}
}

# Save converted Power data
power_output = output_dir / 'power_converted.csv'
df_power.to_csv(power_output, index=False)
print(f"\n💾 Saved: {power_output}")

# ============================================================================
# SAVE CONVERSION REPORT
# ============================================================================
report_file = output_dir / 'conversion_report.json'
with open(report_file, 'w') as f:
    json.dump(conversion_report, f, indent=2, default=str)

print("\n" + "="*80)
print("✅ TASK 2-1 COMPLETE")
print("="*80)
print(f"\n💾 Conversion report saved: {report_file}")
print(f"\n📊 Summary:")
print(f"   - Host: {conversion_report['host']['conversions_made']} columns converted")
print(f"   - Network: {len(network_files)} files processed")
print(f"   - Power: All numeric columns ensured proper types")
print(f"\nℹ️  All converted data saved to: {output_dir}")
