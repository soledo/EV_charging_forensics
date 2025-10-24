#!/usr/bin/env python3
"""
Phase 2 - Task 2-3: Missing Value Handling
Handle missing values across all data sources
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
print("PHASE 2 - TASK 2-3: MISSING VALUE HANDLING")
print("="*80)

missing_report = {
    'host': {},
    'network': {},
    'power': {},
    'handling_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
}

# ============================================================================
# HOST DATA MISSING VALUE HANDLING
# ============================================================================
print("\n" + "="*80)
print("HOST DATA MISSING VALUE HANDLING")
print("="*80)

print("\n📂 Loading Host data...")
df_host = pd.read_csv(input_dir / 'host_normalized.csv', low_memory=False)
print(f"✅ Loaded {len(df_host):,} records, {len(df_host.columns)} columns")

# Check missing values
missing_before = df_host.isnull().sum().sum()
missing_pct_before = (missing_before / (len(df_host) * len(df_host.columns))) * 100

print(f"\n📊 Missing Values Before:")
print(f"   Total missing cells: {missing_before:,} ({missing_pct_before:.2f}%)")

# Identify Unnamed columns
unnamed_cols = [col for col in df_host.columns if 'Unnamed' in col]
print(f"\n🗑️  Dropping {len(unnamed_cols)} Unnamed columns...")
df_host = df_host.drop(columns=unnamed_cols)

# Check remaining missing values
missing_summary = df_host.isnull().sum()
cols_with_missing = missing_summary[missing_summary > 0]

if len(cols_with_missing) > 0:
    print(f"\n📋 Columns with missing values ({len(cols_with_missing)} total):")
    for col in cols_with_missing.head(10).index:
        count = missing_summary[col]
        pct = (count / len(df_host)) * 100
        print(f"   {col:50s}: {count:6,} ({pct:5.2f}%)")

    # Fill numeric columns with 0 (kernel event counts)
    print(f"\n🔄 Filling missing values in numeric columns with 0...")
    numeric_cols = df_host.select_dtypes(include=[np.number]).columns
    df_host[numeric_cols] = df_host[numeric_cols].fillna(0)

# Check after
missing_after = df_host.isnull().sum().sum()
missing_pct_after = (missing_after / (len(df_host) * len(df_host.columns))) * 100

print(f"\n📊 Missing Values After:")
print(f"   Total missing cells: {missing_after:,} ({missing_pct_after:.2f}%)")

missing_report['host'] = {
    'columns_before': int(len(df_host.columns) + len(unnamed_cols)),
    'columns_after': int(len(df_host.columns)),
    'unnamed_columns_dropped': len(unnamed_cols),
    'missing_cells_before': int(missing_before),
    'missing_cells_after': int(missing_after),
    'missing_pct_before': float(missing_pct_before),
    'missing_pct_after': float(missing_pct_after),
    'strategy': 'Drop Unnamed columns, fill numeric with 0'
}

# Save cleaned Host data
host_output = output_dir / 'host_cleaned.csv'
df_host.to_csv(host_output, index=False)
print(f"\n💾 Saved: {host_output}")

# ============================================================================
# NETWORK DATA MISSING VALUE HANDLING
# ============================================================================
print("\n" + "="*80)
print("NETWORK DATA MISSING VALUE HANDLING")
print("="*80)

network_files = sorted(input_dir.glob('EVSE-B-*_normalized.csv'))
# Filter out double-normalized files
network_files = [f for f in network_files if '_normalized_normalized' not in f.name]

print(f"\n📂 Processing {len(network_files)} network files...")

network_missing_stats = []

for i, csv_path in enumerate(network_files, 1):
    if i <= 5 or i % 10 == 0:  # Print first 5 and every 10th
        print(f"\n📄 File {i}/{len(network_files)}: {csv_path.name}")

    df_net = pd.read_csv(csv_path, low_memory=False)

    # Check missing values
    missing_before = df_net.isnull().sum().sum()
    missing_summary = df_net.isnull().sum()
    cols_with_missing = missing_summary[missing_summary > 0]

    if i <= 5:
        if len(cols_with_missing) > 0:
            print(f"   Columns with missing: {len(cols_with_missing)}")
            for col in cols_with_missing.index:
                count = missing_summary[col]
                pct = (count / len(df_net)) * 100
                print(f"      {col}: {count} ({pct:.1f}%)")

    # Strategy: Fill HTTP-related columns with empty string, numeric with 0
    http_cols = ['requested_server_name', 'user_agent', 'content_type',
                  'client_fingerprint', 'server_fingerprint']

    for col in http_cols:
        if col in df_net.columns:
            if df_net[col].dtype == 'object':
                df_net[col] = df_net[col].fillna('')
            else:
                df_net[col] = df_net[col].fillna(0)

    # Fill remaining numeric columns with 0
    numeric_cols = df_net.select_dtypes(include=[np.number]).columns
    df_net[numeric_cols] = df_net[numeric_cols].fillna(0)

    # Check after
    missing_after = df_net.isnull().sum().sum()

    network_missing_stats.append({
        'filename': csv_path.name,
        'records': int(len(df_net)),
        'missing_before': int(missing_before),
        'missing_after': int(missing_after)
    })

    # Save cleaned file
    output_path = output_dir / csv_path.name.replace('_normalized', '_cleaned')
    df_net.to_csv(output_path, index=False)

print(f"\n✅ Processed all network files")

total_missing_before = sum(s['missing_before'] for s in network_missing_stats)
total_missing_after = sum(s['missing_after'] for s in network_missing_stats)

print(f"\n📊 Network Missing Values Summary:")
print(f"   Total missing before: {total_missing_before:,}")
print(f"   Total missing after: {total_missing_after:,}")

missing_report['network'] = {
    'total_files': len(network_files),
    'files': network_missing_stats,
    'total_missing_before': int(total_missing_before),
    'total_missing_after': int(total_missing_after),
    'strategy': 'Fill HTTP columns with empty string, numeric with 0'
}

# ============================================================================
# POWER DATA MISSING VALUE HANDLING
# ============================================================================
print("\n" + "="*80)
print("POWER DATA MISSING VALUE HANDLING")
print("="*80)

print("\n📂 Loading Power data...")
df_power = pd.read_csv(input_dir / 'power_normalized.csv', low_memory=False)
print(f"✅ Loaded {len(df_power):,} records, {len(df_power.columns)} columns")

# Check missing values
missing_before_power = df_power.isnull().sum().sum()
print(f"\n📊 Missing Values: {missing_before_power:,}")

if missing_before_power == 0:
    print("   ✅ No missing values detected - no action needed")
else:
    # Fill numeric columns if any missing
    numeric_cols = df_power.select_dtypes(include=[np.number]).columns
    df_power[numeric_cols] = df_power[numeric_cols].fillna(0)

    missing_after_power = df_power.isnull().sum().sum()
    print(f"   Filled missing values: {missing_after_power:,} remaining")

missing_report['power'] = {
    'total_records': int(len(df_power)),
    'total_columns': int(len(df_power.columns)),
    'missing_before': int(missing_before_power),
    'missing_after': int(df_power.isnull().sum().sum()),
    'strategy': 'No action needed (no missing values)'
}

# Save Power data
power_output = output_dir / 'power_cleaned.csv'
df_power.to_csv(power_output, index=False)
print(f"\n💾 Saved: {power_output}")

# ============================================================================
# SAVE MISSING VALUE REPORT
# ============================================================================
report_file = output_dir / 'missing_values_report.json'
with open(report_file, 'w') as f:
    json.dump(missing_report, f, indent=2, default=str)

print("\n" + "="*80)
print("✅ TASK 2-3 COMPLETE")
print("="*80)
print(f"\n💾 Missing value report saved: {report_file}")
print(f"\n📊 Summary:")
print(f"   - Host: Dropped {missing_report['host']['unnamed_columns_dropped']} Unnamed columns")
print(f"   - Host: {missing_report['host']['missing_pct_before']:.2f}% → {missing_report['host']['missing_pct_after']:.2f}% missing")
print(f"   - Network: {total_missing_before:,} → {total_missing_after:,} missing cells")
print(f"   - Power: {missing_before_power:,} missing (perfect data)")
print(f"\nℹ️  All cleaned data saved to: {output_dir}")
