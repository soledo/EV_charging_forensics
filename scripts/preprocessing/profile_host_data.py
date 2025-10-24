#!/usr/bin/env python3
"""
Phase 1 - Task 1-1: Host Data Profiling
Analyze host event data structure and characteristics
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime

base_dir = Path('/mnt/d/EV_charging_forensics')
host_path = base_dir / 'CICEVSE2024_Dataset' / 'Host Events' / 'EVSE-B-HPC-Kernel-Events-Combined.csv'
output_dir = base_dir / 'processed' / 'stage1'
output_dir.mkdir(exist_ok=True, parents=True)

print("="*80)
print("PHASE 1 - TASK 1-1: HOST DATA PROFILING")
print("="*80)

# Load host data
print("\n📂 Loading host data...")
df_host = pd.read_csv(host_path, low_memory=False)
print(f"✅ Loaded {len(df_host):,} records")

# Basic statistics
print("\n" + "="*80)
print("BASIC STATISTICS")
print("="*80)

profile = {
    'file_name': 'EVSE-B-HPC-Kernel-Events-Combined.csv',
    'total_records': int(len(df_host)),
    'total_columns': int(len(df_host.columns)),
    'memory_usage_mb': float(df_host.memory_usage(deep=True).sum() / 1024 / 1024)
}

print(f"\n📊 Dataset Overview:")
print(f"   Total Records: {profile['total_records']:,}")
print(f"   Total Columns: {profile['total_columns']}")
print(f"   Memory Usage: {profile['memory_usage_mb']:.2f} MB")

# Column analysis
print(f"\n📋 Column List (first 20):")
for i, col in enumerate(df_host.columns[:20], 1):
    print(f"   {i:2d}. {col}")
if len(df_host.columns) > 20:
    print(f"   ... and {len(df_host.columns) - 20} more columns")

profile['columns'] = df_host.columns.tolist()

# Identify metadata vs feature columns
metadata_cols = []
feature_cols = []

for col in df_host.columns:
    if col in ['time', 'State', 'Attack', 'Scenario', 'Label', 'interface'] or 'Unnamed' in col:
        metadata_cols.append(col)
    else:
        feature_cols.append(col)

profile['metadata_columns'] = metadata_cols
profile['feature_columns'] = feature_cols
profile['num_metadata'] = len(metadata_cols)
profile['num_features'] = len(feature_cols)

print(f"\n📊 Column Categories:")
print(f"   Metadata columns: {len(metadata_cols)}")
print(f"   Feature columns: {len(feature_cols)}")

# Scenario analysis
print("\n" + "="*80)
print("SCENARIO ANALYSIS")
print("="*80)

if 'Scenario' in df_host.columns:
    scenario_counts = df_host['Scenario'].value_counts().to_dict()
    profile['scenarios'] = {k: int(v) for k, v in scenario_counts.items()}

    print(f"\n📊 Scenario Distribution:")
    for scenario, count in scenario_counts.items():
        pct = count / len(df_host) * 100
        print(f"   {scenario:20s}: {count:5,} ({pct:5.2f}%)")
else:
    profile['scenarios'] = {}
    print("⚠️ 'Scenario' column not found")

# Time analysis
print("\n" + "="*80)
print("TEMPORAL ANALYSIS")
print("="*80)

if 'time' in df_host.columns:
    # Check time format
    time_sample = df_host['time'].iloc[0]
    print(f"\n📅 Time Format:")
    print(f"   Sample: {time_sample}")
    print(f"   Type: {type(time_sample)}")

    # Try to parse timestamp
    try:
        # Assume format from sample data
        df_host['timestamp_parsed'] = pd.to_datetime(df_host['time'], format='%Y-%m-%d %H:%M:%S')

        time_range = {
            'min': str(df_host['timestamp_parsed'].min()),
            'max': str(df_host['timestamp_parsed'].max()),
            'duration_hours': float((df_host['timestamp_parsed'].max() - df_host['timestamp_parsed'].min()).total_seconds() / 3600)
        }

        profile['time_range'] = time_range

        print(f"\n⏰ Time Range:")
        print(f"   Start: {time_range['min']}")
        print(f"   End:   {time_range['max']}")
        print(f"   Duration: {time_range['duration_hours']:.2f} hours")

        # Sampling rate analysis
        if 'Scenario' in df_host.columns:
            print(f"\n📊 Sampling Rate by Scenario:")
            for scenario in df_host['Scenario'].unique():
                scenario_data = df_host[df_host['Scenario'] == scenario]['timestamp_parsed'].sort_values()
                if len(scenario_data) > 1:
                    time_diffs = scenario_data.diff().dt.total_seconds()
                    median_diff = time_diffs.median()
                    print(f"   {scenario:20s}: ~{median_diff:.1f} seconds")

    except Exception as e:
        print(f"⚠️ Could not parse timestamps: {e}")
        profile['time_range'] = None
else:
    print("⚠️ 'time' column not found")
    profile['time_range'] = None

# Missing value analysis
print("\n" + "="*80)
print("MISSING VALUE ANALYSIS")
print("="*80)

missing_summary = df_host.isnull().sum()
missing_pct = (missing_summary / len(df_host) * 100)

# Only show columns with missing values
cols_with_missing = missing_pct[missing_pct > 0].sort_values(ascending=False)

if len(cols_with_missing) > 0:
    print(f"\n⚠️ Columns with missing values ({len(cols_with_missing)} total):")
    for col, pct in cols_with_missing.head(10).items():
        count = missing_summary[col]
        print(f"   {col:50s}: {count:6,} ({pct:5.2f}%)")

    if len(cols_with_missing) > 10:
        print(f"   ... and {len(cols_with_missing) - 10} more columns with missing values")
else:
    print("\n✅ No missing values detected")

profile['missing_values'] = {
    'total_cells_missing': int(missing_summary.sum()),
    'pct_cells_missing': float((missing_summary.sum() / (len(df_host) * len(df_host.columns))) * 100),
    'columns_with_missing': int(len(cols_with_missing))
}

# Feature value statistics (sample)
print("\n" + "="*80)
print("FEATURE STATISTICS (Sample)")
print("="*80)

# Get numeric features only
numeric_cols = df_host.select_dtypes(include=[np.number]).columns.tolist()
numeric_features = [col for col in feature_cols if col in numeric_cols]

sample_features = numeric_features[:5]
print(f"\n📊 Statistics for first 5 numeric features:")

for feat in sample_features:
    if feat in df_host.columns:
        stats = df_host[feat].describe()
        print(f"\n   {feat}:")
        print(f"      Mean: {stats['mean']:.2f}, Std: {stats['std']:.2f}")
        print(f"      Min: {stats['min']:.2f}, Max: {stats['max']:.2f}")

print(f"\nℹ️  Total numeric features: {len(numeric_features)}/{len(feature_cols)}")

# Save profile
profile['profiling_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

output_file = output_dir / 'host_data_profile.json'
with open(output_file, 'w') as f:
    json.dump(profile, f, indent=2, default=str)

print("\n" + "="*80)
print("✅ TASK 1-1 COMPLETE")
print("="*80)
print(f"\n💾 Profile saved: {output_file}")
print(f"\n📊 Key Findings:")
print(f"   - Total Records: {profile['total_records']:,}")
print(f"   - Feature Columns: {profile['num_features']}")
print(f"   - Scenarios: {len(profile['scenarios'])}")
print(f"   - Missing Data: {profile['missing_values']['pct_cells_missing']:.2f}%")
