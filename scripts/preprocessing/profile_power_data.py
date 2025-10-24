#!/usr/bin/env python3
"""
Phase 1 - Task 1-3: Power Data Profiling
Analyze power consumption data structure and characteristics
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime

base_dir = Path('/mnt/d/EV_charging_forensics')
power_path = base_dir / 'CICEVSE2024_Dataset' / 'Power Consumption' / 'EVSE-B-PowerCombined.csv'
output_dir = base_dir / 'processed' / 'stage1'
output_dir.mkdir(exist_ok=True, parents=True)

print("="*80)
print("PHASE 1 - TASK 1-3: POWER DATA PROFILING")
print("="*80)

# Load power data
print("\n📂 Loading power data...")
df_power = pd.read_csv(power_path, low_memory=False)
print(f"✅ Loaded {len(df_power):,} records")

# Basic statistics
print("\n" + "="*80)
print("BASIC STATISTICS")
print("="*80)

profile = {
    'file_name': 'EVSE-B-PowerCombined.csv',
    'total_records': int(len(df_power)),
    'total_columns': int(len(df_power.columns)),
    'memory_usage_mb': float(df_power.memory_usage(deep=True).sum() / 1024 / 1024)
}

print(f"\n📊 Dataset Overview:")
print(f"   Total Records: {profile['total_records']:,}")
print(f"   Total Columns: {profile['total_columns']}")
print(f"   Memory Usage: {profile['memory_usage_mb']:.2f} MB")

# Column analysis
print(f"\n📋 Column List:")
for i, col in enumerate(df_power.columns, 1):
    print(f"   {i:2d}. {col}")

profile['columns'] = df_power.columns.tolist()

# Identify metadata vs feature columns
metadata_cols = []
feature_cols = []

for col in df_power.columns:
    if col in ['time', 'State', 'Attack', 'Scenario', 'Label', 'Timestamp'] or 'Unnamed' in col:
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

if 'Scenario' in df_power.columns:
    scenario_counts = df_power['Scenario'].value_counts().to_dict()
    profile['scenarios'] = {k: int(v) for k, v in scenario_counts.items()}

    print(f"\n📊 Scenario Distribution:")
    for scenario, count in scenario_counts.items():
        pct = count / len(df_power) * 100
        print(f"   {scenario:20s}: {count:5,} ({pct:5.2f}%)")
else:
    profile['scenarios'] = {}
    print("⚠️ 'Scenario' column not found")

# Time analysis
print("\n" + "="*80)
print("TEMPORAL ANALYSIS")
print("="*80)

time_col = None
if 'time' in df_power.columns:
    time_col = 'time'
elif 'Timestamp' in df_power.columns:
    time_col = 'Timestamp'

if time_col:
    time_sample = df_power[time_col].iloc[0]
    print(f"\n📅 Time Column: {time_col}")
    print(f"   Sample: {time_sample}")
    print(f"   Type: {type(time_sample)}")

    # Try to parse timestamp
    try:
        df_power['timestamp_parsed'] = pd.to_datetime(df_power[time_col], format='%Y-%m-%d %H:%M:%S.%f')

        time_range = {
            'min': str(df_power['timestamp_parsed'].min()),
            'max': str(df_power['timestamp_parsed'].max()),
            'duration_seconds': float((df_power['timestamp_parsed'].max() - df_power['timestamp_parsed'].min()).total_seconds())
        }

        profile['time_range'] = time_range

        print(f"\n⏰ Time Range:")
        print(f"   Start: {time_range['min']}")
        print(f"   End:   {time_range['max']}")
        print(f"   Duration: {time_range['duration_seconds']:.2f} seconds")

        # Sampling rate analysis
        if 'Scenario' in df_power.columns:
            print(f"\n📊 Sampling Rate by Scenario:")
            for scenario in df_power['Scenario'].unique():
                scenario_data = df_power[df_power['Scenario'] == scenario]['timestamp_parsed'].sort_values()
                if len(scenario_data) > 1:
                    time_diffs = scenario_data.diff().dt.total_seconds()
                    median_diff = time_diffs.median()
                    print(f"   {scenario:20s}: ~{median_diff:.3f} seconds")

    except Exception as e:
        print(f"⚠️ Could not parse timestamps: {e}")
        profile['time_range'] = None
else:
    print("⚠️ No time column found")
    profile['time_range'] = None

# Missing value analysis
print("\n" + "="*80)
print("MISSING VALUE ANALYSIS")
print("="*80)

missing_summary = df_power.isnull().sum()
missing_pct = (missing_summary / len(df_power) * 100)

cols_with_missing = missing_pct[missing_pct > 0].sort_values(ascending=False)

if len(cols_with_missing) > 0:
    print(f"\n⚠️ Columns with missing values ({len(cols_with_missing)} total):")
    for col, pct in cols_with_missing.items():
        count = missing_summary[col]
        print(f"   {col:50s}: {count:6,} ({pct:5.2f}%)")
else:
    print("\n✅ No missing values detected")

profile['missing_values'] = {
    'total_cells_missing': int(missing_summary.sum()),
    'pct_cells_missing': float((missing_summary.sum() / (len(df_power) * len(df_power.columns))) * 100),
    'columns_with_missing': int(len(cols_with_missing))
}

# Feature value statistics
print("\n" + "="*80)
print("FEATURE STATISTICS")
print("="*80)

numeric_cols = df_power.select_dtypes(include=[np.number]).columns.tolist()
numeric_features = [col for col in feature_cols if col in numeric_cols]

if len(numeric_features) > 0:
    print(f"\n📊 Statistics for all numeric features:")

    for feat in numeric_features:
        stats = df_power[feat].describe()
        print(f"\n   {feat}:")
        print(f"      Mean: {stats['mean']:.4f}, Std: {stats['std']:.4f}")
        print(f"      Min: {stats['min']:.4f}, Max: {stats['max']:.4f}")
        print(f"      25%: {stats['25%']:.4f}, 50%: {stats['50%']:.4f}, 75%: {stats['75%']:.4f}")
else:
    print("\n⚠️ No numeric features found")

profile['num_numeric_features'] = len(numeric_features)

# Data types
print(f"\n📊 Data Types:")
dtype_counts = df_power.dtypes.value_counts()
for dtype, count in dtype_counts.items():
    print(f"   {dtype}: {count} columns")

profile['data_types'] = {str(k): int(v) for k, v in dtype_counts.items()}

# Save profile
profile['profiling_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

output_file = output_dir / 'power_data_profile.json'
with open(output_file, 'w') as f:
    json.dump(profile, f, indent=2, default=str)

print("\n" + "="*80)
print("✅ TASK 1-3 COMPLETE")
print("="*80)
print(f"\n💾 Profile saved: {output_file}")
print(f"\n📊 Key Findings:")
print(f"   - Total Records: {profile['total_records']:,}")
print(f"   - Feature Columns: {profile['num_features']}")
print(f"   - Numeric Features: {profile['num_numeric_features']}")
print(f"   - Scenarios: {len(profile['scenarios'])}")
print(f"   - Missing Data: {profile['missing_values']['pct_cells_missing']:.2f}%")
