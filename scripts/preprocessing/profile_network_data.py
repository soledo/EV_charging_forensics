#!/usr/bin/env python3
"""
Phase 1 - Task 1-2: Network Data Profiling
Analyze network traffic data structure and characteristics
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime

base_dir = Path('/mnt/d/EV_charging_forensics')
network_dir = base_dir / 'CICEVSE2024_Dataset' / 'Network Traffic' / 'EVSE-B' / 'csv'
output_dir = base_dir / 'processed' / 'stage1'
output_dir.mkdir(exist_ok=True, parents=True)

print("="*80)
print("PHASE 1 - TASK 1-2: NETWORK DATA PROFILING")
print("="*80)

# Get all CSV files
print("\n📂 Discovering network CSV files...")
csv_files = sorted(network_dir.glob('*.csv'))
print(f"✅ Found {len(csv_files)} CSV files")

profile = {
    'total_files': len(csv_files),
    'files': [],
    'combined_stats': {}
}

# Analyze each file
print("\n" + "="*80)
print("FILE-BY-FILE ANALYSIS")
print("="*80)

all_dfs = []
for i, csv_path in enumerate(csv_files[:10], 1):  # Sample first 10 files
    print(f"\n📄 File {i}/10: {csv_path.name}")

    try:
        df = pd.read_csv(csv_path, low_memory=False)
        all_dfs.append(df)

        file_info = {
            'filename': csv_path.name,
            'records': int(len(df)),
            'columns': int(len(df.columns)),
            'memory_mb': float(df.memory_usage(deep=True).sum() / 1024 / 1024)
        }

        print(f"   Records: {file_info['records']:,}")
        print(f"   Columns: {file_info['columns']}")
        print(f"   Memory: {file_info['memory_mb']:.2f} MB")

        # Check for Scenario column
        if 'Scenario' in df.columns:
            scenarios = df['Scenario'].value_counts().to_dict()
            file_info['scenarios'] = {k: int(v) for k, v in scenarios.items()}
            print(f"   Scenarios: {list(scenarios.keys())}")

        profile['files'].append(file_info)

    except Exception as e:
        print(f"   ❌ Error: {e}")

if len(csv_files) > 10:
    print(f"\n... and {len(csv_files) - 10} more files")

# Combined analysis (using first file as reference)
print("\n" + "="*80)
print("COMBINED STATISTICS")
print("="*80)

if len(all_dfs) > 0:
    df_sample = all_dfs[0]

    print(f"\n📊 Column Structure (from {csv_files[0].name}):")
    print(f"   Total Columns: {len(df_sample.columns)}")

    # Column categories
    metadata_cols = []
    feature_cols = []

    for col in df_sample.columns:
        if col in ['flow_id', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
                   'timestamp', 'Scenario', 'Label', 'Attack'] or 'Unnamed' in col:
            metadata_cols.append(col)
        else:
            feature_cols.append(col)

    profile['combined_stats'] = {
        'sample_file': csv_files[0].name,
        'total_columns': int(len(df_sample.columns)),
        'metadata_columns': metadata_cols,
        'feature_columns': feature_cols,
        'num_metadata': len(metadata_cols),
        'num_features': len(feature_cols)
    }

    print(f"\n📋 Column Categories:")
    print(f"   Metadata columns: {len(metadata_cols)}")
    print(f"   Feature columns: {len(feature_cols)}")

    # Show column list
    print(f"\n📋 Column List (first 20):")
    for i, col in enumerate(df_sample.columns[:20], 1):
        print(f"   {i:2d}. {col}")
    if len(df_sample.columns) > 20:
        print(f"   ... and {len(df_sample.columns) - 20} more columns")

    # Data types
    print(f"\n📊 Data Types:")
    dtype_counts = df_sample.dtypes.value_counts()
    for dtype, count in dtype_counts.items():
        print(f"   {dtype}: {count} columns")

    # Missing values
    missing_summary = df_sample.isnull().sum()
    missing_pct = (missing_summary / len(df_sample) * 100)
    cols_with_missing = missing_pct[missing_pct > 0].sort_values(ascending=False)

    if len(cols_with_missing) > 0:
        print(f"\n⚠️ Columns with missing values ({len(cols_with_missing)} total):")
        for col, pct in cols_with_missing.head(10).items():
            count = missing_summary[col]
            print(f"   {col:50s}: {count:6,} ({pct:5.2f}%)")
    else:
        print("\n✅ No missing values detected")

    profile['combined_stats']['missing_values'] = {
        'columns_with_missing': int(len(cols_with_missing)),
        'total_missing': int(missing_summary.sum())
    }

    # Numeric features statistics
    numeric_cols = df_sample.select_dtypes(include=[np.number]).columns.tolist()
    numeric_features = [col for col in feature_cols if col in numeric_cols]

    if len(numeric_features) > 0:
        print(f"\n📊 Numeric Feature Statistics (first 5):")
        for feat in numeric_features[:5]:
            stats = df_sample[feat].describe()
            print(f"\n   {feat}:")
            print(f"      Mean: {stats['mean']:.2f}, Std: {stats['std']:.2f}")
            print(f"      Min: {stats['min']:.2f}, Max: {stats['max']:.2f}")

    profile['combined_stats']['num_numeric_features'] = len(numeric_features)

# Save profile
profile['profiling_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

output_file = output_dir / 'network_data_profile.json'
with open(output_file, 'w') as f:
    json.dump(profile, f, indent=2, default=str)

print("\n" + "="*80)
print("✅ TASK 1-2 COMPLETE")
print("="*80)
print(f"\n💾 Profile saved: {output_file}")
print(f"\n📊 Key Findings:")
print(f"   - Total Files: {profile['total_files']}")
print(f"   - Sample File Columns: {profile['combined_stats'].get('total_columns', 'N/A')}")
print(f"   - Feature Columns: {profile['combined_stats'].get('num_features', 'N/A')}")
print(f"   - Numeric Features: {profile['combined_stats'].get('num_numeric_features', 'N/A')}")
