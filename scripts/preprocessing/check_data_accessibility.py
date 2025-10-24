#!/usr/bin/env python3
"""
Phase 0 - Task 0-3: Data Accessibility Check
Validate all required data files are accessible
"""

import os
import pandas as pd
from pathlib import Path

base_dir = Path('/mnt/d/EV_charging_forensics')

print("="*80)
print("PHASE 0: ENVIRONMENT SETUP - DATA ACCESSIBILITY CHECK")
print("="*80)

# Define data paths
data_paths = {
    'Host Events': base_dir / 'CICEVSE2024_Dataset' / 'Host Events' / 'EVSE-B-HPC-Kernel-Events-Combined.csv',
    'Network Traffic': base_dir / 'CICEVSE2024_Dataset' / 'Network Traffic' / 'EVSE-B' / 'csv',
    'Power Consumption': base_dir / 'CICEVSE2024_Dataset' / 'Power Consumption' / 'EVSE-B-PowerCombined.csv'
}

print("\n🔍 Checking data file accessibility...\n")

all_accessible = True

# Check Host data
host_path = data_paths['Host Events']
if host_path.exists():
    print(f"✅ Host Events: {host_path}")
    try:
        df_host = pd.read_csv(host_path, nrows=5)
        print(f"   - Readable: Yes")
        print(f"   - Columns: {len(df_host.columns)}")
        print(f"   - Sample columns: {list(df_host.columns[:5])}")
    except Exception as e:
        print(f"   ❌ Error reading file: {e}")
        all_accessible = False
else:
    print(f"❌ Host Events: NOT FOUND at {host_path}")
    all_accessible = False

# Check Network data
network_path = data_paths['Network Traffic']
if network_path.exists() and network_path.is_dir():
    print(f"\n✅ Network Traffic: {network_path}")
    csv_files = list(network_path.glob('*.csv'))
    print(f"   - CSV files found: {len(csv_files)}")
    if csv_files:
        print(f"   - Sample files: {[f.name for f in csv_files[:3]]}")
        try:
            df_sample = pd.read_csv(csv_files[0], nrows=5)
            print(f"   - Readable: Yes")
            print(f"   - Columns: {len(df_sample.columns)}")
        except Exception as e:
            print(f"   ❌ Error reading file: {e}")
            all_accessible = False
    else:
        print(f"   ⚠️ No CSV files found in directory")
        all_accessible = False
else:
    print(f"❌ Network Traffic: NOT FOUND at {network_path}")
    all_accessible = False

# Check Power data
power_path = data_paths['Power Consumption']
if power_path.exists():
    print(f"\n✅ Power Consumption: {power_path}")
    try:
        df_power = pd.read_csv(power_path, nrows=5)
        print(f"   - Readable: Yes")
        print(f"   - Columns: {len(df_power.columns)}")
        print(f"   - Sample columns: {list(df_power.columns)}")
    except Exception as e:
        print(f"   ❌ Error reading file: {e}")
        all_accessible = False
else:
    print(f"❌ Power Consumption: NOT FOUND at {power_path}")
    all_accessible = False

print("\n" + "="*80)
if all_accessible:
    print("✅ Phase 0 - Task 0-3: PASSED")
    print("   All data files are accessible and readable")
else:
    print("❌ Phase 0 - Task 0-3: FAILED")
    print("   Some data files are missing or unreadable")
print("="*80)
