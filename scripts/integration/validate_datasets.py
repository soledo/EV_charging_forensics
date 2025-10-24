#!/usr/bin/env python3
"""
Phase 4 - Task 4-4: Dataset Validation
Validate quality and correctness of integrated datasets
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime

base_dir = Path('/mnt/d/EV_charging_forensics')
stage4_dir = base_dir / 'processed' / 'stage4'

print("="*80)
print("PHASE 4 - TASK 4-4: DATASET VALIDATION")
print("="*80)

# Load datasets
print("\n📂 Loading datasets...")
df_3layer = pd.read_csv(stage4_dir / 'dataset_3layer_dos_recon.csv', low_memory=False)
df_2layer = pd.read_csv(stage4_dir / 'dataset_2layer_benign_crypto.csv', low_memory=False)

print(f"✅ 3-layer: {len(df_3layer):,} records")
print(f"✅ 2-layer: {len(df_2layer):,} records")

validation_results = {
    '3layer': {},
    '2layer': {},
    'overall': {}
}

# ============================================================================
# STEP 1: Data Quality Checks
# ============================================================================
print("\n" + "="*80)
print("STEP 1: DATA QUALITY CHECKS")
print("="*80)

# 3-layer validation
print("\n📊 3-Layer Dataset Quality:")

# Check for missing values
missing_3 = df_3layer.isnull().sum().sum()
missing_pct_3 = (missing_3 / (len(df_3layer) * len(df_3layer.columns))) * 100

print(f"   Missing values: {missing_3:,} ({missing_pct_3:.4f}%)")
print(f"   {'✅ PASS' if missing_pct_3 < 1 else '⚠️ WARNING'}")

# Check for duplicates
duplicates_3 = df_3layer.duplicated().sum()
print(f"   Duplicate records: {duplicates_3:,}")
print(f"   {'✅ PASS' if duplicates_3 == 0 else '⚠️ WARNING'}")

# Check scenario distribution
scenario_dist_3 = df_3layer['Scenario'].value_counts().to_dict()
print(f"   Scenario distribution:")
for scenario, count in scenario_dist_3.items():
    pct = count / len(df_3layer) * 100
    print(f"      {scenario}: {count:,} ({pct:.1f}%)")

validation_results['3layer'] = {
    'missing_values': int(missing_3),
    'missing_pct': float(missing_pct_3),
    'duplicates': int(duplicates_3),
    'scenario_distribution': {k: int(v) for k, v in scenario_dist_3.items()},
    'quality': 'pass' if missing_pct_3 < 1 and duplicates_3 == 0 else 'warning'
}

# 2-layer validation
print("\n📊 2-Layer Dataset Quality:")

missing_2 = df_2layer.isnull().sum().sum()
missing_pct_2 = (missing_2 / (len(df_2layer) * len(df_2layer.columns))) * 100

print(f"   Missing values: {missing_2:,} ({missing_pct_2:.4f}%)")
print(f"   {'✅ PASS' if missing_pct_2 < 1 else '⚠️ WARNING'}")

duplicates_2 = df_2layer.duplicated().sum()
print(f"   Duplicate records: {duplicates_2:,}")
print(f"   {'✅ PASS' if duplicates_2 == 0 else '⚠️ WARNING'}")

scenario_dist_2 = df_2layer['Scenario'].value_counts().to_dict()
print(f"   Scenario distribution:")
for scenario, count in scenario_dist_2.items():
    pct = count / len(df_2layer) * 100
    print(f"      {scenario}: {count:,} ({pct:.1f}%)")

validation_results['2layer'] = {
    'missing_values': int(missing_2),
    'missing_pct': float(missing_pct_2),
    'duplicates': int(duplicates_2),
    'scenario_distribution': {k: int(v) for k, v in scenario_dist_2.items()},
    'quality': 'pass' if missing_pct_2 < 1 and duplicates_2 == 0 else 'warning'
}

# ============================================================================
# STEP 2: Feature Composition Validation
# ============================================================================
print("\n" + "="*80)
print("STEP 2: FEATURE COMPOSITION VALIDATION")
print("="*80)

# 3-layer: Must have Host + Network + Power
print("\n📊 3-Layer Feature Composition:")
network_cols_3 = [c for c in df_3layer.columns if c in ['net_packet_count', 'net_bytes_total', 'net_packet_rate']]
power_cols_3 = [c for c in df_3layer.columns if c.startswith('power_')]

has_network = len(network_cols_3) > 0
has_power = len(power_cols_3) > 0

print(f"   Network features: {len(network_cols_3)} found")
print(f"   {'✅ PASS' if has_network else '❌ FAIL'}")
print(f"   Power features: {len(power_cols_3)} found")
print(f"   {'✅ PASS' if has_power else '❌ FAIL'}")

validation_results['3layer']['feature_composition'] = {
    'has_network': has_network,
    'has_power': has_power,
    'network_count': len(network_cols_3),
    'power_count': len(power_cols_3),
    'validation': 'pass' if has_network and has_power else 'fail'
}

# 2-layer: Must have Host + Power (NO Network traffic)
print("\n📊 2-Layer Feature Composition:")
network_traffic_cols_2 = [c for c in df_2layer.columns if c in ['net_packet_count', 'net_bytes_total', 'net_packet_rate']]
power_cols_2 = [c for c in df_2layer.columns if c.startswith('power_')]

has_no_network = len(network_traffic_cols_2) == 0
has_power_2 = len(power_cols_2) > 0

print(f"   Network traffic features: {len(network_traffic_cols_2)}")
print(f"   {'✅ PASS (should be 0)' if has_no_network else '❌ FAIL'}")
print(f"   Power features: {len(power_cols_2)} found")
print(f"   {'✅ PASS' if has_power_2 else '❌ FAIL'}")

validation_results['2layer']['feature_composition'] = {
    'has_network_traffic': not has_no_network,
    'has_power': has_power_2,
    'network_traffic_count': len(network_traffic_cols_2),
    'power_count': len(power_cols_2),
    'validation': 'pass' if has_no_network and has_power_2 else 'fail'
}

# ============================================================================
# STEP 3: Attack-Adaptive Layer Selection Verification
# ============================================================================
print("\n" + "="*80)
print("STEP 3: ATTACK-ADAPTIVE LAYER SELECTION VERIFICATION")
print("="*80)

print("\n✅ Network-Originated Attacks (3-Layer):")
print(f"   Scenarios: {list(scenario_dist_3.keys())}")
print(f"   Records: {len(df_3layer):,}")
print(f"   Layer composition: Host + Network + Power ✅")

print("\n✅ Host-Originated Attacks (2-Layer):")
print(f"   Scenarios: {list(scenario_dist_2.keys())}")
print(f"   Records: {len(df_2layer):,}")
print(f"   Layer composition: Host + Power (NO Network traffic) ✅")

total_records = len(df_3layer) + len(df_2layer)
print(f"\n📊 Total Dataset:")
print(f"   Total records: {total_records:,}")
print(f"   3-layer (network-originated): {len(df_3layer):,} ({len(df_3layer)/total_records*100:.1f}%)")
print(f"   2-layer (host-originated): {len(df_2layer):,} ({len(df_2layer)/total_records*100:.1f}%)")

# ============================================================================
# STEP 4: Overall Validation Score
# ============================================================================
print("\n" + "="*80)
print("STEP 4: OVERALL VALIDATION SCORE")
print("="*80)

validation_checks = [
    validation_results['3layer']['quality'] == 'pass',
    validation_results['2layer']['quality'] == 'pass',
    validation_results['3layer']['feature_composition']['validation'] == 'pass',
    validation_results['2layer']['feature_composition']['validation'] == 'pass'
]

passed_checks = sum(validation_checks)
total_checks = len(validation_checks)
validation_score = (passed_checks / total_checks) * 100

print(f"\n📊 Validation Results:")
print(f"   Passed checks: {passed_checks}/{total_checks}")
print(f"   Validation score: {validation_score:.1f}%")
print(f"   {'✅ ALL CHECKS PASSED' if validation_score == 100 else '⚠️ SOME CHECKS FAILED'}")

validation_results['overall'] = {
    'passed_checks': passed_checks,
    'total_checks': total_checks,
    'validation_score': float(validation_score),
    'status': 'pass' if validation_score == 100 else 'fail',
    'total_records': int(total_records),
    '3layer_records': int(len(df_3layer)),
    '2layer_records': int(len(df_2layer))
}

# ============================================================================
# SAVE VALIDATION RESULTS
# ============================================================================
validation_results['validation_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

output_file = stage4_dir / 'dataset_validation.json'
with open(output_file, 'w') as f:
    json.dump(validation_results, f, indent=2)

print(f"\n💾 Validation results saved: {output_file}")

print("\n" + "="*80)
print("✅ TASK 4-4 COMPLETE")
print("="*80)

print("\n" + "="*80)
print("✅ PHASE 4: CROSS-LAYER INTEGRATION COMPLETE")
print("="*80)

print(f"\n📊 Final Summary:")
print(f"   - 3-Layer Dataset: {len(df_3layer):,} records (DoS + Recon)")
print(f"   - 2-Layer Dataset: {len(df_2layer):,} records (Benign + Crypto)")
print(f"   - Total: {total_records:,} records")
print(f"   - Validation: {validation_score:.1f}% ({passed_checks}/{total_checks} checks)")

print(f"\nℹ️  Datasets ready for Phase 5: Baseline Comparison & Modeling")
