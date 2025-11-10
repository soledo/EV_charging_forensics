#!/usr/bin/env python3
"""
Phase 1: Data Preparation for ML Experiments

Loads aligned timelines and prepares train/test splits for:
- Host-only (887 features)
- Network-only (5 features)
- 2-Layer (Host + Network, 892 features)
- 3-Layer (Host + Network + Power, 895 features)

Author: MLCER Team
Date: 2025-11-10
"""

import pandas as pd
import numpy as np
from pathlib import Path
import json
from sklearn.model_selection import train_test_split

# Paths
DATA_DIR = Path("results/aligned_timelines")
OUTPUT_DIR = Path("processed/ml_datasets")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Random seed for reproducibility
RANDOM_STATE = 42
TEST_SIZE = 0.2  # 80/20 split

print("=" * 70)
print("Phase 1: Data Preparation for ML Classification")
print("=" * 70)

# Step 1: Load data
print("\n[1/6] Loading aligned datasets...")
scenarios = {
    'benign': 0,
    'dos': 1,
    'recon': 2,
    'cryptojacking': 3
}

dfs = []
labels = []

for scenario, label in scenarios.items():
    filepath = DATA_DIR / f"{scenario}_aligned.csv"
    print(f"  Loading {filepath}...")
    df = pd.read_csv(filepath)

    # Remove time column if present
    if 'time_rel' in df.columns:
        df = df.drop(columns=['time_rel'])
    elif df.columns[0].startswith('time') or df.columns[0] == 'Unnamed: 0':
        df = df.iloc[:, 1:]  # Drop first column if it's an index

    dfs.append(df)
    labels.extend([label] * len(df))
    print(f"    Loaded: {len(df)} samples × {len(df.columns)} features")

# Combine all scenarios
print("\n[2/6] Combining scenarios...")
X = pd.concat(dfs, axis=0, ignore_index=True)
y = np.array(labels)

print(f"  Combined dataset: {X.shape[0]} samples × {X.shape[1]} features")
print(f"  Class distribution: {dict(zip(*np.unique(y, return_counts=True)))}")

# Step 2: Identify feature groups
print("\n[3/6] Identifying feature groups...")
host_cols = [col for col in X.columns if col.startswith('host_')]
network_cols = [col for col in X.columns if col.startswith('network_')]
power_cols = [col for col in X.columns if col.startswith('power_')]

print(f"  Host features: {len(host_cols)}")
print(f"  Network features: {len(network_cols)}")
print(f"  Power features: {len(power_cols)}")

# Check for unexpected columns
other_cols = [col for col in X.columns if col not in host_cols + network_cols + power_cols]
if other_cols:
    print(f"  ⚠️  Unexpected columns: {other_cols[:5]}...")
    # Assume they're host features if they don't have prefix
    host_cols.extend(other_cols)
    print(f"  Treating as host features. New host count: {len(host_cols)}")

# Step 3: Extract feature subsets
print("\n[4/6] Extracting feature subsets...")
X_host = X[host_cols]
X_network = X[network_cols] if network_cols else pd.DataFrame()
X_power = X[power_cols] if power_cols else pd.DataFrame()

X_2layer = pd.concat([X_host, X_network], axis=1) if not X_network.empty else X_host
X_3layer = pd.concat([X_host, X_network, X_power], axis=1) if not X_power.empty else X_2layer

print(f"  X_host: {X_host.shape}")
print(f"  X_network: {X_network.shape}")
print(f"  X_2layer: {X_2layer.shape}")
print(f"  X_3layer: {X_3layer.shape}")

# Check missing data
print(f"\n  Missing data analysis:")
print(f"    X_host missing: {X_host.isna().sum().sum()} / {X_host.size} ({X_host.isna().mean().mean()*100:.2f}%)")
if not X_network.empty:
    print(f"    X_network missing: {X_network.isna().sum().sum()} / {X_network.size} ({X_network.isna().mean().mean()*100:.2f}%)")
if not X_power.empty:
    print(f"    X_power missing: {X_power.isna().sum().sum()} / {X_power.size} ({X_power.isna().mean().mean()*100:.2f}%)")

# Step 4: Train-test split
print(f"\n[5/6] Splitting into train/test ({100*(1-TEST_SIZE):.0f}/{100*TEST_SIZE:.0f})...")

# Split indices
train_idx, test_idx = train_test_split(
    np.arange(len(y)),
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=y  # Maintain class balance
)

# Create splits
splits = {
    'host': X_host,
    'network': X_network,
    '2layer': X_2layer,
    '3layer': X_3layer
}

saved_files = []

for name, X_data in splits.items():
    if X_data.empty:
        print(f"  Skipping {name} (no data)")
        continue

    X_train = X_data.iloc[train_idx]
    X_test = X_data.iloc[test_idx]

    # Save
    train_path = OUTPUT_DIR / f"X_train_{name}.csv"
    test_path = OUTPUT_DIR / f"X_test_{name}.csv"

    X_train.to_csv(train_path, index=False)
    X_test.to_csv(test_path, index=False)

    saved_files.extend([train_path, test_path])
    print(f"  Saved {name}: train {X_train.shape}, test {X_test.shape}")

# Save labels
y_train = y[train_idx]
y_test = y[test_idx]

y_train_path = OUTPUT_DIR / "y_train.csv"
y_test_path = OUTPUT_DIR / "y_test.csv"

pd.DataFrame({'label': y_train}).to_csv(y_train_path, index=False)
pd.DataFrame({'label': y_test}).to_csv(y_test_path, index=False)

saved_files.extend([y_train_path, y_test_path])

print(f"\n  Labels: y_train {y_train.shape}, y_test {y_test.shape}")
print(f"  Train class distribution: {dict(zip(*np.unique(y_train, return_counts=True)))}")
print(f"  Test class distribution: {dict(zip(*np.unique(y_test, return_counts=True)))}")

# Step 5: Save metadata
print("\n[6/6] Saving metadata...")
metadata = {
    'creation_date': '2025-11-10',
    'random_state': RANDOM_STATE,
    'test_size': TEST_SIZE,
    'total_samples': len(y),
    'train_samples': len(y_train),
    'test_samples': len(y_test),
    'scenarios': {name: label for name, label in scenarios.items()},
    'class_distribution': {
        'train': {int(k): int(v) for k, v in zip(*np.unique(y_train, return_counts=True))},
        'test': {int(k): int(v) for k, v in zip(*np.unique(y_test, return_counts=True))}
    },
    'feature_counts': {
        'host': len(host_cols),
        'network': len(network_cols),
        'power': len(power_cols),
        '2layer': X_2layer.shape[1],
        '3layer': X_3layer.shape[1]
    },
    'missing_rates': {
        'host': float(X_host.isna().mean().mean()),
        'network': float(X_network.isna().mean().mean()) if not X_network.empty else None,
        'power': float(X_power.isna().mean().mean()) if not X_power.empty else None,
        '3layer': float(X_3layer.isna().mean().mean())
    },
    'files_created': [str(f) for f in saved_files]
}

metadata_path = OUTPUT_DIR / "dataset_summary.json"
with open(metadata_path, 'w') as f:
    json.dump(metadata, f, indent=2)

print(f"  Metadata saved to {metadata_path}")

# Summary
print("\n" + "=" * 70)
print("✅ Data Preparation Complete!")
print("=" * 70)
print(f"Total files created: {len(saved_files) + 1}")
print(f"Output directory: {OUTPUT_DIR}")
print("\nNext step: Run baseline experiments")
print("  → python3 scripts/ml_experiments/baseline_host_only.py")
print("=" * 70)
