#!/usr/bin/env python3
"""
Task 3: Multi-Layer "얼추" Alignment
Align 3 layers using ±2.5s tolerance window (5s total)
Method: Windowed averaging to handle slight temporal misalignment
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime

base_dir = Path('/mnt/d/EV_charging_forensics')
normalized_dir = base_dir / 'results' / 'normalized_timelines'
aligned_dir = base_dir / 'results' / 'aligned_timelines'
aligned_dir.mkdir(exist_ok=True, parents=True)

print("="*80)
print("TASK 3: MULTI-LAYER ALIGNMENT (±2.5s TOLERANCE)")
print("="*80)

# Alignment configuration
WINDOW_TOLERANCE = 2.5  # ±2.5 seconds (5s total window)
TIME_RANGE = range(0, 61)  # 0-60 seconds

def align_multilayer_timeline(scenario, has_network=True):
    """
    Align network, host, power using windowed average
    Tolerance: ±2.5 seconds (5s total window)
    """
    print(f"\n{'='*80}")
    print(f"Scenario: {scenario.upper()}")
    print(f"{'='*80}")

    scenario_dir = normalized_dir / scenario

    # Load normalized timelines
    print(f"\n📂 Loading normalized timelines...")
    host_df = pd.read_csv(scenario_dir / 'host_relative.csv')
    power_df = pd.read_csv(scenario_dir / 'power_relative.csv')

    print(f"   ✅ Host: {host_df.shape}")
    print(f"   ✅ Power: {power_df.shape}")

    if has_network:
        network_df = pd.read_csv(scenario_dir / 'network_relative.csv')
        print(f"   ✅ Network: {network_df.shape}")
    else:
        network_df = None
        print(f"   ⚠️  Network: Not available (host-originated attack)")

    # Alignment metadata
    metadata = {
        'scenario': scenario,
        'window_tolerance': WINDOW_TOLERANCE,
        'has_network': has_network,
        'samples_used': {},
        'missing_rate': {},
        'feature_count': {}
    }

    aligned_timeline = []

    print(f"\n🔄 Aligning with ±{WINDOW_TOLERANCE}s window...")

    for t in TIME_RANGE:
        window_start = t - WINDOW_TOLERANCE
        window_end = t + WINDOW_TOLERANCE

        row = {'time_rel': t}

        # -------------------------------------------------------------------------
        # Host Layer
        # -------------------------------------------------------------------------
        host_window = host_df[
            (host_df['time_rel'] >= window_start) &
            (host_df['time_rel'] < window_end)
        ]

        if len(host_window) > 0:
            # Select numeric columns only (exclude time_rel)
            host_numeric = host_window.select_dtypes(include=[np.number]).drop(columns=['time_rel'], errors='ignore')
            host_features = host_numeric.mean()

            for col, val in host_features.items():
                row[f'host_{col}'] = val

            if t == 0:
                metadata['feature_count']['host'] = len(host_features)
        else:
            # No data in window - use NaN
            if t == 0:
                host_numeric = host_df.select_dtypes(include=[np.number]).drop(columns=['time_rel'], errors='ignore')
                for col in host_numeric.columns:
                    row[f'host_{col}'] = np.nan
                metadata['feature_count']['host'] = len(host_numeric.columns)

        # -------------------------------------------------------------------------
        # Network Layer
        # -------------------------------------------------------------------------
        if has_network:
            net_window = network_df[
                (network_df['time_rel'] >= window_start) &
                (network_df['time_rel'] < window_end)
            ]

            if len(net_window) > 0:
                net_numeric = net_window.select_dtypes(include=[np.number]).drop(columns=['time_rel'], errors='ignore')
                net_features = net_numeric.mean()

                for col, val in net_features.items():
                    row[f'net_{col}'] = val

                if t == 0:
                    metadata['feature_count']['network'] = len(net_features)
            else:
                if t == 0:
                    net_numeric = network_df.select_dtypes(include=[np.number]).drop(columns=['time_rel'], errors='ignore')
                    for col in net_numeric.columns:
                        row[f'net_{col}'] = np.nan
                    metadata['feature_count']['network'] = len(net_numeric.columns)

        # -------------------------------------------------------------------------
        # Power Layer
        # -------------------------------------------------------------------------
        power_window = power_df[
            (power_df['time_rel'] >= window_start) &
            (power_df['time_rel'] < window_end)
        ]

        if len(power_window) > 0:
            power_numeric = power_window.select_dtypes(include=[np.number]).drop(columns=['time_rel'], errors='ignore')
            power_features = power_numeric.mean()

            for col, val in power_features.items():
                row[f'power_{col}'] = val

            if t == 0:
                metadata['feature_count']['power'] = len(power_features)
        else:
            if t == 0:
                power_numeric = power_df.select_dtypes(include=[np.number]).drop(columns=['time_rel'], errors='ignore')
                for col in power_numeric.columns:
                    row[f'power_{col}'] = np.nan
                metadata['feature_count']['power'] = len(power_numeric.columns)

        aligned_timeline.append(row)

    # Create aligned DataFrame
    df_aligned = pd.DataFrame(aligned_timeline)

    # Calculate alignment quality metrics
    print(f"\n📊 Alignment Quality:")

    # Samples used per layer
    host_cols = [col for col in df_aligned.columns if col.startswith('host_')]
    power_cols = [col for col in df_aligned.columns if col.startswith('power_')]

    host_missing = df_aligned[host_cols].isnull().sum().sum() / (len(df_aligned) * len(host_cols)) * 100
    power_missing = df_aligned[power_cols].isnull().sum().sum() / (len(df_aligned) * len(power_cols)) * 100

    print(f"   Host: {len(host_cols)} features, {host_missing:.2f}% missing")
    print(f"   Power: {len(power_cols)} features, {power_missing:.2f}% missing")

    metadata['missing_rate']['host'] = float(host_missing)
    metadata['missing_rate']['power'] = float(power_missing)

    if has_network:
        net_cols = [col for col in df_aligned.columns if col.startswith('net_')]
        net_missing = df_aligned[net_cols].isnull().sum().sum() / (len(df_aligned) * len(net_cols)) * 100
        print(f"   Network: {len(net_cols)} features, {net_missing:.2f}% missing")
        metadata['missing_rate']['network'] = float(net_missing)

    # Overall missing rate
    total_missing = df_aligned.isnull().sum().sum() / (df_aligned.shape[0] * df_aligned.shape[1]) * 100
    print(f"   Overall: {total_missing:.2f}% missing")
    metadata['missing_rate']['overall'] = float(total_missing)

    # Save aligned timeline
    output_file = aligned_dir / f'{scenario}_aligned.csv'
    df_aligned.to_csv(output_file, index=False)

    print(f"\n💾 Saved: {output_file.name}")
    print(f"   Shape: {df_aligned.shape[0]} rows × {df_aligned.shape[1]} columns")

    # Save metadata
    metadata['shape'] = {'rows': int(df_aligned.shape[0]), 'columns': int(df_aligned.shape[1])}
    metadata['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    metadata_file = aligned_dir / f'{scenario}_aligned_metadata.json'
    with open(metadata_file, 'w') as f:
        json.dump(metadata, f, indent=2)

    print(f"💾 Metadata: {metadata_file.name}")

    return df_aligned, metadata

# ============================================================================
# Process All Scenarios
# ============================================================================

scenarios = {
    'dos': {'has_network': True},
    'recon': {'has_network': True},
    'cryptojacking': {'has_network': False},
    'benign': {'has_network': False}
}

all_metadata = {}

for scenario, config in scenarios.items():
    df_aligned, metadata = align_multilayer_timeline(scenario, has_network=config['has_network'])
    all_metadata[scenario] = metadata

# ============================================================================
# Summary Report
# ============================================================================
print(f"\n{'='*80}")
print("ALIGNMENT SUMMARY")
print(f"{'='*80}")

print(f"\n📊 Feature Counts:")
for scenario, meta in all_metadata.items():
    feature_counts = meta['feature_count']
    total = sum(feature_counts.values())
    print(f"\n{scenario.upper()}:")
    for layer, count in feature_counts.items():
        print(f"   {layer.capitalize()}: {count} features")
    print(f"   Total: {total} features")

print(f"\n📊 Missing Data Rates:")
for scenario, meta in all_metadata.items():
    print(f"\n{scenario.upper()}:")
    for layer, rate in meta['missing_rate'].items():
        if layer != 'overall':
            print(f"   {layer.capitalize()}: {rate:.2f}%")
    print(f"   Overall: {meta['missing_rate']['overall']:.2f}%")

# Save combined summary
summary = {
    'window_tolerance': WINDOW_TOLERANCE,
    'time_range': [TIME_RANGE.start, TIME_RANGE.stop - 1],
    'scenarios': all_metadata,
    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
}

summary_file = aligned_dir / 'alignment_summary.json'
with open(summary_file, 'w') as f:
    json.dump(summary, f, indent=2)

print(f"\n💾 Summary saved: {summary_file}")

print("\n" + "="*80)
print("✅ TASK 3 COMPLETE")
print("="*80)
print(f"\n📂 Aligned timelines saved to: {aligned_dir}")
print(f"\nFiles created:")
print(f"   - dos_aligned.csv (61 rows × ~900 columns)")
print(f"   - recon_aligned.csv")
print(f"   - cryptojacking_aligned.csv")
print(f"   - benign_aligned.csv")
print(f"   - *_metadata.json (4 files)")
print(f"   - alignment_summary.json")
