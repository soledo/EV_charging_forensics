#!/usr/bin/env python3
"""
Task 5: Time-Lagged Cross-Layer Correlation
Measure propagation lag between layers
Lag range: -10s to +10s (negative = layer1 leads, positive = layer2 leads)
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime
from scipy import stats

base_dir = Path('/mnt/d/EV_charging_forensics')
aligned_dir = base_dir / 'results' / 'aligned_timelines'
results_dir = base_dir / 'results'

print("="*80)
print("TASK 5: TIME-LAGGED CROSS-LAYER CORRELATION")
print("="*80)

# Lag range configuration
LAG_MIN = -10
LAG_MAX = 10

def interpret_lag(lag, layer1, layer2):
    """
    Interpret the meaning of optimal lag
    """
    if lag < 0:
        return f"{layer1.upper()} leads {layer2.upper()} by {abs(lag)} seconds"
    elif lag > 0:
        return f"{layer2.upper()} leads {layer1.upper()} by {lag} seconds"
    else:
        return f"{layer1.upper()} and {layer2.upper()} are synchronous (no lag)"

def time_lagged_correlation(scenario, has_network=True):
    """
    Compute correlation at different time lags
    """
    print(f"\n{'='*80}")
    print(f"Scenario: {scenario.upper()}")
    print(f"{'='*80}")

    # Load aligned timeline
    aligned_file = aligned_dir / f'{scenario}_aligned.csv'
    df = pd.read_csv(aligned_file)

    print(f"\n📂 Loaded: {aligned_file.name}")
    print(f"   Shape: {df.shape}")

    correlations = {}

    # Get feature columns
    host_cols = [col for col in df.columns if col.startswith('host_')]
    power_cols = [col for col in df.columns if col.startswith('power_')]

    if has_network:
        net_cols = [col for col in df.columns if col.startswith('net_')]
    else:
        net_cols = []

    # Aggregate features to single time series per layer
    print(f"\n🔄 Aggregating features...")

    host_intensity = df[host_cols].mean(axis=1).values
    power_intensity = df[power_cols].mean(axis=1).values

    print(f"   Host: {len(host_cols)} features → intensity time series")
    print(f"   Power: {len(power_cols)} features → intensity time series")

    if has_network:
        net_intensity = df[net_cols].mean(axis=1).values
        print(f"   Network: {len(net_cols)} features → intensity time series")

    # -------------------------------------------------------------------------
    # 1. Network → Host Correlation
    # -------------------------------------------------------------------------
    if has_network:
        print(f"\n🔗 Network → Host correlation...")

        net_host_corr = []

        for lag in range(LAG_MIN, LAG_MAX + 1):
            if lag < 0:
                # Network leads: shift host backward (later in time)
                net_shifted = net_intensity[:lag]  # Remove last |lag| points
                host_shifted = host_intensity[-lag:]  # Remove first |lag| points
            elif lag > 0:
                # Host leads: shift network backward
                net_shifted = net_intensity[lag:]
                host_shifted = host_intensity[:-lag]
            else:
                # No lag
                net_shifted = net_intensity
                host_shifted = host_intensity

            # Remove NaN values
            valid_mask = ~(np.isnan(net_shifted) | np.isnan(host_shifted))

            if valid_mask.sum() < 3:
                # Not enough valid data
                net_host_corr.append({
                    'lag': lag,
                    'r': 0.0,
                    'p_value': 1.0,
                    'significant': bool(False),
                    'n_samples': int(valid_mask.sum())
                })
                continue

            net_valid = net_shifted[valid_mask]
            host_valid = host_shifted[valid_mask]

            # Pearson correlation
            r, p_value = stats.pearsonr(net_valid, host_valid)

            net_host_corr.append({
                'lag': lag,
                'r': float(r) if not np.isnan(r) else 0.0,
                'p_value': float(p_value) if not np.isnan(p_value) else 1.0,
                'significant': bool(p_value < 0.05 if not np.isnan(p_value) else False),
                'n_samples': int(valid_mask.sum())
            })

        # Find optimal lag (max |r|)
        optimal = max(net_host_corr, key=lambda x: abs(x['r']))

        correlations['net_host'] = {
            'lag_correlations': net_host_corr,
            'optimal_lag': optimal['lag'],
            'optimal_r': optimal['r'],
            'optimal_p': optimal['p_value'],
            'interpretation': interpret_lag(optimal['lag'], 'network', 'host')
        }

        print(f"   Optimal lag: {optimal['lag']}s (r={optimal['r']:.3f}, p={optimal['p_value']:.4f})")
        print(f"   {correlations['net_host']['interpretation']}")

    # -------------------------------------------------------------------------
    # 2. Host → Power Correlation
    # -------------------------------------------------------------------------
    print(f"\n🔗 Host → Power correlation...")

    host_power_corr = []

    for lag in range(LAG_MIN, LAG_MAX + 1):
        if lag < 0:
            # Host leads
            host_shifted = host_intensity[:lag]
            power_shifted = power_intensity[-lag:]
        elif lag > 0:
            # Power leads
            host_shifted = host_intensity[lag:]
            power_shifted = power_intensity[:-lag]
        else:
            host_shifted = host_intensity
            power_shifted = power_intensity

        # Remove NaN values
        valid_mask = ~(np.isnan(host_shifted) | np.isnan(power_shifted))

        if valid_mask.sum() < 3:
            host_power_corr.append({
                'lag': lag,
                'r': 0.0,
                'p_value': 1.0,
                'significant': bool(False),
                'n_samples': int(valid_mask.sum())
            })
            continue

        host_valid = host_shifted[valid_mask]
        power_valid = power_shifted[valid_mask]

        r, p_value = stats.pearsonr(host_valid, power_valid)

        host_power_corr.append({
            'lag': lag,
            'r': float(r) if not np.isnan(r) else 0.0,
            'p_value': float(p_value) if not np.isnan(p_value) else 1.0,
            'significant': bool(p_value < 0.05 if not np.isnan(p_value) else False),
            'n_samples': int(valid_mask.sum())
        })

    # Find optimal lag
    optimal = max(host_power_corr, key=lambda x: abs(x['r']))

    correlations['host_power'] = {
        'lag_correlations': host_power_corr,
        'optimal_lag': optimal['lag'],
        'optimal_r': optimal['r'],
        'optimal_p': optimal['p_value'],
        'interpretation': interpret_lag(optimal['lag'], 'host', 'power')
    }

    print(f"   Optimal lag: {optimal['lag']}s (r={optimal['r']:.3f}, p={optimal['p_value']:.4f})")
    print(f"   {correlations['host_power']['interpretation']}")

    # -------------------------------------------------------------------------
    # 3. Network → Power Correlation (if available)
    # -------------------------------------------------------------------------
    if has_network:
        print(f"\n🔗 Network → Power correlation...")

        net_power_corr = []

        for lag in range(LAG_MIN, LAG_MAX + 1):
            if lag < 0:
                # Network leads
                net_shifted = net_intensity[:lag]
                power_shifted = power_intensity[-lag:]
            elif lag > 0:
                # Power leads
                net_shifted = net_intensity[lag:]
                power_shifted = power_intensity[:-lag]
            else:
                net_shifted = net_intensity
                power_shifted = power_intensity

            # Remove NaN values
            valid_mask = ~(np.isnan(net_shifted) | np.isnan(power_shifted))

            if valid_mask.sum() < 3:
                net_power_corr.append({
                    'lag': lag,
                    'r': 0.0,
                    'p_value': 1.0,
                    'significant': bool(False),
                    'n_samples': int(valid_mask.sum())
                })
                continue

            net_valid = net_shifted[valid_mask]
            power_valid = power_shifted[valid_mask]

            r, p_value = stats.pearsonr(net_valid, power_valid)

            net_power_corr.append({
                'lag': lag,
                'r': float(r) if not np.isnan(r) else 0.0,
                'p_value': float(p_value) if not np.isnan(p_value) else 1.0,
                'significant': bool(p_value < 0.05 if not np.isnan(p_value) else False),
                'n_samples': int(valid_mask.sum())
            })

        # Find optimal lag
        optimal = max(net_power_corr, key=lambda x: abs(x['r']))

        correlations['net_power'] = {
            'lag_correlations': net_power_corr,
            'optimal_lag': optimal['lag'],
            'optimal_r': optimal['r'],
            'optimal_p': optimal['p_value'],
            'interpretation': interpret_lag(optimal['lag'], 'network', 'power')
        }

        print(f"   Optimal lag: {optimal['lag']}s (r={optimal['r']:.3f}, p={optimal['p_value']:.4f})")
        print(f"   {correlations['net_power']['interpretation']}")

    return {
        'scenario': scenario,
        'has_network': has_network,
        'correlations': correlations,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

# ============================================================================
# Process All Scenarios
# ============================================================================

scenarios = {
    'dos': {'has_network': True},
    'recon': {'has_network': True},
    'cryptojacking': {'has_network': False},
    'benign': {'has_network': False}
}

all_correlations = {}

for scenario, config in scenarios.items():
    result = time_lagged_correlation(scenario, has_network=config['has_network'])
    all_correlations[scenario] = result

# ============================================================================
# Save Results
# ============================================================================
output_file = results_dir / 'time_lagged_correlations.json'
with open(output_file, 'w') as f:
    json.dump(all_correlations, f, indent=2)

print(f"\n{'='*80}")
print("SUMMARY")
print(f"{'='*80}")

print(f"\n📊 Optimal Lags and Correlations:")

for scenario, data in all_correlations.items():
    print(f"\n{scenario.upper()}:")

    if 'net_host' in data['correlations']:
        corr = data['correlations']['net_host']
        print(f"   Network → Host: lag={corr['optimal_lag']}s, r={corr['optimal_r']:.3f}")
        print(f"      {corr['interpretation']}")

    corr = data['correlations']['host_power']
    print(f"   Host → Power: lag={corr['optimal_lag']}s, r={corr['optimal_r']:.3f}")
    print(f"      {corr['interpretation']}")

    if 'net_power' in data['correlations']:
        corr = data['correlations']['net_power']
        print(f"   Network → Power: lag={corr['optimal_lag']}s, r={corr['optimal_r']:.3f}")
        print(f"      {corr['interpretation']}")

print(f"\n💾 Results saved: {output_file}")

print("\n" + "="*80)
print("✅ TASK 5 COMPLETE")
print("="*80)
