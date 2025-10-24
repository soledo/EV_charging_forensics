#!/usr/bin/env python3
"""
Task 4: Temporal Evolution Characterization
Analyze attack progression over 3 phases:
- Initiation (0-10s): Attack starts, initial anomaly
- Peak (10-30s): Maximum intensity period
- Sustained (30-60s): Steady-state behavior
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
print("TASK 4: TEMPORAL EVOLUTION CHARACTERIZATION")
print("="*80)

# Phase definitions
PHASES = {
    'initiation': (0, 10),
    'peak': (10, 30),
    'sustained': (30, 60)
}

def compute_linear_trend(data):
    """
    Compute linear trend using OLS
    Returns slope (positive = increasing, negative = decreasing)
    """
    if data.shape[0] == 0:
        return 0.0

    # Average across features for each time point
    time_series = data.mean(axis=1).values

    if len(time_series) == 0 or np.all(np.isnan(time_series)):
        return 0.0

    # Remove NaN values
    valid_mask = ~np.isnan(time_series)
    if valid_mask.sum() < 2:
        return 0.0

    x = np.arange(len(time_series))[valid_mask]
    y = time_series[valid_mask]

    # Linear regression
    slope, _, _, _, _ = stats.linregress(x, y)

    return float(slope)

def detect_plateau_onset(time_series, window=5, threshold=0.05):
    """
    Detect when signal stabilizes (plateau onset)
    Method: Find first time when moving std falls below threshold
    """
    if len(time_series) < window:
        return None

    # Remove NaN
    valid_mask = ~np.isnan(time_series)
    if valid_mask.sum() < window:
        return None

    # Compute moving std
    rolling_std = pd.Series(time_series).rolling(window=window, min_periods=1).std()

    # Find first time below threshold
    stable_points = np.where(rolling_std < threshold)[0]

    if len(stable_points) > 0:
        return int(stable_points[0])

    return None

def characterize_temporal_evolution(scenario, has_network=True):
    """
    Analyze attack progression over time
    """
    print(f"\n{'='*80}")
    print(f"Scenario: {scenario.upper()}")
    print(f"{'='*80}")

    # Load aligned timeline
    aligned_file = aligned_dir / f'{scenario}_aligned.csv'
    df = pd.read_csv(aligned_file)

    print(f"\n📂 Loaded: {aligned_file.name}")
    print(f"   Shape: {df.shape}")

    patterns = {}

    # -------------------------------------------------------------------------
    # Phase Analysis
    # -------------------------------------------------------------------------
    print(f"\n🔄 Analyzing phases...")

    for phase_name, (start, end) in PHASES.items():
        phase_df = df[(df['time_rel'] >= start) & (df['time_rel'] < end)]

        print(f"\n   {phase_name.upper()} ({start}-{end}s): {len(phase_df)} samples")

        # Analyze each layer
        for layer in ['host', 'net', 'power']:
            if layer == 'net' and not has_network:
                continue

            layer_cols = [col for col in df.columns if col.startswith(f'{layer}_')]

            if len(layer_cols) == 0:
                continue

            layer_data = phase_df[layer_cols]

            # Compute statistics
            mean_val = float(layer_data.mean().mean())
            std_val = float(layer_data.std().mean())
            max_val = float(layer_data.max().max())
            min_val = float(layer_data.min().min())
            trend = compute_linear_trend(layer_data)

            patterns[f'{phase_name}_{layer}'] = {
                'mean': mean_val if not np.isnan(mean_val) else 0.0,
                'std': std_val if not np.isnan(std_val) else 0.0,
                'max': max_val if not np.isnan(max_val) else 0.0,
                'min': min_val if not np.isnan(min_val) else 0.0,
                'trend': trend if not np.isnan(trend) else 0.0,
                'samples': len(phase_df)
            }

            print(f"      {layer.upper()}: mean={mean_val:.4f}, trend={trend:+.6f}")

    # -------------------------------------------------------------------------
    # Critical Events Detection
    # -------------------------------------------------------------------------
    print(f"\n🎯 Detecting critical events...")

    critical_events = []

    # 1. Peak intensity (Host layer)
    host_cols = [col for col in df.columns if col.startswith('host_')]
    if len(host_cols) > 0:
        # Sum across features to get overall intensity
        host_intensity = df[host_cols].sum(axis=1)

        peak_idx = host_intensity.idxmax()
        peak_time = int(df.iloc[peak_idx]['time_rel'])
        peak_value = float(host_intensity.iloc[peak_idx])

        critical_events.append({
            'event': 'peak_intensity',
            'time': peak_time,
            'value': peak_value,
            'layer': 'host',
            'description': 'Maximum host activity'
        })

        print(f"   ✅ Peak intensity at t={peak_time}s (value={peak_value:.2f})")

        # 2. Plateau onset (Host layer)
        plateau_time = detect_plateau_onset(host_intensity.values, window=5, threshold=host_intensity.std() * 0.1)

        if plateau_time is not None:
            plateau_value = float(host_intensity.iloc[plateau_time])

            critical_events.append({
                'event': 'plateau_onset',
                'time': plateau_time,
                'value': plateau_value,
                'layer': 'host',
                'description': 'Signal stabilization'
            })

            print(f"   ✅ Plateau onset at t={plateau_time}s (value={plateau_value:.2f})")
        else:
            print(f"   ⚠️  Plateau onset not detected")

    # 3. Network spike (if available)
    if has_network:
        net_cols = [col for col in df.columns if col.startswith('net_')]
        if len(net_cols) > 0:
            net_intensity = df[net_cols].sum(axis=1)

            net_peak_idx = net_intensity.idxmax()
            net_peak_time = int(df.iloc[net_peak_idx]['time_rel'])
            net_peak_value = float(net_intensity.iloc[net_peak_idx])

            critical_events.append({
                'event': 'network_peak',
                'time': net_peak_time,
                'value': net_peak_value,
                'layer': 'network',
                'description': 'Maximum network activity'
            })

            print(f"   ✅ Network peak at t={net_peak_time}s (value={net_peak_value:.2f})")

    # 4. Power spike
    power_cols = [col for col in df.columns if col.startswith('power_')]
    if len(power_cols) > 0:
        power_data = df[power_cols].mean(axis=1)  # Average power

        # Only if data available
        if power_data.notna().sum() > 0:
            power_peak_idx = power_data.idxmax()
            power_peak_time = int(df.iloc[power_peak_idx]['time_rel'])
            power_peak_value = float(power_data.iloc[power_peak_idx])

            critical_events.append({
                'event': 'power_peak',
                'time': power_peak_time,
                'value': power_peak_value,
                'layer': 'power',
                'description': 'Maximum power consumption'
            })

            print(f"   ✅ Power peak at t={power_peak_time}s (value={power_peak_value:.2f} mW)")

    return {
        'scenario': scenario,
        'has_network': has_network,
        'phases': patterns,
        'critical_events': critical_events,
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

all_patterns = {}

for scenario, config in scenarios.items():
    result = characterize_temporal_evolution(scenario, has_network=config['has_network'])
    all_patterns[scenario] = result

# ============================================================================
# Save Results
# ============================================================================
output_file = results_dir / 'temporal_patterns.json'
with open(output_file, 'w') as f:
    json.dump(all_patterns, f, indent=2)

print(f"\n{'='*80}")
print("SUMMARY")
print(f"{'='*80}")

print(f"\n📊 Phase Patterns:")
for scenario in all_patterns.keys():
    print(f"\n{scenario.upper()}:")
    phases = all_patterns[scenario]['phases']

    for phase_name in ['initiation', 'peak', 'sustained']:
        print(f"   {phase_name.upper()}:")
        for layer in ['host', 'net', 'power']:
            key = f'{phase_name}_{layer}'
            if key in phases:
                stats = phases[key]
                print(f"      {layer}: mean={stats['mean']:.4f}, trend={stats['trend']:+.6f}")

print(f"\n📊 Critical Events:")
for scenario, data in all_patterns.items():
    print(f"\n{scenario.upper()}:")
    for event in data['critical_events']:
        print(f"   {event['event']}: t={event['time']}s ({event['layer']})")

print(f"\n💾 Results saved: {output_file}")

print("\n" + "="*80)
print("✅ TASK 4 COMPLETE")
print("="*80)
