#!/usr/bin/env python3
"""
Task 1: Attack Start Point Detection
Automatically detect attack initiation using anomaly detection
Strategy: Benign baseline + 2σ threshold + confirmation window
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime

base_dir = Path('/mnt/d/EV_charging_forensics')
processed_dir = base_dir / 'processed' / 'stage2'
results_dir = base_dir / 'results'
results_dir.mkdir(exist_ok=True, parents=True)

print("="*80)
print("TASK 1: ATTACK START POINT DETECTION")
print("="*80)

results = {
    'dos': {},
    'recon': {},
    'cryptojacking': {},
    'metadata': {
        'method': 'anomaly_detection',
        'threshold': 'μ_benign + 2σ',
        'window_size': 5.0,
        'confirmation_duration': 10.0,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
}

# ============================================================================
# STEP 1: Load Data
# ============================================================================
print("\n📂 Loading preprocessed data...")
df_host = pd.read_csv(processed_dir / 'host_scaled.csv', low_memory=False)
df_power = pd.read_csv(processed_dir / 'power_scaled.csv', low_memory=False)

# Convert Host time to numeric
df_host['time'] = pd.to_numeric(df_host['time'], errors='coerce')

print(f"✅ Host: {len(df_host):,} records")
print(f"✅ Power: {len(df_power):,} records")

# ============================================================================
# STEP 2: Calculate Benign Baseline
# ============================================================================
print("\n" + "="*80)
print("STEP 2: BENIGN BASELINE CALCULATION")
print("="*80)

# Host Benign baseline
benign_host = df_host[df_host['Scenario'].isin(['Benign', '0'])].copy()
print(f"\n📊 Benign Host: {len(benign_host):,} records")

# Select key feature: cpu-related (most sensitive to attacks)
host_cpu_cols = [col for col in benign_host.columns if 'cpu' in col.lower() or 'sched' in col.lower()]
if len(host_cpu_cols) == 0:
    # Fallback: use any numeric column
    host_cpu_cols = benign_host.select_dtypes(include=[np.number]).columns[:10].tolist()

host_key_feature = host_cpu_cols[0] if len(host_cpu_cols) > 0 else 'time'
print(f"   Key feature: {host_key_feature}")

benign_host_mean = benign_host[host_key_feature].mean()
benign_host_std = benign_host[host_key_feature].std()
benign_host_threshold = benign_host_mean + 2 * benign_host_std

print(f"   μ = {benign_host_mean:.6f}")
print(f"   σ = {benign_host_std:.6f}")
print(f"   Threshold = {benign_host_threshold:.6f}")

# Power Benign baseline
benign_power_labels = ['none', 'Normal', 'Benign', 'Backdoor']
benign_power = df_power[df_power['Attack'].isin(benign_power_labels)].copy()

if len(benign_power) == 0:
    # Use all Power data as baseline
    benign_power = df_power.copy()

print(f"\n📊 Benign Power: {len(benign_power):,} records")

power_key_feature = 'power_mW'
benign_power_mean = benign_power[power_key_feature].mean()
benign_power_std = benign_power[power_key_feature].std()
benign_power_threshold = benign_power_mean + 2 * benign_power_std

print(f"   Key feature: {power_key_feature}")
print(f"   μ = {benign_power_mean:.6f}")
print(f"   σ = {benign_power_std:.6f}")
print(f"   Threshold = {benign_power_threshold:.6f}")

# ============================================================================
# STEP 3: Detect Attack Starts (Each Scenario)
# ============================================================================
print("\n" + "="*80)
print("STEP 3: ATTACK START DETECTION")
print("="*80)

scenarios = {
    'dos': 'DoS',
    'recon': 'Recon',
    'cryptojacking': 'Cryptojacking'
}

for scenario_key, scenario_label in scenarios.items():
    print(f"\n{'='*80}")
    print(f"Scenario: {scenario_label}")
    print(f"{'='*80}")

    results[scenario_key] = {}

    # -------------------------------------------------------------------------
    # Host Layer Detection
    # -------------------------------------------------------------------------
    print(f"\n🔍 Host Layer Detection...")

    attack_host = df_host[df_host['Scenario'] == scenario_label].copy()

    if len(attack_host) > 0:
        attack_host = attack_host.sort_values('time').reset_index(drop=True)

        # Sliding window (5-second)
        window_size = 5.0
        confirmation_duration = 10.0

        attack_detected = False
        t_start = None

        time_values = attack_host['time'].values
        feature_values = attack_host[host_key_feature].values

        for i in range(len(attack_host)):
            window_start = time_values[i]
            window_end = window_start + window_size

            # Get window data
            window_mask = (time_values >= window_start) & (time_values < window_end)
            window_mean = feature_values[window_mask].mean()

            # Check threshold
            if window_mean > benign_host_threshold:
                # Confirmation: check next 10 seconds
                confirm_end = window_start + confirmation_duration
                confirm_mask = (time_values >= window_start) & (time_values < confirm_end)
                confirm_data = feature_values[confirm_mask]

                if len(confirm_data) > 0 and confirm_data.mean() > benign_host_threshold:
                    t_start = window_start
                    attack_detected = True
                    break

        if attack_detected:
            results[scenario_key]['host'] = {
                'timestamp': float(t_start),
                'feature': host_key_feature,
                'value': float(attack_host[attack_host['time'] == t_start][host_key_feature].iloc[0]),
                'threshold': float(benign_host_threshold),
                'confidence': 'high',
                'detection_method': 'sliding_window_2sigma'
            }
            print(f"   ✅ Attack detected at t = {t_start:.1f}s")
            print(f"      Feature: {host_key_feature}")
            print(f"      Value: {results[scenario_key]['host']['value']:.6f}")
        else:
            # Fallback: Use first timestamp
            t_start = time_values[0]
            results[scenario_key]['host'] = {
                'timestamp': float(t_start),
                'feature': host_key_feature,
                'value': float(feature_values[0]),
                'threshold': float(benign_host_threshold),
                'confidence': 'low',
                'detection_method': 'manual_fallback_first_timestamp'
            }
            print(f"   ⚠️ No clear attack start detected")
            print(f"   Using first timestamp: t = {t_start:.1f}s")
    else:
        print(f"   ❌ No {scenario_label} data in Host")
        results[scenario_key]['host'] = None

    # -------------------------------------------------------------------------
    # Network Layer Detection
    # -------------------------------------------------------------------------
    print(f"\n🔍 Network Layer Detection...")

    # Find corresponding network file
    network_files = list(processed_dir.glob(f'*{scenario_key}*.csv'))
    if len(network_files) == 0:
        # Try alternative names
        if scenario_key == 'dos':
            network_files = list(processed_dir.glob('*flood*.csv'))
        elif scenario_key == 'recon':
            network_files = list(processed_dir.glob('*scan*.csv'))
        elif scenario_key == 'cryptojacking':
            network_files = list(processed_dir.glob('*crypto*.csv'))

    if len(network_files) > 0:
        # Use first matching file
        net_file = network_files[0]
        print(f"   Using: {net_file.name}")

        df_network = pd.read_csv(net_file, low_memory=False)

        # Check if has timestamp
        if 'timestamp_normalized' in df_network.columns:
            time_col = 'timestamp_normalized'
        elif 'bidirectional_first_seen_s' in df_network.columns:
            time_col = 'bidirectional_first_seen_s'
        elif 'bidirectional_first_seen_ms' in df_network.columns:
            # Convert ms to s
            df_network['timestamp_s'] = df_network['bidirectional_first_seen_ms'] / 1000.0
            time_col = 'timestamp_s'
        else:
            time_col = None

        if time_col:
            df_network = df_network.sort_values(time_col).reset_index(drop=True)

            # Network packets don't have "benign" - use first timestamp as attack start
            t_start = df_network[time_col].iloc[0]
            packet_count = len(df_network)
            duration = df_network[time_col].iloc[-1] - t_start
            packet_rate = packet_count / duration if duration > 0 else 0

            results[scenario_key]['network'] = {
                'timestamp': float(t_start),
                'feature': 'packet_count',
                'value': int(packet_count),
                'packet_rate': float(packet_rate),
                'duration': float(duration),
                'confidence': 'high',
                'detection_method': 'first_packet_timestamp'
            }
            print(f"   ✅ Network start: t = {t_start:.1f}")
            print(f"      Packets: {packet_count:,}")
            print(f"      Rate: {packet_rate:.1f} pps")
        else:
            print(f"   ⚠️ No timestamp column found")
            results[scenario_key]['network'] = None
    else:
        print(f"   ❌ No Network file found for {scenario_label}")
        results[scenario_key]['network'] = None

    # -------------------------------------------------------------------------
    # Power Layer Detection
    # -------------------------------------------------------------------------
    print(f"\n🔍 Power Layer Detection...")

    # Find Power data for this scenario
    if scenario_key == 'dos':
        attack_power = df_power[df_power['Attack'].str.contains('flood', case=False, na=False)]
    elif scenario_key == 'recon':
        attack_power = df_power[df_power['Attack'].str.contains('scan', case=False, na=False)]
    elif scenario_key == 'cryptojacking':
        attack_power = df_power[df_power['Attack'].str.contains('crypto', case=False, na=False)]
    else:
        attack_power = pd.DataFrame()

    if len(attack_power) > 0:
        attack_power = attack_power.sort_values('timestamp_normalized').reset_index(drop=True)

        # Simple detection: first timestamp where power exceeds threshold
        power_values = attack_power[power_key_feature].values
        time_values = attack_power['timestamp_normalized'].values

        threshold_mask = power_values > benign_power_threshold

        if threshold_mask.sum() > 0:
            first_exceed_idx = np.where(threshold_mask)[0][0]
            t_start = time_values[first_exceed_idx]

            results[scenario_key]['power'] = {
                'timestamp': float(t_start),
                'feature': power_key_feature,
                'value': float(power_values[first_exceed_idx]),
                'threshold': float(benign_power_threshold),
                'confidence': 'medium',
                'detection_method': 'threshold_crossing'
            }
            print(f"   ✅ Power anomaly at t = {t_start:.1f}")
            print(f"      Power: {power_values[first_exceed_idx]:.6f} mW")
        else:
            # No threshold crossing - use first timestamp
            t_start = time_values[0]
            results[scenario_key]['power'] = {
                'timestamp': float(t_start),
                'feature': power_key_feature,
                'value': float(power_values[0]),
                'threshold': float(benign_power_threshold),
                'confidence': 'low',
                'detection_method': 'manual_fallback_first_timestamp'
            }
            print(f"   ⚠️ No clear power spike detected")
            print(f"   Using first timestamp: t = {t_start:.1f}")
    else:
        print(f"   ❌ No Power data found for {scenario_label}")
        results[scenario_key]['power'] = None

# ============================================================================
# STEP 4: Save Results
# ============================================================================
output_file = results_dir / 'attack_start_points.json'
with open(output_file, 'w') as f:
    json.dump(results, f, indent=2)

print("\n" + "="*80)
print("DETECTION SUMMARY")
print("="*80)

for scenario_key, scenario_label in scenarios.items():
    print(f"\n{scenario_label}:")

    for layer in ['host', 'network', 'power']:
        if results[scenario_key].get(layer):
            data = results[scenario_key][layer]
            print(f"   {layer.capitalize()}: t = {data['timestamp']:.1f}, "
                  f"confidence = {data['confidence']}")
        else:
            print(f"   {layer.capitalize()}: ❌ Not detected")

print(f"\n💾 Results saved: {output_file}")

print("\n" + "="*80)
print("✅ TASK 1 COMPLETE")
print("="*80)
