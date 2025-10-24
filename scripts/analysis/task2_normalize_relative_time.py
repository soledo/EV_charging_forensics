#!/usr/bin/env python3
"""
Task 2: Relative Time Normalization
Normalize each layer to attack-relative time (T_attack = 0)
Extract 0-60s window and resample to 1-second intervals
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime

base_dir = Path('/mnt/d/EV_charging_forensics')
processed_dir = base_dir / 'processed' / 'stage2'
results_dir = base_dir / 'results'
normalized_dir = results_dir / 'normalized_timelines'

# Create output directories
for scenario in ['dos', 'recon', 'cryptojacking', 'benign']:
    (normalized_dir / scenario).mkdir(exist_ok=True, parents=True)

print("="*80)
print("TASK 2: RELATIVE TIME NORMALIZATION")
print("="*80)

# Load attack start points from Task 1
with open(results_dir / 'attack_start_points.json', 'r') as f:
    attack_starts = json.load(f)

# Load data
print("\n📂 Loading data...")
df_host = pd.read_csv(processed_dir / 'host_scaled.csv', low_memory=False)
df_power = pd.read_csv(processed_dir / 'power_scaled.csv', low_memory=False)

df_host['time'] = pd.to_numeric(df_host['time'], errors='coerce')

print(f"✅ Host: {len(df_host):,}")
print(f"✅ Power: {len(df_power):,}")

# ============================================================================
# Process each scenario
# ============================================================================

scenarios = {
    'dos': {'label': 'DoS', 'duration': 60},
    'recon': {'label': 'Recon', 'duration': 60},
    'cryptojacking': {'label': 'Cryptojacking', 'duration': 60}
}

for scenario_key, scenario_info in scenarios.items():
    print(f"\n{'='*80}")
    print(f"Scenario: {scenario_info['label']}")
    print(f"{'='*80}")

    scenario_dir = normalized_dir / scenario_key

    # -------------------------------------------------------------------------
    # Host Layer
    # -------------------------------------------------------------------------
    print(f"\n🔄 Host Layer...")

    if attack_starts[scenario_key].get('host'):
        t_start = attack_starts[scenario_key]['host']['timestamp']

        # Extract scenario data
        host_data = df_host[df_host['Scenario'] == scenario_info['label']].copy()

        if len(host_data) > 0:
            # Create relative time
            host_data['time_rel'] = host_data['time'] - t_start

            # Filter 0-60s window
            host_window = host_data[
                (host_data['time_rel'] >= 0) &
                (host_data['time_rel'] <= scenario_info['duration'])
            ].copy()

            print(f"   Records in window: {len(host_window):,}")

            if len(host_window) > 0:
                # Select features (exclude metadata)
                meta_cols = ['time', 'time_rel', 'State', 'Attack', 'Scenario', 'Label',
                            'interface', 'timestamp_normalized', 'Unnamed: 0']
                feature_cols = [col for col in host_window.columns if col not in meta_cols
                               and not col.startswith('net_') and not col.startswith('power_')]

                # Resample to 1-second intervals
                host_window = host_window.sort_values('time_rel')
                host_window['time_sec'] = host_window['time_rel'].round().astype(int)

                # Group by second and take mean
                host_1s = host_window.groupby('time_sec')[feature_cols].mean().reset_index()
                host_1s = host_1s.rename(columns={'time_sec': 'time_rel'})

                # Fill missing seconds (0-60)
                all_seconds = pd.DataFrame({'time_rel': range(0, scenario_info['duration'] + 1)})
                host_1s = all_seconds.merge(host_1s, on='time_rel', how='left')

                # Forward fill (max 5 seconds)
                host_1s = host_1s.fillna(method='ffill', limit=5)

                # Save
                output_file = scenario_dir / 'host_relative.csv'
                host_1s.to_csv(output_file, index=False)

                print(f"   ✅ Saved: {output_file.name}")
                print(f"      Shape: {host_1s.shape[0]} rows × {host_1s.shape[1]} columns")
                print(f"      Missing rate: {host_1s.isnull().sum().sum() / (host_1s.shape[0] * host_1s.shape[1]) * 100:.2f}%")
            else:
                print(f"   ⚠️ No data in 0-60s window")
        else:
            print(f"   ⚠️ No {scenario_info['label']} data in Host")
    else:
        print(f"   ❌ No attack start detected")

    # -------------------------------------------------------------------------
    # Network Layer
    # -------------------------------------------------------------------------
    print(f"\n🔄 Network Layer...")

    if attack_starts[scenario_key].get('network'):
        t_start = attack_starts[scenario_key]['network']['timestamp']

        # Find network file
        if scenario_key == 'dos':
            network_files = list(processed_dir.glob('*flood*.csv'))
        elif scenario_key == 'recon':
            network_files = list(processed_dir.glob('*scan*.csv'))
        elif scenario_key == 'cryptojacking':
            network_files = list(processed_dir.glob('*crypto*.csv'))
        else:
            network_files = []

        if len(network_files) > 0:
            net_file = network_files[0]
            df_network = pd.read_csv(net_file, low_memory=False)

            # Get timestamp column
            if 'bidirectional_first_seen_ms' in df_network.columns:
                df_network['timestamp_s'] = df_network['bidirectional_first_seen_ms'] / 1000.0
                time_col = 'timestamp_s'
            elif 'timestamp_normalized' in df_network.columns:
                time_col = 'timestamp_normalized'
            else:
                time_col = None

            if time_col:
                # Create relative time
                df_network['time_rel'] = df_network[time_col] - t_start

                # Filter 0-60s window
                net_window = df_network[
                    (df_network['time_rel'] >= 0) &
                    (df_network['time_rel'] <= scenario_info['duration'])
                ].copy()

                print(f"   Records in window: {len(net_window):,}")

                if len(net_window) > 0:
                    # Select key features
                    feature_cols = ['bidirectional_packets', 'bidirectional_bytes',
                                   'src2dst_packets', 'dst2src_packets']
                    feature_cols = [col for col in feature_cols if col in net_window.columns]

                    if len(feature_cols) > 0:
                        # Resample to 1-second
                        net_window['time_sec'] = net_window['time_rel'].round().astype(int)
                        net_1s = net_window.groupby('time_sec')[feature_cols].sum().reset_index()
                        net_1s = net_1s.rename(columns={'time_sec': 'time_rel'})

                        # Add packet rate
                        if 'bidirectional_packets' in net_1s.columns:
                            net_1s['packet_rate'] = net_1s['bidirectional_packets']

                        # Fill missing seconds
                        all_seconds = pd.DataFrame({'time_rel': range(0, scenario_info['duration'] + 1)})
                        net_1s = all_seconds.merge(net_1s, on='time_rel', how='left')
                        net_1s = net_1s.fillna(0)  # Network: no packets = 0

                        # Save
                        output_file = scenario_dir / 'network_relative.csv'
                        net_1s.to_csv(output_file, index=False)

                        print(f"   ✅ Saved: {output_file.name}")
                        print(f"      Shape: {net_1s.shape[0]} rows × {net_1s.shape[1]} columns")
                    else:
                        print(f"   ⚠️ No suitable features found")
                else:
                    print(f"   ⚠️ No data in 0-60s window")
            else:
                print(f"   ⚠️ No timestamp column")
        else:
            print(f"   ⚠️ No network file found")
    else:
        print(f"   ❌ No attack start detected")

    # -------------------------------------------------------------------------
    # Power Layer
    # -------------------------------------------------------------------------
    print(f"\n🔄 Power Layer...")

    if attack_starts[scenario_key].get('power'):
        t_start = attack_starts[scenario_key]['power']['timestamp']

        # Get power data for this scenario
        if scenario_key == 'dos':
            power_data = df_power[df_power['Attack'].str.contains('flood', case=False, na=False)].copy()
        elif scenario_key == 'recon':
            power_data = df_power[df_power['Attack'].str.contains('scan', case=False, na=False)].copy()
        elif scenario_key == 'cryptojacking':
            power_data = df_power[df_power['Attack'].str.contains('crypto', case=False, na=False)].copy()
        else:
            power_data = pd.DataFrame()

        if len(power_data) > 0:
            # Create relative time
            power_data['time_rel'] = power_data['timestamp_normalized'] - t_start

            # Filter 0-60s window
            power_window = power_data[
                (power_data['time_rel'] >= 0) &
                (power_data['time_rel'] <= scenario_info['duration'])
            ].copy()

            print(f"   Records in window: {len(power_window):,}")

            if len(power_window) > 0:
                # Select features
                feature_cols = ['power_mW', 'bus_voltage_V', 'current_mA']
                feature_cols = [col for col in feature_cols if col in power_window.columns]

                # Resample to 1-second
                power_window['time_sec'] = power_window['time_rel'].round().astype(int)
                power_1s = power_window.groupby('time_sec')[feature_cols].mean().reset_index()
                power_1s = power_1s.rename(columns={'time_sec': 'time_rel'})

                # Fill missing seconds
                all_seconds = pd.DataFrame({'time_rel': range(0, scenario_info['duration'] + 1)})
                power_1s = all_seconds.merge(power_1s, on='time_rel', how='left')
                power_1s = power_1s.fillna(method='ffill', limit=5)

                # Save
                output_file = scenario_dir / 'power_relative.csv'
                power_1s.to_csv(output_file, index=False)

                print(f"   ✅ Saved: {output_file.name}")
                print(f"      Shape: {power_1s.shape[0]} rows × {power_1s.shape[1]} columns")
                print(f"      Missing rate: {power_1s.isnull().sum().sum() / (power_1s.shape[0] * power_1s.shape[1]) * 100:.2f}%")
            else:
                print(f"   ⚠️ No data in 0-60s window")
        else:
            print(f"   ⚠️ No power data for {scenario_info['label']}")
    else:
        print(f"   ❌ No attack start detected")

# ============================================================================
# Process Benign (reference baseline)
# ============================================================================
print(f"\n{'='*80}")
print(f"Scenario: Benign (Reference)")
print(f"{'='*80}")

benign_dir = normalized_dir / 'benign'

# Host Benign
print(f"\n🔄 Host Benign...")
benign_host = df_host[df_host['Scenario'].isin(['Benign', '0'])].copy()

if len(benign_host) > 0:
    # Take first 60 seconds
    benign_host = benign_host.sort_values('time').head(60).copy()
    benign_host['time_rel'] = range(len(benign_host))

    meta_cols = ['time', 'time_rel', 'State', 'Attack', 'Scenario', 'Label',
                'interface', 'timestamp_normalized', 'Unnamed: 0']
    feature_cols = [col for col in benign_host.columns if col not in meta_cols
                   and not col.startswith('net_') and not col.startswith('power_')]

    benign_host_1s = benign_host[['time_rel'] + feature_cols].copy()

    output_file = benign_dir / 'host_relative.csv'
    benign_host_1s.to_csv(output_file, index=False)
    print(f"   ✅ Saved: {output_file.name} ({benign_host_1s.shape[0]} rows)")

# Power Benign
print(f"\n🔄 Power Benign...")
benign_power_labels = ['none', 'Normal', 'Benign', 'Backdoor']
benign_power = df_power[df_power['Attack'].isin(benign_power_labels)].copy()

if len(benign_power) > 0:
    benign_power = benign_power.sort_values('timestamp_normalized').head(60).copy()
    benign_power['time_rel'] = range(len(benign_power))

    feature_cols = ['power_mW', 'bus_voltage_V', 'current_mA']
    feature_cols = [col for col in feature_cols if col in benign_power.columns]

    benign_power_1s = benign_power[['time_rel'] + feature_cols].copy()

    output_file = benign_dir / 'power_relative.csv'
    benign_power_1s.to_csv(output_file, index=False)
    print(f"   ✅ Saved: {output_file.name} ({benign_power_1s.shape[0]} rows)")

print("\n" + "="*80)
print("✅ TASK 2 COMPLETE")
print("="*80)
print(f"\n📂 Normalized timelines saved to: {normalized_dir}")
