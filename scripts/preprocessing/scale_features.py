#!/usr/bin/env python3
"""
Phase 2 - Task 2-4: Feature Scaling
Apply StandardScaler to Host/Network, MinMaxScaler to Power
"""

import pandas as pd
import numpy as np
import json
import pickle
from pathlib import Path
from datetime import datetime
from sklearn.preprocessing import StandardScaler, MinMaxScaler

base_dir = Path('/mnt/d/EV_charging_forensics')
input_dir = base_dir / 'processed' / 'stage2'
output_dir = base_dir / 'processed' / 'stage2'
scaler_dir = base_dir / 'models' / 'scalers'
scaler_dir.mkdir(exist_ok=True, parents=True)

print("="*80)
print("PHASE 2 - TASK 2-4: FEATURE SCALING")
print("="*80)

scaling_report = {
    'host': {},
    'network': {},
    'power': {},
    'scaling_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
}

# ============================================================================
# HOST DATA SCALING (StandardScaler)
# ============================================================================
print("\n" + "="*80)
print("HOST DATA SCALING (StandardScaler)")
print("="*80)

print("\n📂 Loading Host data...")
df_host = pd.read_csv(input_dir / 'host_cleaned.csv', low_memory=False)
print(f"✅ Loaded {len(df_host):,} records, {len(df_host.columns)} columns")

# Identify feature columns (exclude metadata)
metadata_cols = ['time', 'State', 'Attack', 'Scenario', 'Label', 'interface', 'timestamp_normalized']
feature_cols = [col for col in df_host.columns if col not in metadata_cols]

print(f"\n📊 Feature columns: {len(feature_cols)}")

# Separate features and metadata
X_host = df_host[feature_cols].values
metadata_host = df_host[metadata_cols]

print(f"\n🔄 Applying StandardScaler...")
print(f"   Formula: (X - mean) / std")

scaler_host = StandardScaler()
X_host_scaled = scaler_host.fit_transform(X_host)

print(f"   ✅ Scaled {X_host_scaled.shape[1]} features")
print(f"   Mean (after): {X_host_scaled.mean():.6f}")
print(f"   Std (after): {X_host_scaled.std():.6f}")

# Create scaled DataFrame
df_host_scaled = pd.DataFrame(X_host_scaled, columns=feature_cols)
df_host_scaled = pd.concat([metadata_host.reset_index(drop=True), df_host_scaled], axis=1)

scaling_report['host'] = {
    'total_features': len(feature_cols),
    'scaler_type': 'StandardScaler',
    'mean_before': float(X_host.mean()),
    'std_before': float(X_host.std()),
    'mean_after': float(X_host_scaled.mean()),
    'std_after': float(X_host_scaled.std())
}

# Save scaler
scaler_path = scaler_dir / 'host_scaler.pkl'
with open(scaler_path, 'wb') as f:
    pickle.dump(scaler_host, f)
print(f"\n💾 Scaler saved: {scaler_path}")

# Save scaled data
host_output = output_dir / 'host_scaled.csv'
df_host_scaled.to_csv(host_output, index=False)
print(f"💾 Data saved: {host_output}")

# ============================================================================
# NETWORK DATA SCALING (StandardScaler)
# ============================================================================
print("\n" + "="*80)
print("NETWORK DATA SCALING (StandardScaler)")
print("="*80)

network_files = sorted(input_dir.glob('EVSE-B-*_cleaned.csv'))
print(f"\n📂 Processing {len(network_files)} network files...")

# Use first file to determine feature columns
df_net_sample = pd.read_csv(network_files[0], low_memory=False)

# Identify feature columns
net_metadata_cols = ['id', 'expiration_id', 'src_ip', 'src_mac', 'src_oui',
                      'dst_ip', 'dst_mac', 'dst_oui', 'protocol',
                      'requested_server_name', 'user_agent', 'content_type',
                      'client_fingerprint', 'server_fingerprint', 'timestamp_normalized']
net_feature_cols = [col for col in df_net_sample.columns if col not in net_metadata_cols]

print(f"📊 Network feature columns: {len(net_feature_cols)}")

# Collect all data to fit scaler
print(f"\n🔄 Collecting data from all files for scaler fitting...")
all_network_data = []
for csv_path in network_files[:5]:  # Use first 5 files for fitting
    df_net = pd.read_csv(csv_path, low_memory=False)
    all_network_data.append(df_net[net_feature_cols].values)

X_net_combined = np.vstack(all_network_data)
print(f"   ✅ Collected {X_net_combined.shape[0]:,} samples for fitting")

# Fit scaler
print(f"\n🔄 Fitting StandardScaler on combined network data...")
scaler_network = StandardScaler()
scaler_network.fit(X_net_combined)

print(f"   ✅ Scaler fitted")
print(f"   Mean: {scaler_network.mean_.mean():.6f}")
print(f"   Std: {scaler_network.scale_.mean():.6f}")

# Save scaler
scaler_net_path = scaler_dir / 'network_scaler.pkl'
with open(scaler_net_path, 'wb') as f:
    pickle.dump(scaler_network, f)
print(f"\n💾 Scaler saved: {scaler_net_path}")

# Transform all files
print(f"\n🔄 Transforming all network files...")
network_scaling_stats = []

for i, csv_path in enumerate(network_files, 1):
    if i <= 5 or i % 10 == 0:
        print(f"\n📄 File {i}/{len(network_files)}: {csv_path.name}")

    df_net = pd.read_csv(csv_path, low_memory=False)

    # Separate features and metadata
    X_net = df_net[net_feature_cols].values
    metadata_net = df_net[net_metadata_cols]

    # Transform
    X_net_scaled = scaler_network.transform(X_net)

    # Create scaled DataFrame
    df_net_scaled = pd.DataFrame(X_net_scaled, columns=net_feature_cols)
    df_net_scaled = pd.concat([metadata_net.reset_index(drop=True), df_net_scaled], axis=1)

    network_scaling_stats.append({
        'filename': csv_path.name,
        'records': int(len(df_net)),
        'features_scaled': len(net_feature_cols)
    })

    # Save
    output_path = output_dir / csv_path.name.replace('_cleaned', '_scaled')
    df_net_scaled.to_csv(output_path, index=False)

print(f"\n✅ All network files scaled and saved")

scaling_report['network'] = {
    'total_files': len(network_files),
    'total_features': len(net_feature_cols),
    'scaler_type': 'StandardScaler',
    'files': network_scaling_stats,
    'scaler_mean': float(scaler_network.mean_.mean()),
    'scaler_std': float(scaler_network.scale_.mean())
}

# ============================================================================
# POWER DATA SCALING (MinMaxScaler)
# ============================================================================
print("\n" + "="*80)
print("POWER DATA SCALING (MinMaxScaler)")
print("="*80)

print("\n📂 Loading Power data...")
df_power = pd.read_csv(input_dir / 'power_cleaned.csv', low_memory=False)
print(f"✅ Loaded {len(df_power):,} records, {len(df_power.columns)} columns")

# Identify feature columns
power_metadata_cols = ['time', 'State', 'Attack', 'Attack-Group', 'Label', 'interface',
                        'timestamp', 'unix_timestamp', 'timestamp_normalized']
power_feature_cols = ['shunt_voltage', 'bus_voltage_V', 'current_mA', 'power_mW']

print(f"\n📊 Power feature columns: {len(power_feature_cols)}")

# Separate features and metadata
X_power = df_power[power_feature_cols].values
metadata_power = df_power[[col for col in power_metadata_cols if col in df_power.columns]]

print(f"\n🔄 Applying MinMaxScaler...")
print(f"   Formula: (X - min) / (max - min)")

scaler_power = MinMaxScaler()
X_power_scaled = scaler_power.fit_transform(X_power)

print(f"   ✅ Scaled {X_power_scaled.shape[1]} features")
print(f"   Min (after): {X_power_scaled.min():.6f}")
print(f"   Max (after): {X_power_scaled.max():.6f}")
print(f"   Range: [0, 1]")

# Create scaled DataFrame
df_power_scaled = pd.DataFrame(X_power_scaled, columns=power_feature_cols)
df_power_scaled = pd.concat([metadata_power.reset_index(drop=True), df_power_scaled], axis=1)

scaling_report['power'] = {
    'total_features': len(power_feature_cols),
    'scaler_type': 'MinMaxScaler',
    'min_before': float(X_power.min()),
    'max_before': float(X_power.max()),
    'min_after': float(X_power_scaled.min()),
    'max_after': float(X_power_scaled.max())
}

# Save scaler
scaler_power_path = scaler_dir / 'power_scaler.pkl'
with open(scaler_power_path, 'wb') as f:
    pickle.dump(scaler_power, f)
print(f"\n💾 Scaler saved: {scaler_power_path}")

# Save scaled data
power_output = output_dir / 'power_scaled.csv'
df_power_scaled.to_csv(power_output, index=False)
print(f"💾 Data saved: {power_output}")

# ============================================================================
# SAVE SCALING REPORT
# ============================================================================
report_file = output_dir / 'scaling_report.json'
with open(report_file, 'w') as f:
    json.dump(scaling_report, f, indent=2, default=str)

print("\n" + "="*80)
print("✅ TASK 2-4 COMPLETE")
print("="*80)
print(f"\n💾 Scaling report saved: {report_file}")
print(f"\n📊 Summary:")
print(f"   - Host: {scaling_report['host']['total_features']} features (StandardScaler)")
print(f"   - Network: {scaling_report['network']['total_features']} features (StandardScaler)")
print(f"   - Power: {scaling_report['power']['total_features']} features (MinMaxScaler)")
print(f"   - Scalers saved to: {scaler_dir}")

print("\n" + "="*80)
print("✅ PHASE 2: PREPROCESSING & NORMALIZATION COMPLETE")
print("="*80)
print("\nℹ️  Ready to proceed to Phase 3: Time Anchor Extraction (CRITICAL)")
