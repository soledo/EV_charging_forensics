#!/usr/bin/env python3
"""
Phase 1 - Task 1-4: Scenario Distribution Analysis
Cross-layer scenario/attack distribution analysis
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime

base_dir = Path('/mnt/d/EV_charging_forensics')
output_dir = base_dir / 'processed' / 'stage1'
output_dir.mkdir(exist_ok=True, parents=True)

print("="*80)
print("PHASE 1 - TASK 1-4: SCENARIO DISTRIBUTION ANALYSIS")
print("="*80)

# Load Host data
print("\n📂 Loading Host data...")
host_path = base_dir / 'CICEVSE2024_Dataset' / 'Host Events' / 'EVSE-B-HPC-Kernel-Events-Combined.csv'
df_host = pd.read_csv(host_path, low_memory=False)
print(f"✅ Loaded {len(df_host):,} records")

# Load Network data (sample first file)
print("\n📂 Loading Network data (sample)...")
network_dir = base_dir / 'CICEVSE2024_Dataset' / 'Network Traffic' / 'EVSE-B' / 'csv'
network_files = sorted(network_dir.glob('*.csv'))
network_scenarios = []
for csv_path in network_files:
    filename = csv_path.stem  # Get filename without extension
    # Extract scenario from filename patterns
    if 'aggressive-scan' in filename:
        network_scenarios.append('Recon')
    elif 'os-fingerprinting' in filename:
        network_scenarios.append('Recon')
    elif 'port-scan' in filename:
        network_scenarios.append('Recon')
    elif 'service-detection' in filename:
        network_scenarios.append('Recon')
    elif 'syn-stealth-scan' in filename:
        network_scenarios.append('Recon')
    elif 'vulnerability-scan' in filename:
        network_scenarios.append('Recon')
    elif 'icmp-flood' in filename or 'syn-flood' in filename or 'udp-flood' in filename:
        network_scenarios.append('DoS')
    elif 'benign' in filename or 'charging' in filename:
        network_scenarios.append('Benign')
print(f"✅ Found {len(network_files)} network files")

# Load Power data
print("\n📂 Loading Power data...")
power_path = base_dir / 'CICEVSE2024_Dataset' / 'Power Consumption' / 'EVSE-B-PowerCombined.csv'
df_power = pd.read_csv(power_path, low_memory=False)
print(f"✅ Loaded {len(df_power):,} records")

# Analysis
print("\n" + "="*80)
print("SCENARIO DISTRIBUTION ANALYSIS")
print("="*80)

analysis = {
    'host': {},
    'network': {},
    'power': {},
    'comparison': {}
}

# Host scenario distribution
print("\n📊 HOST LAYER (Scenario column):")
if 'Scenario' in df_host.columns:
    host_scenarios = df_host['Scenario'].value_counts().to_dict()
    analysis['host'] = {
        'total_records': int(len(df_host)),
        'scenarios': {k: int(v) for k, v in host_scenarios.items()}
    }

    for scenario, count in sorted(host_scenarios.items(), key=lambda x: x[1], reverse=True):
        pct = count / len(df_host) * 100
        print(f"   {scenario:30s}: {count:6,} ({pct:6.2f}%)")

# Network scenario distribution (inferred from filenames)
print("\n📊 NETWORK LAYER (inferred from filenames):")
network_scenario_counts = {}
for scenario in network_scenarios:
    network_scenario_counts[scenario] = network_scenario_counts.get(scenario, 0) + 1

analysis['network'] = {
    'total_files': len(network_files),
    'scenarios': network_scenario_counts
}

for scenario, count in sorted(network_scenario_counts.items(), key=lambda x: x[1], reverse=True):
    pct = count / len(network_files) * 100
    print(f"   {scenario:30s}: {count:6,} files ({pct:6.2f}%)")

# Power attack distribution
print("\n📊 POWER LAYER (Attack column):")
if 'Attack' in df_power.columns:
    power_attacks = df_power['Attack'].value_counts().to_dict()
    analysis['power'] = {
        'total_records': int(len(df_power)),
        'attacks': {k: int(v) for k, v in power_attacks.items()}
    }

    for attack, count in sorted(power_attacks.items(), key=lambda x: x[1], reverse=True):
        pct = count / len(df_power) * 100
        print(f"   {attack:30s}: {count:6,} ({pct:6.2f}%)")

# Cross-layer comparison
print("\n" + "="*80)
print("CROSS-LAYER COMPARISON")
print("="*80)

# Identify common scenarios
host_scenario_set = set(analysis['host']['scenarios'].keys()) if 'scenarios' in analysis['host'] else set()
network_scenario_set = set(analysis['network']['scenarios'].keys())
power_scenario_set = set(analysis['power']['attacks'].keys()) if 'attacks' in analysis['power'] else set()

print("\n🔍 Common Scenario/Attack Categories:")
print(f"   Host scenarios: {sorted(host_scenario_set)}")
print(f"   Network scenarios: {sorted(network_scenario_set)}")
print(f"   Power attacks: {sorted(power_scenario_set)}")

# Map Power attacks to Host/Network scenarios
power_to_scenario_map = {
    'DoS': 'DoS',
    'Dos': 'DoS',
    'Reconnaissance': 'Recon',
    'Recon': 'Recon',
    'Crypto': 'Cryptojacking',
    'Cryptojacking': 'Cryptojacking',
    'Normal': 'Benign',
    'Benign': 'Benign'
}

print("\n🔄 Scenario Mapping:")
print("   DoS/Dos → DoS")
print("   Reconnaissance/Recon → Recon")
print("   Crypto/Cryptojacking → Cryptojacking")
print("   Normal/Benign → Benign")

# Unified scenario categories
unified_scenarios = {
    'DoS': {
        'host': analysis['host']['scenarios'].get('DoS', 0),
        'network': analysis['network']['scenarios'].get('DoS', 0),
        'power': sum([v for k, v in analysis['power'].get('attacks', {}).items() if k in ['DoS', 'Dos']])
    },
    'Recon': {
        'host': analysis['host']['scenarios'].get('Recon', 0),
        'network': analysis['network']['scenarios'].get('Recon', 0),
        'power': sum([v for k, v in analysis['power'].get('attacks', {}).items() if k in ['Reconnaissance', 'Recon']])
    },
    'Cryptojacking': {
        'host': analysis['host']['scenarios'].get('Cryptojacking', 0),
        'network': 0,  # No Crypto in Network files
        'power': sum([v for k, v in analysis['power'].get('attacks', {}).items() if k in ['Crypto', 'Cryptojacking']])
    },
    'Benign': {
        'host': analysis['host']['scenarios'].get('Benign', 0) + analysis['host']['scenarios'].get('0', 0),
        'network': analysis['network']['scenarios'].get('Benign', 0),
        'power': sum([v for k, v in analysis['power'].get('attacks', {}).items() if k in ['Normal', 'Benign']])
    }
}

analysis['comparison']['unified_scenarios'] = unified_scenarios

print("\n📊 Unified Scenario Distribution:")
print(f"\n{'Scenario':<15} {'Host':>10} {'Network':>10} {'Power':>10}")
print("-" * 50)
for scenario, counts in unified_scenarios.items():
    print(f"{scenario:<15} {counts['host']:>10,} {counts['network']:>10,} {counts['power']:>10,}")

# Attack-Adaptive Layer Selection Analysis
print("\n" + "="*80)
print("ATTACK-ADAPTIVE LAYER SELECTION ANALYSIS")
print("="*80)

print("\n🎯 Network-Originated Attacks (Host + Network + Power):")
print("   - DoS: Network traffic patterns essential")
print("   - Recon: Network scanning patterns essential")

print("\n🎯 Host-Originated Attacks (Host + Power only):")
print("   - Cryptojacking: CPU-intensive, no network signature")
print("   - Benign: Normal operations")

network_originated_total = (
    unified_scenarios['DoS']['host'] +
    unified_scenarios['Recon']['host']
)

host_originated_total = (
    unified_scenarios['Cryptojacking']['host'] +
    unified_scenarios['Benign']['host']
)

analysis['comparison']['attack_adaptive'] = {
    'network_originated': {
        'scenarios': ['DoS', 'Recon'],
        'total_host_records': int(network_originated_total)
    },
    'host_originated': {
        'scenarios': ['Cryptojacking', 'Benign'],
        'total_host_records': int(host_originated_total)
    }
}

print(f"\n📊 Attack-Adaptive Distribution:")
print(f"   Network-Originated: {network_originated_total:,} Host records ({network_originated_total / len(df_host) * 100:.2f}%)")
print(f"   Host-Originated: {host_originated_total:,} Host records ({host_originated_total / len(df_host) * 100:.2f}%)")

# Save analysis
analysis['analysis_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

output_file = output_dir / 'scenario_distribution_analysis.json'
with open(output_file, 'w') as f:
    json.dump(analysis, f, indent=2, default=str)

print("\n" + "="*80)
print("✅ TASK 1-4 COMPLETE")
print("="*80)
print(f"\n💾 Analysis saved: {output_file}")
print(f"\n📊 Key Findings:")
print(f"   - Host Records: {len(df_host):,}")
print(f"   - Network Files: {len(network_files)}")
print(f"   - Power Records: {len(df_power):,}")
print(f"   - Network-Originated Attacks: {network_originated_total:,} ({network_originated_total / len(df_host) * 100:.2f}%)")
print(f"   - Host-Originated Attacks: {host_originated_total:,} ({host_originated_total / len(df_host) * 100:.2f}%)")

print("\n" + "="*80)
print("✅ PHASE 1: DATA DISCOVERY & UNDERSTANDING COMPLETE")
print("="*80)
print("\nℹ️  Ready to proceed to Phase 2: Preprocessing & Normalization")
