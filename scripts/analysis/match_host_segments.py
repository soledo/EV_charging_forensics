#!/usr/bin/env python3
"""
Phase 3 - Task 3-3: Host Segment Matching
Match Network windows to corresponding Host segments using pattern-based alignment
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime
from scipy.stats import pearsonr

base_dir = Path('/mnt/d/EV_charging_forensics')
network_dir = base_dir / 'processed' / 'stage2'
host_path = base_dir / 'processed' / 'stage2' / 'host_scaled.csv'
power_path = base_dir / 'processed' / 'stage2' / 'power_scaled.csv'
stage3_dir = base_dir / 'processed' / 'stage3'
output_dir = base_dir / 'processed' / 'stage3'
output_dir.mkdir(exist_ok=True, parents=True)

print("="*80)
print("PHASE 3 - TASK 3-3: HOST SEGMENT MATCHING")
print("="*80)

# Load discovered windows
print("\n📂 Loading discovered windows...")
with open(stage3_dir / 'recon_windows.json', 'r') as f:
    recon_data = json.load(f)
    recon_window = recon_data['selected_window']

with open(stage3_dir / 'dos_windows.json', 'r') as f:
    dos_data = json.load(f)
    dos_window = dos_data['selected_window']

print(f"✅ Loaded window information")
print(f"   Recon window: {recon_window['file']}")
print(f"   DoS window: {dos_window['file']}")

# Load Host data
print("\n📂 Loading Host data...")
df_host = pd.read_csv(host_path, low_memory=False)
print(f"✅ Loaded {len(df_host):,} records")

# ============================================================================
# STEP 1: Match Recon Window to Host Recon Segment
# ============================================================================
print("\n" + "="*80)
print("STEP 1: RECON WINDOW → HOST SEGMENT MATCHING")
print("="*80)

# Get Host Recon segment
recon_host = df_host[df_host['Scenario'] == 'Recon'].copy().sort_values('timestamp_normalized')
print(f"\n📊 Host Recon segment:")
print(f"   Records: {len(recon_host):,}")
print(f"   Time range: {recon_host['timestamp_normalized'].min():.3f} - {recon_host['timestamp_normalized'].max():.3f}")

# Load Recon network window
recon_net_file = network_dir / recon_window['file']
df_recon_net = pd.read_csv(recon_net_file, low_memory=False)
df_recon_net = df_recon_net.sort_values('timestamp_normalized')

# Extract specific window
window_start = recon_window['start_time']
window_end = recon_window['end_time']
recon_net_window = df_recon_net[
    (df_recon_net['timestamp_normalized'] >= window_start) &
    (df_recon_net['timestamp_normalized'] < window_end)
].copy()

print(f"\n📊 Network Recon window:")
print(f"   Records: {len(recon_net_window):,}")
print(f"   Time range: {window_start:.3f} - {window_end:.3f}")

# Pattern-based matching strategy:
# Use entire Host Recon segment (not trying to find exact timestamp match)
# This is because timestamps are from different recording systems
print(f"\n🔄 Pattern-Based Alignment Strategy:")
print(f"   - Network window represents Recon attack pattern")
print(f"   - Corresponding Host segment: ALL Recon records")
print(f"   - Alignment: Based on Scenario label matching")

recon_alignment = {
    'scenario': 'Recon',
    'network_window': {
        'file': recon_window['file'],
        'start_time': float(window_start),
        'end_time': float(window_end),
        'records': int(len(recon_net_window)),
        'duration': float(window_end - window_start)
    },
    'host_segment': {
        'start_time': float(recon_host['timestamp_normalized'].min()),
        'end_time': float(recon_host['timestamp_normalized'].max()),
        'records': int(len(recon_host)),
        'duration': float(recon_host['timestamp_normalized'].max() - recon_host['timestamp_normalized'].min())
    },
    'alignment_method': 'pattern_based_scenario_matching'
}

print(f"\n✅ Recon Alignment:")
print(f"   Network: {recon_alignment['network_window']['records']:,} records over {recon_alignment['network_window']['duration']:.1f}s")
print(f"   Host: {recon_alignment['host_segment']['records']:,} records over {recon_alignment['host_segment']['duration']:.1f}s")

# ============================================================================
# STEP 2: Match DoS Window to Host DoS Segment
# ============================================================================
print("\n" + "="*80)
print("STEP 2: DOS WINDOW → HOST SEGMENT MATCHING")
print("="*80)

# Get Host DoS segment
dos_host = df_host[df_host['Scenario'] == 'DoS'].copy().sort_values('timestamp_normalized')
print(f"\n📊 Host DoS segment:")
print(f"   Records: {len(dos_host):,}")
print(f"   Time range: {dos_host['timestamp_normalized'].min():.3f} - {dos_host['timestamp_normalized'].max():.3f}")

# Load DoS network window
dos_net_file = network_dir / dos_window['file']
df_dos_net = pd.read_csv(dos_net_file, low_memory=False)
df_dos_net = df_dos_net.sort_values('timestamp_normalized')

# Extract specific window
window_start = dos_window['start_time']
window_end = dos_window['end_time']
dos_net_window = df_dos_net[
    (df_dos_net['timestamp_normalized'] >= window_start) &
    (df_dos_net['timestamp_normalized'] < window_end)
].copy()

print(f"\n📊 Network DoS window:")
print(f"   Records: {len(dos_net_window):,}")
print(f"   Time range: {window_start:.3f} - {window_end:.3f}")

print(f"\n🔄 Pattern-Based Alignment Strategy:")
print(f"   - Network window represents DoS attack pattern")
print(f"   - Corresponding Host segment: ALL DoS records")
print(f"   - Alignment: Based on Scenario label matching")

dos_alignment = {
    'scenario': 'DoS',
    'network_window': {
        'file': dos_window['file'],
        'start_time': float(window_start),
        'end_time': float(window_end),
        'records': int(len(dos_net_window)),
        'duration': float(window_end - window_start)
    },
    'host_segment': {
        'start_time': float(dos_host['timestamp_normalized'].min()),
        'end_time': float(dos_host['timestamp_normalized'].max()),
        'records': int(len(dos_host)),
        'duration': float(dos_host['timestamp_normalized'].max() - dos_host['timestamp_normalized'].min())
    },
    'alignment_method': 'pattern_based_scenario_matching'
}

print(f"\n✅ DoS Alignment:")
print(f"   Network: {dos_alignment['network_window']['records']:,} records over {dos_alignment['network_window']['duration']:.1f}s")
print(f"   Host: {dos_alignment['host_segment']['records']:,} records over {dos_alignment['host_segment']['duration']:.1f}s")

# ============================================================================
# STEP 3: Power Consumption Validation
# ============================================================================
print("\n" + "="*80)
print("STEP 3: POWER CONSUMPTION VALIDATION")
print("="*80)

print("\n📂 Loading Power data...")
df_power = pd.read_csv(power_path, low_memory=False)

# Recon power validation
recon_power_attacks = ['vuln-scan', 'syn-stealth']
recon_power = df_power[df_power['Attack'].isin(recon_power_attacks)].copy()

if len(recon_power) > 0:
    recon_power_mean = recon_power['power_mW'].mean()
    recon_power_std = recon_power['power_mW'].std()
    print(f"\n📊 Recon Power Characteristics:")
    print(f"   Records: {len(recon_power):,}")
    print(f"   Mean power: {recon_power_mean:.6f} (normalized)")
    print(f"   Std power: {recon_power_std:.6f}")

    recon_alignment['power_validation'] = {
        'records': int(len(recon_power)),
        'mean_power': float(recon_power_mean),
        'std_power': float(recon_power_std)
    }

# DoS power validation
dos_power_keywords = ['flood']
dos_power = df_power[df_power['Attack'].str.contains('|'.join(dos_power_keywords), case=False, na=False)].copy()

if len(dos_power) > 0:
    dos_power_mean = dos_power['power_mW'].mean()
    dos_power_std = dos_power['power_mW'].std()
    print(f"\n📊 DoS Power Characteristics:")
    print(f"   Records: {len(dos_power):,}")
    print(f"   Mean power: {dos_power_mean:.6f} (normalized)")
    print(f"   Std power: {dos_power_std:.6f}")

    dos_alignment['power_validation'] = {
        'records': int(len(dos_power)),
        'mean_power': float(dos_power_mean),
        'std_power': float(dos_power_std)
    }

# Power difference between Recon and DoS
if len(recon_power) > 0 and len(dos_power) > 0:
    power_diff_pct = abs(dos_power_mean - recon_power_mean) / max(recon_power_mean, dos_power_mean) * 100
    print(f"\n📊 Power Consumption Difference:")
    print(f"   Recon vs DoS: {power_diff_pct:.2f}%")
    print(f"   {'✅ Significant difference' if power_diff_pct > 5 else '⚠️ Small difference'}")

# ============================================================================
# SAVE ALIGNMENT RESULTS
# ============================================================================
alignment_results = {
    'recon_alignment': recon_alignment,
    'dos_alignment': dos_alignment,
    'alignment_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    'alignment_strategy': 'Pattern-based scenario matching using Scenario labels'
}

output_file = output_dir / 'host_segment_matching.json'
with open(output_file, 'w') as f:
    json.dump(alignment_results, f, indent=2, default=str)

print("\n" + "="*80)
print("✅ TASK 3-3 COMPLETE")
print("="*80)
print(f"\n💾 Results saved: {output_file}")
print(f"\n📊 Summary:")
print(f"   - Recon: {recon_alignment['host_segment']['records']:,} Host records matched")
print(f"   - DoS: {dos_alignment['host_segment']['records']:,} Host records matched")
print(f"   - Alignment: Pattern-based (Scenario labels)")
print(f"\nℹ️  Next: Task 3-4 - Temporal Alignment Validation")
