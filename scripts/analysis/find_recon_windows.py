#!/usr/bin/env python3
"""
Phase 3 - Task 3-1: Recon Window Discovery
Find optimal Network traffic windows for Reconnaissance attacks
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
output_dir = base_dir / 'processed' / 'stage3'
output_dir.mkdir(exist_ok=True, parents=True)

print("="*80)
print("PHASE 3 - TASK 3-1: RECON WINDOW DISCOVERY")
print("="*80)

# Load Host data to get Recon segment timestamps
print("\n📂 Loading Host data...")
df_host = pd.read_csv(host_path, low_memory=False)
print(f"✅ Loaded {len(df_host):,} records")

# Get Recon segments from Host
recon_host = df_host[df_host['Scenario'] == 'Recon'].copy()
print(f"\n📊 Recon segments in Host data: {len(recon_host):,} records")

if len(recon_host) > 0:
    print(f"   Time range: {recon_host['timestamp_normalized'].min():.3f} - {recon_host['timestamp_normalized'].max():.3f} seconds")

# Load Power data to get correlation reference
print("\n📂 Loading Power data...")
df_power = pd.read_csv(power_path, low_memory=False)
print(f"✅ Loaded {len(df_power):,} records")

# Identify Recon-related power data
recon_power_attacks = ['vuln-scan', 'syn-stealth']
recon_power = df_power[df_power['Attack'].isin(recon_power_attacks)].copy()
print(f"\n📊 Recon-related Power data: {len(recon_power):,} records")
print(f"   Attacks: {recon_power['Attack'].value_counts().to_dict()}")

# ============================================================================
# STEP 1: Load Recon Network files
# ============================================================================
print("\n" + "="*80)
print("STEP 1: LOAD RECON NETWORK FILES")
print("="*80)

recon_patterns = [
    'aggressive-scan',
    'os-fingerprinting',
    'port-scan',
    'service-detection',
    'syn-stealth-scan',
    'vulnerability-scan'
]

network_files = []
for pattern in recon_patterns:
    files = list(network_dir.glob(f'*{pattern}_scaled.csv'))
    network_files.extend(files)

print(f"\n📂 Found {len(network_files)} Recon network files:")
for f in network_files:
    print(f"   - {f.name}")

# ============================================================================
# STEP 2: Analyze each file to find best windows
# ============================================================================
print("\n" + "="*80)
print("STEP 2: SLIDING WINDOW ANALYSIS")
print("="*80)

window_results = []

for i, net_file in enumerate(network_files, 1):
    print(f"\n📄 File {i}/{len(network_files)}: {net_file.name}")

    df_net = pd.read_csv(net_file, low_memory=False)
    print(f"   Records: {len(df_net):,}")

    if len(df_net) == 0:
        print("   ⚠️ Empty file, skipping")
        continue

    # Sort by timestamp
    df_net = df_net.sort_values('timestamp_normalized')

    # Get time range
    t_min = df_net['timestamp_normalized'].min()
    t_max = df_net['timestamp_normalized'].max()
    duration = t_max - t_min

    print(f"   Time range: {t_min:.3f} - {t_max:.3f} ({duration:.3f} seconds)")

    # Window parameters
    window_size = 60  # 60 seconds
    step_size = 30     # 30 seconds overlap

    num_windows = int((duration - window_size) / step_size) + 1

    if num_windows <= 0:
        print("   ⚠️ Duration too short for windowing")
        continue

    print(f"   Sliding windows: {num_windows} (size={window_size}s, step={step_size}s)")

    # Analyze windows
    best_window = None
    best_score = -1

    for w in range(min(num_windows, 100)):  # Limit to 100 windows per file
        window_start = t_min + w * step_size
        window_end = window_start + window_size

        # Get window data
        window_data = df_net[
            (df_net['timestamp_normalized'] >= window_start) &
            (df_net['timestamp_normalized'] < window_end)
        ]

        if len(window_data) == 0:
            continue

        # Calculate Recon-specific metrics
        packet_count = len(window_data)
        packet_rate = packet_count / window_size

        # Unique destination ports (scan indicator)
        unique_ports = window_data['dst_port'].nunique() if 'dst_port' in window_data.columns else 0
        port_diversity = unique_ports / max(packet_count, 1)

        # SYN packets ratio (stealth scan indicator)
        syn_ratio = window_data['bidirectional_syn_packets'].sum() / max(packet_count, 1) if 'bidirectional_syn_packets' in window_data.columns else 0

        # Calculate composite score
        # Higher score = better Recon window
        score = (
            0.4 * min(port_diversity, 1.0) +          # Port diversity (40%)
            0.3 * min(packet_rate / 1000, 1.0) +      # Packet rate (30%)
            0.3 * min(syn_ratio, 1.0)                  # SYN ratio (30%)
        )

        if score > best_score:
            best_score = score
            best_window = {
                'file': net_file.name,
                'window_id': w,
                'start_time': float(window_start),
                'end_time': float(window_end),
                'packet_count': int(packet_count),
                'packet_rate': float(packet_rate),
                'unique_ports': int(unique_ports),
                'port_diversity': float(port_diversity),
                'syn_ratio': float(syn_ratio),
                'score': float(score)
            }

    if best_window:
        window_results.append(best_window)
        print(f"   ✅ Best window: #{best_window['window_id']}")
        print(f"      Score: {best_window['score']:.4f}")
        print(f"      Packets: {best_window['packet_count']:,} ({best_window['packet_rate']:.1f}/s)")
        print(f"      Unique ports: {best_window['unique_ports']}")

# ============================================================================
# STEP 3: Select top windows
# ============================================================================
print("\n" + "="*80)
print("STEP 3: SELECT TOP RECON WINDOWS")
print("="*80)

# Sort by score
window_results.sort(key=lambda x: x['score'], reverse=True)

print(f"\n📊 Top 5 Recon Windows:")
for i, window in enumerate(window_results[:5], 1):
    print(f"\n{i}. {window['file']} - Window #{window['window_id']}")
    print(f"   Time: {window['start_time']:.3f} - {window['end_time']:.3f}")
    print(f"   Score: {window['score']:.4f}")
    print(f"   Packets: {window['packet_count']:,} ({window['packet_rate']:.1f}/s)")
    print(f"   Unique ports: {window['unique_ports']} (diversity: {window['port_diversity']:.3f})")
    print(f"   SYN ratio: {window['syn_ratio']:.3f}")

# ============================================================================
# STEP 4: Validate with Host correlation
# ============================================================================
print("\n" + "="*80)
print("STEP 4: VALIDATE WITH HOST CORRELATION")
print("="*80)

# For top window, check correlation with Host Recon segment
if len(window_results) > 0 and len(recon_host) > 0:
    top_window = window_results[0]

    print(f"\n🔍 Validating top window: {top_window['file']}")
    print(f"   Network window: {top_window['start_time']:.3f} - {top_window['end_time']:.3f}")
    print(f"   Host Recon range: {recon_host['timestamp_normalized'].min():.3f} - {recon_host['timestamp_normalized'].max():.3f}")

    # Check for temporal overlap (conceptual - actual alignment will be done in Task 3-3)
    window_center = (top_window['start_time'] + top_window['end_time']) / 2
    host_recon_center = (recon_host['timestamp_normalized'].min() + recon_host['timestamp_normalized'].max()) / 2

    time_offset = window_center - host_recon_center

    print(f"\n⏱️  Temporal Analysis:")
    print(f"   Network window center: {window_center:.3f}")
    print(f"   Host Recon center: {host_recon_center:.3f}")
    print(f"   Time offset: {time_offset:.3f} seconds")

    # Note: Actual correlation will be computed in Task 3-3 after alignment

# ============================================================================
# SAVE RESULTS
# ============================================================================
results = {
    'total_files_analyzed': len(network_files),
    'total_windows_found': len(window_results),
    'top_windows': window_results[:10],
    'selected_window': window_results[0] if len(window_results) > 0 else None,
    'discovery_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
}

output_file = output_dir / 'recon_windows.json'
with open(output_file, 'w') as f:
    json.dump(results, f, indent=2, default=str)

print("\n" + "="*80)
print("✅ TASK 3-1 COMPLETE")
print("="*80)
print(f"\n💾 Results saved: {output_file}")
print(f"\n📊 Summary:")
print(f"   - Files analyzed: {len(network_files)}")
print(f"   - Windows found: {len(window_results)}")
print(f"   - Top window score: {window_results[0]['score']:.4f}" if len(window_results) > 0 else "   - No windows found")
print(f"\nℹ️  Next: Task 3-2 - DoS Window Discovery")
