#!/usr/bin/env python3
"""
Phase 3 - Task 3-2: DoS Window Discovery
Find optimal Network traffic windows for Denial-of-Service attacks
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime

base_dir = Path('/mnt/d/EV_charging_forensics')
network_dir = base_dir / 'processed' / 'stage2'
host_path = base_dir / 'processed' / 'stage2' / 'host_scaled.csv'
power_path = base_dir / 'processed' / 'stage2' / 'power_scaled.csv'
output_dir = base_dir / 'processed' / 'stage3'
output_dir.mkdir(exist_ok=True, parents=True)

print("="*80)
print("PHASE 3 - TASK 3-2: DOS WINDOW DISCOVERY")
print("="*80)

# Load Host data to get DoS segment timestamps
print("\n📂 Loading Host data...")
df_host = pd.read_csv(host_path, low_memory=False)
print(f"✅ Loaded {len(df_host):,} records")

# Get DoS segments from Host
dos_host = df_host[df_host['Scenario'] == 'DoS'].copy()
print(f"\n📊 DoS segments in Host data: {len(dos_host):,} records")

if len(dos_host) > 0:
    print(f"   Time range: {dos_host['timestamp_normalized'].min():.3f} - {dos_host['timestamp_normalized'].max():.3f} seconds")

# Load Power data to get correlation reference
print("\n📂 Loading Power data...")
df_power = pd.read_csv(power_path, low_memory=False)
print(f"✅ Loaded {len(df_power):,} records")

# Identify DoS-related power data
dos_power_attacks = ['tcp-flood', 'syn-flood', 'udp-flood', 'icmp-flood', 'push-ack-flood', 'synonymous-ip-flood']
# Note: Power data may use different attack labels
dos_power = df_power[df_power['Attack'].str.contains('flood', case=False, na=False)].copy()
print(f"\n📊 DoS-related Power data: {len(dos_power):,} records")
if len(dos_power) > 0:
    print(f"   Attacks: {dos_power['Attack'].value_counts().to_dict()}")

# ============================================================================
# STEP 1: Load DoS Network files
# ============================================================================
print("\n" + "="*80)
print("STEP 1: LOAD DOS NETWORK FILES")
print("="*80)

dos_patterns = [
    'icmp-flood',
    'syn-flood',
    'tcp-flood',
    'udp-flood',
    'push-ack-flood',
    'synonymous-ip-flood',
    'icmp-fragmentation'
]

network_files = []
for pattern in dos_patterns:
    files = list(network_dir.glob(f'*{pattern}_scaled.csv'))
    network_files.extend(files)

print(f"\n📂 Found {len(network_files)} DoS network files:")
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

    # Window parameters (shorter for flood detection)
    window_size = 30  # 30 seconds (floods are intense bursts)
    step_size = 15     # 15 seconds overlap

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

        # Calculate DoS-specific metrics
        packet_count = len(window_data)
        packet_rate = packet_count / window_size

        # Protocol concentration (flood attacks focus on one protocol)
        if 'protocol' in window_data.columns:
            protocol_counts = window_data['protocol'].value_counts()
            protocol_concentration = protocol_counts.max() / max(packet_count, 1)
        else:
            protocol_concentration = 0

        # Packet size uniformity (floods often have similar packet sizes)
        if 'bidirectional_bytes' in window_data.columns:
            pkt_sizes = window_data['bidirectional_bytes']
            size_std = pkt_sizes.std() / (pkt_sizes.mean() + 1)  # Normalized std
            size_uniformity = 1 / (1 + size_std)  # Higher = more uniform
        else:
            size_uniformity = 0

        # Calculate composite score
        # Higher score = better DoS window
        score = (
            0.5 * min(packet_rate / 5000, 1.0) +      # Packet rate (50%) - very high for floods
            0.3 * protocol_concentration +             # Protocol focus (30%)
            0.2 * size_uniformity                      # Size uniformity (20%)
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
                'protocol_concentration': float(protocol_concentration),
                'size_uniformity': float(size_uniformity),
                'score': float(score)
            }

    if best_window:
        window_results.append(best_window)
        print(f"   ✅ Best window: #{best_window['window_id']}")
        print(f"      Score: {best_window['score']:.4f}")
        print(f"      Packets: {best_window['packet_count']:,} ({best_window['packet_rate']:.1f}/s)")
        print(f"      Protocol concentration: {best_window['protocol_concentration']:.3f}")

# ============================================================================
# STEP 3: Select top windows
# ============================================================================
print("\n" + "="*80)
print("STEP 3: SELECT TOP DOS WINDOWS")
print("="*80)

# Sort by score
window_results.sort(key=lambda x: x['score'], reverse=True)

print(f"\n📊 Top 5 DoS Windows:")
for i, window in enumerate(window_results[:5], 1):
    print(f"\n{i}. {window['file']} - Window #{window['window_id']}")
    print(f"   Time: {window['start_time']:.3f} - {window['end_time']:.3f}")
    print(f"   Score: {window['score']:.4f}")
    print(f"   Packets: {window['packet_count']:,} ({window['packet_rate']:.1f}/s)")
    print(f"   Protocol concentration: {window['protocol_concentration']:.3f}")
    print(f"   Size uniformity: {window['size_uniformity']:.3f}")

# ============================================================================
# STEP 4: Validate with Host correlation
# ============================================================================
print("\n" + "="*80)
print("STEP 4: VALIDATE WITH HOST CORRELATION")
print("="*80)

# For top window, check correlation with Host DoS segment
if len(window_results) > 0 and len(dos_host) > 0:
    top_window = window_results[0]

    print(f"\n🔍 Validating top window: {top_window['file']}")
    print(f"   Network window: {top_window['start_time']:.3f} - {top_window['end_time']:.3f}")
    print(f"   Host DoS range: {dos_host['timestamp_normalized'].min():.3f} - {dos_host['timestamp_normalized'].max():.3f}")

    # Check for temporal characteristics
    window_center = (top_window['start_time'] + top_window['end_time']) / 2
    host_dos_center = (dos_host['timestamp_normalized'].min() + dos_host['timestamp_normalized'].max()) / 2

    time_offset = window_center - host_dos_center

    print(f"\n⏱️  Temporal Analysis:")
    print(f"   Network window center: {window_center:.3f}")
    print(f"   Host DoS center: {host_dos_center:.3f}")
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

output_file = output_dir / 'dos_windows.json'
with open(output_file, 'w') as f:
    json.dump(results, f, indent=2, default=str)

print("\n" + "="*80)
print("✅ TASK 3-2 COMPLETE")
print("="*80)
print(f"\n💾 Results saved: {output_file}")
print(f"\n📊 Summary:")
print(f"   - Files analyzed: {len(network_files)}")
print(f"   - Windows found: {len(window_results)}")
print(f"   - Top window score: {window_results[0]['score']:.4f}" if len(window_results) > 0 else "   - No windows found")
print(f"\nℹ️  Next: Task 3-3 - Host Segment Matching")
