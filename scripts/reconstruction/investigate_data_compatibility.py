#!/usr/bin/env python3
"""
Option 3: Data Compatibility Investigation
CRITICAL: Determine if Event Reconstruction is fundamentally possible
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from datetime import datetime, timedelta

base_dir = Path('/mnt/d/EV_charging_forensics')
raw_dir = base_dir / 'CICEVSE2024_Dataset'
processed_dir = base_dir / 'processed' / 'stage2'
output_dir = base_dir / 'processed' / 'reconstruction'
output_dir.mkdir(exist_ok=True, parents=True)

print("="*80)
print("OPTION 3: DATA COMPATIBILITY INVESTIGATION")
print("="*80)
print("\n🔍 CRITICAL QUESTION: Can we perform Event Reconstruction?")
print("   Investigating temporal overlap across Host, Network, Power layers")

investigation_report = {
    'host': {},
    'network': {},
    'power': {},
    'compatibility': {},
    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
}

# ============================================================================
# STEP 1: Analyze RAW Host Data Timestamps
# ============================================================================
print("\n" + "="*80)
print("STEP 1: HOST LAYER TEMPORAL ANALYSIS")
print("="*80)

print("\n📂 Loading raw Host data...")
df_host_raw = pd.read_csv(raw_dir / 'Host Events' / 'EVSE-B-HPC-Kernel-Events-Combined.csv', low_memory=False)

print(f"   Records: {len(df_host_raw):,}")
print(f"\n⏱️  Raw Host Timestamps:")
print(f"   Column: 'time'")
print(f"   Format: {df_host_raw['time'].dtype}")
print(f"   Sample: {df_host_raw['time'].iloc[0]}")

# Convert time to numeric (handle mixed types)
df_host_raw['time'] = pd.to_numeric(df_host_raw['time'], errors='coerce')

print(f"   Min: {df_host_raw['time'].min()}")
print(f"   Max: {df_host_raw['time'].max()}")
print(f"   Range: {df_host_raw['time'].max() - df_host_raw['time'].min():.2f} units")

# Check if it's relative seconds or absolute time
if df_host_raw['time'].max() < 1000000:  # Likely relative seconds
    print(f"\n   ✅ Interpretation: RELATIVE SECONDS from recording start")
    print(f"   Duration: {df_host_raw['time'].max():.2f} seconds = {df_host_raw['time'].max()/60:.2f} minutes")

    host_format = 'relative_seconds'
    host_t0 = 0.0  # Relative to recording start
    host_duration = df_host_raw['time'].max()
else:  # Likely Unix timestamp
    print(f"\n   ⚠️  Interpretation: Possibly UNIX TIMESTAMP")
    host_format = 'unix_timestamp'
    host_t0 = df_host_raw['time'].min()
    host_duration = df_host_raw['time'].max() - df_host_raw['time'].min()

# Scenario breakdown
print(f"\n📊 Host Scenarios:")
scenario_counts = df_host_raw['Scenario'].value_counts()
for scenario, count in scenario_counts.items():
    scenario_data = df_host_raw[df_host_raw['Scenario'] == scenario]
    time_min = scenario_data['time'].min()
    time_max = scenario_data['time'].max()
    print(f"   {scenario}: {count:,} records, time range: {time_min:.1f} - {time_max:.1f}")

investigation_report['host'] = {
    'total_records': int(len(df_host_raw)),
    'timestamp_format': host_format,
    'time_min': float(df_host_raw['time'].min()),
    'time_max': float(df_host_raw['time'].max()),
    'duration_seconds': float(host_duration),
    'scenarios': {k: int(v) for k, v in scenario_counts.items()}
}

# ============================================================================
# STEP 2: Analyze RAW Network Data Timestamps
# ============================================================================
print("\n" + "="*80)
print("STEP 2: NETWORK LAYER TEMPORAL ANALYSIS")
print("="*80)

print("\n📂 Loading raw Network data (sample)...")
network_files = sorted((raw_dir / 'Network Traffic' / 'EVSE-B' / 'csv').glob('EVSE-B-*.csv'))
print(f"   Total files: {len(network_files)}")

# Analyze first few files
network_time_ranges = []
for i, csv_path in enumerate(network_files[:5], 1):
    print(f"\n📄 File {i}: {csv_path.name}")
    df_net = pd.read_csv(csv_path, low_memory=False)

    if 'bidirectional_first_seen_ms' in df_net.columns:
        time_col = 'bidirectional_first_seen_ms'
        time_min_ms = df_net[time_col].min()
        time_max_ms = df_net[time_col].max()
        time_min_s = time_min_ms / 1000.0
        time_max_s = time_max_ms / 1000.0

        # Convert to datetime for readability
        time_min_dt = datetime.fromtimestamp(time_min_s)
        time_max_dt = datetime.fromtimestamp(time_max_s)

        print(f"   Records: {len(df_net):,}")
        print(f"   Time (ms): {time_min_ms} - {time_max_ms}")
        print(f"   Time (s): {time_min_s:.1f} - {time_max_s:.1f}")
        print(f"   Time (datetime): {time_min_dt} - {time_max_dt}")
        print(f"   Duration: {time_max_s - time_min_s:.1f} seconds")

        network_time_ranges.append({
            'file': csv_path.name,
            'records': len(df_net),
            'time_min_s': time_min_s,
            'time_max_s': time_max_s,
            'time_min_dt': str(time_min_dt),
            'time_max_dt': str(time_max_dt),
            'duration_s': time_max_s - time_min_s
        })

# Overall Network timestamp range
if network_time_ranges:
    net_global_min = min(r['time_min_s'] for r in network_time_ranges)
    net_global_max = max(r['time_max_s'] for r in network_time_ranges)
    net_global_min_dt = datetime.fromtimestamp(net_global_min)
    net_global_max_dt = datetime.fromtimestamp(net_global_max)

    print(f"\n📊 Network Overall Time Range (from sampled files):")
    print(f"   Min: {net_global_min_dt} ({net_global_min:.1f})")
    print(f"   Max: {net_global_max_dt} ({net_global_max:.1f})")
    print(f"   Total duration: {net_global_max - net_global_min:.1f} seconds")

    investigation_report['network'] = {
        'timestamp_format': 'unix_milliseconds',
        'sampled_files': len(network_time_ranges),
        'time_min_unix': float(net_global_min),
        'time_max_unix': float(net_global_max),
        'time_min_datetime': str(net_global_min_dt),
        'time_max_datetime': str(net_global_max_dt),
        'duration_seconds': float(net_global_max - net_global_min),
        'file_details': network_time_ranges
    }

# ============================================================================
# STEP 3: Analyze RAW Power Data Timestamps
# ============================================================================
print("\n" + "="*80)
print("STEP 3: POWER LAYER TEMPORAL ANALYSIS")
print("="*80)

print("\n📂 Loading raw Power data...")
df_power_raw = pd.read_csv(raw_dir / 'Power Consumption' / 'EVSE-B-PowerCombined.csv', low_memory=False)

print(f"   Records: {len(df_power_raw):,}")
print(f"\n⏱️  Raw Power Timestamps:")
print(f"   Column: 'time'")
print(f"   Format: {df_power_raw['time'].dtype}")
print(f"   Sample: {df_power_raw['time'].iloc[0]}")

# Parse datetime
try:
    df_power_raw['timestamp'] = pd.to_datetime(df_power_raw['time'], format='%m/%d/%Y %H:%M')
    print(f"   ✅ Parsed with format: %m/%d/%Y %H:%M")
except:
    df_power_raw['timestamp'] = pd.to_datetime(df_power_raw['time'])
    print(f"   ✅ Parsed with automatic detection")

# Convert to Unix timestamp
df_power_raw['unix_timestamp'] = df_power_raw['timestamp'].astype('int64') / 1e9

power_min_dt = df_power_raw['timestamp'].min()
power_max_dt = df_power_raw['timestamp'].max()
power_min_unix = df_power_raw['unix_timestamp'].min()
power_max_unix = df_power_raw['unix_timestamp'].max()
power_duration = power_max_unix - power_min_unix

print(f"\n   Time (datetime): {power_min_dt} - {power_max_dt}")
print(f"   Time (unix): {power_min_unix:.1f} - {power_max_unix:.1f}")
print(f"   Duration: {power_duration:.1f} seconds = {power_duration/3600:.2f} hours")

# Attack breakdown
print(f"\n📊 Power Attack Types:")
attack_counts = df_power_raw['Attack'].value_counts()
for attack, count in attack_counts.items():
    attack_data = df_power_raw[df_power_raw['Attack'] == attack]
    time_min_dt = attack_data['timestamp'].min()
    time_max_dt = attack_data['timestamp'].max()
    print(f"   {attack}: {count:,} records")
    print(f"      {time_min_dt} - {time_max_dt}")

investigation_report['power'] = {
    'total_records': int(len(df_power_raw)),
    'timestamp_format': 'human_datetime',
    'time_min_unix': float(power_min_unix),
    'time_max_unix': float(power_max_unix),
    'time_min_datetime': str(power_min_dt),
    'time_max_datetime': str(power_max_dt),
    'duration_seconds': float(power_duration),
    'attacks': {k: int(v) for k, v in attack_counts.items()}
}

# ============================================================================
# STEP 4: TEMPORAL COMPATIBILITY ANALYSIS
# ============================================================================
print("\n" + "="*80)
print("STEP 4: TEMPORAL COMPATIBILITY ANALYSIS")
print("="*80)

print("\n🔍 Cross-Layer Timestamp Comparison:")
print(f"\n   Host:")
print(f"      Format: {host_format}")
if host_format == 'relative_seconds':
    print(f"      Range: 0 - {df_host_raw['time'].max():.1f} seconds (relative)")
    print(f"      UNKNOWN ABSOLUTE TIME (no T0 reference!)")
else:
    print(f"      Range: {df_host_raw['time'].min()} - {df_host_raw['time'].max()}")

print(f"\n   Network:")
print(f"      Format: Unix timestamp (milliseconds)")
print(f"      Range: {net_global_min_dt} - {net_global_max_dt}")
print(f"      Unix: {net_global_min:.1f} - {net_global_max:.1f}")

print(f"\n   Power:")
print(f"      Format: Human datetime")
print(f"      Range: {power_min_dt} - {power_max_dt}")
print(f"      Unix: {power_min_unix:.1f} - {power_max_unix:.1f}")

# ============================================================================
# CRITICAL: Check if Network and Power overlap
# ============================================================================
print("\n" + "="*80)
print("🚨 CRITICAL: TIME OVERLAP ANALYSIS")
print("="*80)

print(f"\n1️⃣ Network ↔ Power Overlap:")
print(f"   Network: {net_global_min:.1f} - {net_global_max:.1f}")
print(f"   Power:   {power_min_unix:.1f} - {power_max_unix:.1f}")

net_power_overlap_start = max(net_global_min, power_min_unix)
net_power_overlap_end = min(net_global_max, power_max_unix)
net_power_overlap = net_power_overlap_end - net_power_overlap_start

if net_power_overlap > 0:
    print(f"   ✅ OVERLAP EXISTS: {net_power_overlap:.1f} seconds")
    print(f"   Overlap: {datetime.fromtimestamp(net_power_overlap_start)} - {datetime.fromtimestamp(net_power_overlap_end)}")

    net_power_compatible = True
else:
    print(f"   ❌ NO OVERLAP: {abs(net_power_overlap):.1f} seconds gap")
    if net_global_max < power_min_unix:
        gap = power_min_unix - net_global_max
        print(f"   Network ends {gap:.1f} seconds ({gap/3600:.2f} hours) BEFORE Power starts")
    else:
        gap = net_global_min - power_max_unix
        print(f"   Network starts {gap:.1f} seconds ({gap/3600:.2f} hours) AFTER Power ends")

    net_power_compatible = False

print(f"\n2️⃣ Host ↔ Power Overlap:")
if host_format == 'relative_seconds':
    print(f"   ❌ CANNOT DETERMINE: Host uses relative time without absolute T0")
    print(f"   Host: 0 - {df_host_raw['time'].max():.1f} seconds (relative)")
    print(f"   Power: {power_min_dt} - {power_max_dt}")
    print(f"\n   ⚠️  CRITICAL ISSUE: Host data has NO absolute timestamp reference!")
    print(f"   We don't know WHEN Host events actually occurred.")

    host_power_compatible = 'unknown'
else:
    # If Host is Unix timestamp, check overlap
    host_power_overlap_start = max(df_host_raw['time'].min(), power_min_unix)
    host_power_overlap_end = min(df_host_raw['time'].max(), power_max_unix)
    host_power_overlap = host_power_overlap_end - host_power_overlap_start

    if host_power_overlap > 0:
        print(f"   ✅ OVERLAP EXISTS: {host_power_overlap:.1f} seconds")
        host_power_compatible = True
    else:
        print(f"   ❌ NO OVERLAP")
        host_power_compatible = False

print(f"\n3️⃣ Host ↔ Network Overlap:")
if host_format == 'relative_seconds':
    print(f"   ❌ CANNOT DETERMINE: Host uses relative time without absolute T0")
    print(f"   Host: 0 - {df_host_raw['time'].max():.1f} seconds (relative)")
    print(f"   Network: {net_global_min_dt} - {net_global_max_dt}")

    host_net_compatible = 'unknown'
else:
    host_net_overlap_start = max(df_host_raw['time'].min(), net_global_min)
    host_net_overlap_end = min(df_host_raw['time'].max(), net_global_max)
    host_net_overlap = host_net_overlap_end - host_net_overlap_start

    if host_net_overlap > 0:
        print(f"   ✅ OVERLAP EXISTS: {host_net_overlap:.1f} seconds")
        host_net_compatible = True
    else:
        print(f"   ❌ NO OVERLAP")
        host_net_compatible = False

# ============================================================================
# STEP 5: DETERMINE FEASIBILITY
# ============================================================================
print("\n" + "="*80)
print("STEP 5: EVENT RECONSTRUCTION FEASIBILITY")
print("="*80)

compatibility_issues = []

# Issue 1: Host has no absolute time reference
if host_format == 'relative_seconds':
    compatibility_issues.append({
        'severity': 'CRITICAL',
        'layer': 'Host',
        'issue': 'No absolute timestamp reference',
        'impact': 'Cannot align Host events with Network/Power',
        'solution': 'Need metadata or external reference to determine Host T0'
    })

# Issue 2: Network-Power overlap
if not net_power_compatible:
    compatibility_issues.append({
        'severity': 'CRITICAL',
        'layer': 'Network-Power',
        'issue': 'No temporal overlap',
        'impact': 'Cannot create unified timeline with both layers',
        'solution': 'Use Network OR Power, not both'
    })

# Issue 3: Timestamp normalization bug
compatibility_issues.append({
    'severity': 'HIGH',
    'layer': 'All',
    'issue': 'Phase 2 normalization bug (Network timestamps not normalized)',
    'impact': 'Current processed data has incompatible timestamps',
    'solution': 'Fix normalize_timestamps.py and re-run Phase 2'
})

print(f"\n🚨 Compatibility Issues Found: {len(compatibility_issues)}")
for i, issue in enumerate(compatibility_issues, 1):
    print(f"\n   Issue {i} [{issue['severity']}]: {issue['layer']}")
    print(f"      Problem: {issue['issue']}")
    print(f"      Impact: {issue['impact']}")
    print(f"      Solution: {issue['solution']}")

# Overall feasibility
print(f"\n" + "="*80)
print("FEASIBILITY VERDICT")
print("="*80)

if host_format == 'relative_seconds':
    print(f"\n⚠️  Event Reconstruction: PROBLEMATIC")
    print(f"\n   CRITICAL BLOCKER:")
    print(f"   - Host data uses RELATIVE timestamps with no absolute T0")
    print(f"   - We don't know WHEN Host events actually occurred")
    print(f"   - Cannot align Host with Network/Power absolute timestamps")

    print(f"\n   Possible Solutions:")
    print(f"   1. Find metadata with Host capture start time")
    print(f"   2. Infer Host T0 from scenario labels (match Network/Power attacks)")
    print(f"   3. Use Network-Power only (2-layer instead of 3-layer)")

    feasibility = 'problematic_host_no_t0'

elif not net_power_compatible:
    print(f"\n❌ Event Reconstruction: NOT FEASIBLE (Network-Power gap)")
    print(f"\n   Network and Power data do NOT overlap in time")
    print(f"   Cannot create 3-layer unified timeline")

    print(f"\n   Alternative Approaches:")
    print(f"   1. Host + Network only (if Host T0 can be determined)")
    print(f"   2. Host + Power only (if Host T0 can be determined)")

    feasibility = 'not_feasible_no_overlap'

else:
    print(f"\n✅ Event Reconstruction: FEASIBLE (with fixes)")
    print(f"\n   Network-Power overlap: {net_power_overlap:.1f} seconds")
    print(f"   After fixing Phase 2 normalization bug, can create timeline")

    if host_format == 'unix_timestamp':
        print(f"   Host timestamps are absolute - can align all 3 layers")

    feasibility = 'feasible'

investigation_report['compatibility'] = {
    'network_power_overlap_seconds': float(net_power_overlap) if net_power_overlap > 0 else 0.0,
    'network_power_compatible': net_power_compatible,
    'host_power_compatible': host_power_compatible,
    'host_network_compatible': host_net_compatible,
    'issues': compatibility_issues,
    'feasibility': feasibility
}

# ============================================================================
# STEP 6: SCENARIO-BASED TEMPORAL MAPPING
# ============================================================================
print("\n" + "="*80)
print("STEP 6: SCENARIO-BASED TEMPORAL MAPPING")
print("="*80)

print(f"\n🔍 Attempting to infer Host T0 from scenario labels...")

# Get DoS scenario from Host
dos_host = df_host_raw[df_host_raw['Scenario'] == 'DoS']
if len(dos_host) > 0:
    print(f"\n📊 DoS Scenario in Host:")
    print(f"   Records: {len(dos_host):,}")
    print(f"   Time range: {dos_host['time'].min():.1f} - {dos_host['time'].max():.1f} seconds (relative)")
    print(f"   Duration: {dos_host['time'].max() - dos_host['time'].min():.1f} seconds")

    # Find DoS in Network (flood attacks)
    dos_net_files = [f for f in network_files if 'flood' in f.name.lower()]
    print(f"\n📊 DoS (flood) attacks in Network: {len(dos_net_files)} files")

    if len(dos_net_files) > 0:
        # Sample one DoS network file
        sample_dos = pd.read_csv(dos_net_files[0], low_memory=False)
        if 'bidirectional_first_seen_ms' in sample_dos.columns:
            dos_net_start = sample_dos['bidirectional_first_seen_ms'].min() / 1000.0
            dos_net_end = sample_dos['bidirectional_first_seen_ms'].max() / 1000.0
            dos_net_start_dt = datetime.fromtimestamp(dos_net_start)

            print(f"\n   Sample DoS Network file: {dos_net_files[0].name}")
            print(f"      Start: {dos_net_start_dt} ({dos_net_start:.1f})")
            print(f"      Duration: {dos_net_end - dos_net_start:.1f} seconds")

            # HYPOTHESIS: Host DoS start time aligns with Network DoS start time
            inferred_host_t0 = dos_net_start - dos_host['time'].min()
            inferred_host_t0_dt = datetime.fromtimestamp(inferred_host_t0)

            print(f"\n💡 INFERRED Host T0:")
            print(f"   Assumption: Host DoS starts at same time as Network DoS")
            print(f"   Host T0: {inferred_host_t0_dt} ({inferred_host_t0:.1f})")
            print(f"   Host time range: {datetime.fromtimestamp(inferred_host_t0)} - {datetime.fromtimestamp(inferred_host_t0 + df_host_raw['time'].max())}")

            # Check if inferred Host overlaps with Power
            host_inferred_start = inferred_host_t0
            host_inferred_end = inferred_host_t0 + df_host_raw['time'].max()

            host_power_inferred_overlap_start = max(host_inferred_start, power_min_unix)
            host_power_inferred_overlap_end = min(host_inferred_end, power_max_unix)
            host_power_inferred_overlap = host_power_inferred_overlap_end - host_power_inferred_overlap_start

            print(f"\n   Host (inferred) ↔ Power overlap:")
            if host_power_inferred_overlap > 0:
                print(f"   ✅ {host_power_inferred_overlap:.1f} seconds overlap!")
                print(f"   Overlap: {datetime.fromtimestamp(host_power_inferred_overlap_start)} - {datetime.fromtimestamp(host_power_inferred_overlap_end)}")
            else:
                print(f"   ❌ NO OVERLAP ({abs(host_power_inferred_overlap):.1f} seconds gap)")

            investigation_report['scenario_mapping'] = {
                'method': 'dos_scenario_alignment',
                'inferred_host_t0_unix': float(inferred_host_t0),
                'inferred_host_t0_datetime': str(inferred_host_t0_dt),
                'host_power_overlap_seconds': float(host_power_inferred_overlap) if host_power_inferred_overlap > 0 else 0.0,
                'hypothesis': 'Host DoS scenario starts at same time as Network flood attacks'
            }

# ============================================================================
# SAVE REPORT
# ============================================================================
report_file = output_dir / 'data_compatibility_investigation.json'
with open(report_file, 'w') as f:
    json.dump(investigation_report, f, indent=2)

print(f"\n💾 Investigation report saved: {report_file}")

print("\n" + "="*80)
print("✅ INVESTIGATION COMPLETE")
print("="*80)

# Final summary
print(f"\n📋 EXECUTIVE SUMMARY:")
print(f"   Network-Power overlap: {'✅ YES' if net_power_compatible else '❌ NO'}")
print(f"   Host absolute T0: {'✅ YES' if host_format != 'relative_seconds' else '❌ NO (CRITICAL)'}")
print(f"   Event Reconstruction feasibility: {feasibility.upper()}")

if feasibility == 'problematic_host_no_t0':
    print(f"\n⚠️  DECISION REQUIRED:")
    print(f"   1. Attempt scenario-based Host T0 inference (risky)")
    print(f"   2. Use 2-layer only (Network-Power or Host-Power)")
    print(f"   3. Re-evaluate research approach")
elif feasibility == 'feasible':
    print(f"\n✅ NEXT STEP: Fix Phase 2 normalization bug and re-run")
else:
    print(f"\n❌ RECOMMENDATION: Re-evaluate research approach")
