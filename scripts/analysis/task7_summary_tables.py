#!/usr/bin/env python3
"""
Task 7: Statistical Summary Tables
Generate markdown tables for publication
"""

import json
import pandas as pd
from pathlib import Path

base_dir = Path('/mnt/d/EV_charging_forensics')
results_dir = base_dir / 'results'
tables_dir = results_dir / 'tables'
tables_dir.mkdir(exist_ok=True, parents=True)

print("="*80)
print("TASK 7: STATISTICAL SUMMARY TABLES")
print("="*80)

def df_to_markdown(df):
    """
    Convert DataFrame to markdown table format
    """
    # Get column names
    cols = df.columns.tolist()

    # Header row
    header = "| " + " | ".join(cols) + " |"

    # Separator row
    separator = "| " + " | ".join(["---"] * len(cols)) + " |"

    # Data rows
    rows = []
    for _, row in df.iterrows():
        row_str = "| " + " | ".join(str(val) for val in row.values) + " |"
        rows.append(row_str)

    # Combine
    markdown = "\n".join([header, separator] + rows)
    return markdown

# Load data
with open(results_dir / 'attack_start_points.json', 'r') as f:
    attack_starts = json.load(f)

with open(results_dir / 'temporal_patterns.json', 'r') as f:
    patterns = json.load(f)

with open(results_dir / 'time_lagged_correlations.json', 'r') as f:
    correlations = json.load(f)

# ============================================================================
# TABLE 1: Attack Start Detection Results
# ============================================================================
print("\n📊 Generating Table 1: Attack Start Detection...")

table1_data = []

scenarios = {'dos': 'DoS', 'recon': 'Recon', 'cryptojacking': 'Cryptojacking'}

for scenario_key, scenario_label in scenarios.items():
    scenario_data = attack_starts[scenario_key]

    for layer in ['host', 'network', 'power']:
        if layer in scenario_data and scenario_data[layer] is not None:
            layer_data = scenario_data[layer]
            table1_data.append({
                'Scenario': scenario_label,
                'Layer': layer.capitalize(),
                'Detection Time (s)': f"{layer_data['timestamp']:.1f}",
                'Confidence': layer_data['confidence'].capitalize(),
                'Method': '2σ' if 'sigma' in layer_data['detection_method'] else 'First packet'
            })

df_table1 = pd.DataFrame(table1_data)

# Save as markdown
table1_file = tables_dir / 'table1_attack_detection.md'
with open(table1_file, 'w') as f:
    f.write("# Table 1: Attack Start Detection Results\n\n")
    f.write(df_to_markdown(df_table1))
    f.write("\n\n**Notes**:\n")
    f.write("- Detection Time: Relative to dataset start (not attack-relative)\n")
    f.write("- 2σ: Anomaly detection using benign baseline + 2 standard deviations\n")
    f.write("- Confidence: High (confirmed), Medium (threshold crossing), Low (fallback)\n")

print(f"   ✅ Saved: {table1_file.name}")
print(f"      {len(df_table1)} rows")

# ============================================================================
# TABLE 2: Temporal Pattern Summary
# ============================================================================
print("\n📊 Generating Table 2: Temporal Pattern Summary...")

table2_data = []

for scenario_key, scenario_label in scenarios.items():
    scenario_patterns = patterns[scenario_key]['phases']

    for phase in ['initiation', 'peak', 'sustained']:
        for layer in ['host', 'net', 'power']:
            key = f'{phase}_{layer}'
            if key in scenario_patterns:
                stats = scenario_patterns[key]
                table2_data.append({
                    'Scenario': scenario_label,
                    'Phase': phase.capitalize(),
                    'Layer': layer.capitalize() if layer != 'net' else 'Network',
                    'Mean': f"{stats['mean']:.4f}",
                    'Std': f"{stats['std']:.4f}",
                    'Max': f"{stats['max']:.4f}",
                    'Trend': f"{stats['trend']:+.6f}"
                })

df_table2 = pd.DataFrame(table2_data)

# Save as markdown
table2_file = tables_dir / 'table2_temporal_patterns.md'
with open(table2_file, 'w') as f:
    f.write("# Table 2: Temporal Pattern Summary\n\n")
    f.write(df_to_markdown(df_table2))
    f.write("\n\n**Notes**:\n")
    f.write("- Mean/Std/Max: Normalized intensity values (0-1 scale)\n")
    f.write("- Trend: Linear slope (OLS) across phase duration\n")
    f.write("- Positive trend = increasing, negative = decreasing\n")
    f.write("- Phases: Initiation (0-10s), Peak (10-30s), Sustained (30-60s)\n")

print(f"   ✅ Saved: {table2_file.name}")
print(f"      {len(df_table2)} rows")

# ============================================================================
# TABLE 3: Time-Lagged Correlation Summary
# ============================================================================
print("\n📊 Generating Table 3: Time-Lagged Correlation...")

table3_data = []

for scenario_key, scenario_label in scenarios.items():
    scenario_corr = correlations[scenario_key]['correlations']

    # Define layer pairs in logical order
    layer_pairs = [
        ('net_host', 'Network → Host'),
        ('host_power', 'Host → Power'),
        ('net_power', 'Network → Power')
    ]

    for pair_key, pair_label in layer_pairs:
        if pair_key in scenario_corr:
            corr_data = scenario_corr[pair_key]
            table3_data.append({
                'Scenario': scenario_label,
                'Layer Pair': pair_label,
                'Optimal Lag (s)': corr_data['optimal_lag'],
                'r': f"{corr_data['optimal_r']:.3f}",
                'p-value': f"{corr_data['optimal_p']:.4f}" if corr_data['optimal_p'] >= 0.0001 else '<0.0001',
                'Interpretation': corr_data['interpretation']
            })

df_table3 = pd.DataFrame(table3_data)

# Save as markdown
table3_file = tables_dir / 'table3_lagged_correlations.md'
with open(table3_file, 'w') as f:
    f.write("# Table 3: Time-Lagged Cross-Layer Correlation\n\n")
    f.write(df_to_markdown(df_table3))
    f.write("\n\n**Notes**:\n")
    f.write("- Optimal Lag: Time shift (seconds) that maximizes |r|\n")
    f.write("- Negative lag: First layer leads second layer\n")
    f.write("- Positive lag: Second layer leads first layer\n")
    f.write("- r: Pearson correlation coefficient (-1 to +1)\n")
    f.write("- p-value: Statistical significance (α=0.05)\n")
    f.write("- Interpretation: Temporal relationship between layers\n")

print(f"   ✅ Saved: {table3_file.name}")
print(f"      {len(df_table3)} rows")

# ============================================================================
# Generate Combined Summary
# ============================================================================
print("\n📊 Generating Combined Summary...")

summary_file = tables_dir / 'summary_all_tables.md'
with open(summary_file, 'w') as f:
    f.write("# Statistical Summary: Multi-Layer Cyber Event Reconstruction\n\n")
    f.write("**Analysis Date**: 2025-10-25\n\n")
    f.write("**Dataset**: CICEVSE2024 - EV Charging Infrastructure Security\n\n")
    f.write("**Analysis Method**: Attack-Relative Time Normalization (얼추 맞추기)\n\n")
    f.write("---\n\n")

    # Table 1
    f.write("## Table 1: Attack Start Detection Results\n\n")
    f.write(df_to_markdown(df_table1))
    f.write("\n\n**Notes**:\n")
    f.write("- Detection Time: Relative to dataset start (not attack-relative)\n")
    f.write("- 2σ: Anomaly detection using benign baseline + 2 standard deviations\n")
    f.write("- Confidence: High (confirmed), Medium (threshold crossing), Low (fallback)\n\n")
    f.write("---\n\n")

    # Table 2
    f.write("## Table 2: Temporal Pattern Summary\n\n")
    f.write(df_to_markdown(df_table2))
    f.write("\n\n**Notes**:\n")
    f.write("- Mean/Std/Max: Normalized intensity values (0-1 scale)\n")
    f.write("- Trend: Linear slope (OLS) across phase duration\n")
    f.write("- Positive trend = increasing, negative = decreasing\n")
    f.write("- Phases: Initiation (0-10s), Peak (10-30s), Sustained (30-60s)\n\n")
    f.write("---\n\n")

    # Table 3
    f.write("## Table 3: Time-Lagged Cross-Layer Correlation\n\n")
    f.write(df_to_markdown(df_table3))
    f.write("\n\n**Notes**:\n")
    f.write("- Optimal Lag: Time shift (seconds) that maximizes |r|\n")
    f.write("- Negative lag: First layer leads second layer\n")
    f.write("- Positive lag: Second layer leads first layer\n")
    f.write("- r: Pearson correlation coefficient (-1 to +1)\n")
    f.write("- p-value: Statistical significance (α=0.05)\n")
    f.write("- Interpretation: Temporal relationship between layers\n\n")
    f.write("---\n\n")

    # Key findings
    f.write("## Key Findings\n\n")
    f.write("### Attack Propagation Patterns\n\n")
    f.write("**DoS Attack**:\n")
    f.write("- Network → Host: 6-second propagation delay (r=0.642)\n")
    f.write("- Host → Power: 4-second propagation delay (r=1.000)\n")
    f.write("- Total propagation: Network → Host (6s) → Power (4s)\n\n")

    f.write("**Recon Attack**:\n")
    f.write("- Network → Host: 1-second propagation delay (r=0.825) - instant!\n")
    f.write("- Host → Power: 6-second propagation delay (r=1.000)\n")
    f.write("- Rapid reconnaissance burst at attack onset\n\n")

    f.write("**Cryptojacking Attack**:\n")
    f.write("- Host → Power: 6-second propagation delay (r=0.997)\n")
    f.write("- No network component (host-originated)\n")
    f.write("- Gradual intensity buildup (late peak at 48s)\n\n")

    f.write("### Temporal Evolution Insights\n\n")
    f.write("**Phase Characteristics**:\n")
    f.write("- DoS: Rapid decline after initiation (-0.004 trend in peak phase)\n")
    f.write("- Recon: Steepest decline (-0.13 trend in initiation)\n")
    f.write("- Cryptojacking: Gradual increase (+0.003 trend in initiation)\n\n")

    f.write("**Critical Events**:\n")
    f.write("- DoS peak: 7 seconds after attack start\n")
    f.write("- Recon peak: Immediate (0-1 seconds)\n")
    f.write("- Cryptojacking peak: Late (48 seconds)\n\n")

print(f"   ✅ Saved: {summary_file.name}")

print("\n" + "="*80)
print("✅ TASK 7 COMPLETE")
print("="*80)
print(f"\n📂 Tables saved to: {tables_dir}")
print(f"\nGenerated files:")
print(f"   - table1_attack_detection.md")
print(f"   - table2_temporal_patterns.md")
print(f"   - table3_lagged_correlations.md")
print(f"   - summary_all_tables.md (combined)")
