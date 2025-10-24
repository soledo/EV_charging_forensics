#!/usr/bin/env python3
"""
Task 6: Visualization - AlE'mari Figure 6 Style
Publication-quality 3-layer temporal evolution visualization
"""

import pandas as pd
import numpy as np
import json
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

base_dir = Path('/mnt/d/EV_charging_forensics')
aligned_dir = base_dir / 'results' / 'aligned_timelines'
results_dir = base_dir / 'results'
figures_dir = base_dir / 'figures'
figures_dir.mkdir(exist_ok=True, parents=True)

print("="*80)
print("TASK 6: PUBLICATION-QUALITY VISUALIZATION")
print("="*80)

# Set publication-quality style
plt.rcParams['font.size'] = 12
plt.rcParams['axes.labelsize'] = 12
plt.rcParams['axes.titlesize'] = 14
plt.rcParams['xtick.labelsize'] = 11
plt.rcParams['ytick.labelsize'] = 11
plt.rcParams['legend.fontsize'] = 11
plt.rcParams['figure.dpi'] = 300
plt.rcParams['savefig.dpi'] = 300

# Colorblind-friendly palette
colors = {
    'network': '#0173B2',  # Blue
    'host': '#DE8F05',     # Orange
    'power': '#029E73',    # Green
    'benign': '#949494'    # Gray
}

# Load correlation data
with open(results_dir / 'time_lagged_correlations.json', 'r') as f:
    correlations = json.load(f)

# Load temporal patterns
with open(results_dir / 'temporal_patterns.json', 'r') as f:
    patterns = json.load(f)

# ============================================================================
# FIGURE 1: Multi-Layer Temporal Evolution (3 subplots)
# ============================================================================

def plot_temporal_evolution(scenario, has_network=True):
    """
    Figure 1: Multi-layer temporal evolution with phase annotations
    """
    print(f"\n📊 Creating Figure 1: {scenario.upper()} temporal evolution...")

    # Load aligned timeline
    df = pd.read_csv(aligned_dir / f'{scenario}_aligned.csv')

    # Aggregate features
    host_cols = [col for col in df.columns if col.startswith('host_')]
    power_cols = [col for col in df.columns if col.startswith('power_')]

    host_intensity = df[host_cols].mean(axis=1)
    power_intensity = df[power_cols].mean(axis=1)

    # Create figure
    if has_network:
        net_cols = [col for col in df.columns if col.startswith('net_')]
        net_intensity = df[net_cols].mean(axis=1)

        fig, axes = plt.subplots(3, 1, figsize=(10, 9), sharex=True)
        fig.suptitle(f'{scenario.upper()} Attack: Multi-Layer Temporal Evolution', fontsize=16, fontweight='bold')

        # Subplot 1: Network
        ax = axes[0]
        ax.plot(df['time_rel'].values, net_intensity.values, color=colors['network'], linewidth=2, label='Network')
        ax.set_ylabel('Network Intensity', fontweight='bold')
        ax.grid(True, linestyle=':', alpha=0.3)
        ax.legend(loc='upper right')

        # Subplot 2: Host
        ax = axes[1]
        ax.plot(df['time_rel'].values, host_intensity.values, color=colors['host'], linewidth=2, label='Host')
        ax.set_ylabel('Host Intensity', fontweight='bold')
        ax.grid(True, linestyle=':', alpha=0.3)
        ax.legend(loc='upper right')

        # Subplot 3: Power
        ax = axes[2]
        ax.plot(df['time_rel'].values, power_intensity.values, color=colors['power'], linewidth=2, label='Power')
        ax.set_ylabel('Power (mW)', fontweight='bold')
        ax.set_xlabel('Time Relative to Attack Start (seconds)', fontweight='bold')
        ax.grid(True, linestyle=':', alpha=0.3)
        ax.legend(loc='upper right')

        # Phase boundaries (vertical lines at 10s and 30s)
        for ax in axes:
            ax.axvline(x=10, color='gray', linestyle='--', alpha=0.5, linewidth=1)
            ax.axvline(x=30, color='gray', linestyle='--', alpha=0.5, linewidth=1)

        # Phase labels (only on top subplot)
        axes[0].text(5, axes[0].get_ylim()[1] * 0.9, 'Initiation', ha='center', fontsize=10, style='italic')
        axes[0].text(20, axes[0].get_ylim()[1] * 0.9, 'Peak', ha='center', fontsize=10, style='italic')
        axes[0].text(45, axes[0].get_ylim()[1] * 0.9, 'Sustained', ha='center', fontsize=10, style='italic')

    else:
        # 2-layer (no network)
        fig, axes = plt.subplots(2, 1, figsize=(10, 6), sharex=True)
        fig.suptitle(f'{scenario.upper()}: Multi-Layer Temporal Evolution', fontsize=16, fontweight='bold')

        # Subplot 1: Host
        ax = axes[0]
        ax.plot(df['time_rel'].values, host_intensity.values, color=colors['host'], linewidth=2, label='Host')
        ax.set_ylabel('Host Intensity', fontweight='bold')
        ax.grid(True, linestyle=':', alpha=0.3)
        ax.legend(loc='upper right')

        # Subplot 2: Power
        ax = axes[1]
        ax.plot(df['time_rel'].values, power_intensity.values, color=colors['power'], linewidth=2, label='Power')
        ax.set_ylabel('Power (mW)', fontweight='bold')
        ax.set_xlabel('Time Relative to Attack Start (seconds)', fontweight='bold')
        ax.grid(True, linestyle=':', alpha=0.3)
        ax.legend(loc='upper right')

        # Phase boundaries
        for ax in axes:
            ax.axvline(x=10, color='gray', linestyle='--', alpha=0.5, linewidth=1)
            ax.axvline(x=30, color='gray', linestyle='--', alpha=0.5, linewidth=1)

        # Phase labels
        axes[0].text(5, axes[0].get_ylim()[1] * 0.9, 'Initiation', ha='center', fontsize=10, style='italic')
        axes[0].text(20, axes[0].get_ylim()[1] * 0.9, 'Peak', ha='center', fontsize=10, style='italic')
        axes[0].text(45, axes[0].get_ylim()[1] * 0.9, 'Sustained', ha='center', fontsize=10, style='italic')

    plt.tight_layout()

    # Save
    output_file = figures_dir / f'figure1_{scenario}_temporal_evolution.png'
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"   ✅ Saved: {output_file.name}")

# ============================================================================
# FIGURE 2: Time-Lagged Correlation Heatmaps
# ============================================================================

def plot_lagged_correlation(scenario, has_network=True):
    """
    Figure 2: Time-lagged correlation heatmap
    """
    print(f"\n📊 Creating Figure 2: {scenario.upper()} lagged correlation...")

    corr_data = correlations[scenario]['correlations']

    # Extract correlation matrices
    if has_network:
        layer_pairs = ['net_host', 'host_power', 'net_power']
        pair_labels = ['Network → Host', 'Host → Power', 'Network → Power']
    else:
        layer_pairs = ['host_power']
        pair_labels = ['Host → Power']

    # Build correlation matrix (lags × pairs)
    lags = range(-10, 11)
    corr_matrix = []

    for pair in layer_pairs:
        if pair in corr_data:
            lag_corrs = corr_data[pair]['lag_correlations']
            r_values = [lc['r'] for lc in lag_corrs]
            corr_matrix.append(r_values)

    corr_matrix = np.array(corr_matrix).T  # Transpose: rows=lags, cols=pairs

    # Create heatmap
    fig, ax = plt.subplots(figsize=(8, 10))

    sns.heatmap(corr_matrix, ax=ax,
                xticklabels=pair_labels,
                yticklabels=list(lags),
                cmap='RdBu_r', center=0, vmin=-1, vmax=1,
                cbar_kws={'label': 'Correlation Coefficient (r)'},
                annot=False, fmt='.2f')

    ax.set_xlabel('Layer Pair', fontweight='bold')
    ax.set_ylabel('Time Lag (seconds)', fontweight='bold')
    ax.set_title(f'{scenario.upper()} Attack: Time-Lagged Cross-Layer Correlation', fontsize=14, fontweight='bold')

    # Annotate optimal lags
    for i, pair in enumerate(layer_pairs):
        if pair in corr_data:
            optimal_lag = corr_data[pair]['optimal_lag']
            optimal_r = corr_data[pair]['optimal_r']
            lag_idx = optimal_lag + 10  # Convert lag to index (lag=-10 → idx=0)

            ax.text(i + 0.5, lag_idx + 0.5, f'★\n{optimal_r:.2f}',
                   ha='center', va='center', fontsize=10, fontweight='bold', color='black')

    plt.tight_layout()

    # Save
    output_file = figures_dir / f'figure2_{scenario}_lagged_correlation.png'
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"   ✅ Saved: {output_file.name}")

# ============================================================================
# FIGURE 3: Phase Comparison Bar Charts
# ============================================================================

def plot_phase_comparison():
    """
    Figure 3: Phase comparison across scenarios
    """
    print(f"\n📊 Creating Figure 3: Phase comparison...")

    # Extract phase statistics for all scenarios
    scenarios = ['dos', 'recon', 'cryptojacking']
    phases = ['initiation', 'peak', 'sustained']
    layers = ['host', 'net', 'power']

    data = []

    for scenario in scenarios:
        scenario_patterns = patterns[scenario]['phases']

        for phase in phases:
            for layer in layers:
                key = f'{phase}_{layer}'
                if key in scenario_patterns:
                    stats = scenario_patterns[key]
                    data.append({
                        'scenario': scenario.upper(),
                        'phase': phase.capitalize(),
                        'layer': layer.capitalize(),
                        'mean': stats['mean'],
                        'std': stats['std']
                    })

    df_data = pd.DataFrame(data)

    # Create figure with 3 subplots (one per layer)
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    fig.suptitle('Phase Comparison Across Attack Scenarios', fontsize=16, fontweight='bold')

    for i, layer in enumerate(['Host', 'Net', 'Power']):
        ax = axes[i]

        layer_data = df_data[df_data['layer'] == layer]

        if len(layer_data) == 0:
            continue

        # Pivot for grouped bar chart
        pivot_data = layer_data.pivot_table(index='phase', columns='scenario', values='mean')
        pivot_std = layer_data.pivot_table(index='phase', columns='scenario', values='std')

        pivot_data.plot(kind='bar', ax=ax, yerr=pivot_std, capsize=4,
                       color=[colors['host'], colors['network'], colors['power']])

        ax.set_title(f'{layer} Layer', fontweight='bold')
        ax.set_ylabel('Mean Intensity', fontweight='bold')
        ax.set_xlabel('Phase', fontweight='bold')
        ax.legend(title='Scenario', loc='upper right')
        ax.grid(True, linestyle=':', alpha=0.3, axis='y')
        ax.set_xticklabels(ax.get_xticklabels(), rotation=0)

    plt.tight_layout()

    # Save
    output_file = figures_dir / 'figure3_phase_comparison.png'
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"   ✅ Saved: {output_file.name}")

# ============================================================================
# Generate All Figures
# ============================================================================

scenarios = {
    'dos': {'has_network': True},
    'recon': {'has_network': True},
    'cryptojacking': {'has_network': False},
    'benign': {'has_network': False}
}

# Figure 1: Temporal evolution (all scenarios)
for scenario, config in scenarios.items():
    plot_temporal_evolution(scenario, has_network=config['has_network'])

# Figure 2: Lagged correlation (attack scenarios only)
for scenario in ['dos', 'recon', 'cryptojacking']:
    has_network = scenario in ['dos', 'recon']
    plot_lagged_correlation(scenario, has_network=has_network)

# Figure 3: Phase comparison
plot_phase_comparison()

print("\n" + "="*80)
print("✅ TASK 6 COMPLETE")
print("="*80)
print(f"\n📂 Figures saved to: {figures_dir}")
print(f"\nGenerated files:")
print(f"   - figure1_*_temporal_evolution.png (4 files)")
print(f"   - figure2_*_lagged_correlation.png (3 files)")
print(f"   - figure3_phase_comparison.png")
