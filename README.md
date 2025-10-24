# Multi-Layer Cyber Event Reconstruction for EV Charging Infrastructure

**얼추 맞추기 (Approximate Alignment)** - Attack-Relative Time Normalization Strategy

## 📊 Overview

This project implements multi-layer temporal alignment and analysis for cyber attack detection in EV charging infrastructure using the CICEVSE2024 dataset.

**Key Challenge**: Dataset layers (Host, Network, Power) were captured at different times with no temporal overlap.

**Solution**: Attack-relative time normalization with ±2.5s tolerance window ("얼추 맞추기" strategy).

## 🎯 Key Findings

### Attack Propagation Patterns

**DoS Attack**:
- Network → Host: 6-second lag (r=0.642, p<0.0001)
- Host → Power: 4-second lag (r=1.000, p<0.0001)
- **Propagation chain**: Network → Host (6s) → Power (4s)

**Reconnaissance Attack**:
- Network → Host: 1-second lag (r=0.825, p<0.0001) - instant propagation!
- Host → Power: 6-second lag (r=1.000, p<0.0001)
- **Characteristic**: Rapid burst at attack onset

**Cryptojacking Attack**:
- Host → Power: 6-second lag (r=0.997, p<0.0002)
- **Characteristic**: Gradual buildup, late peak at 48s

### Temporal Signatures

| Attack Type | Initiation (0-10s) | Peak (10-30s) | Sustained (30-60s) |
|-------------|-------------------|---------------|-------------------|
| DoS | High activity (0.12), rapid decline | Moderate (0.06), negative trend | Stabilized low (0.04) |
| Recon | Very high (0.66), steep decline (-0.13) | Declining (0.23) | Low activity (0.07) |
| Cryptojacking | Low (0.06), gradual increase | Moderate (0.08) | Sustained (0.07) |

## 📁 Repository Structure

```
.
├── scripts/
│   ├── preprocessing/        # Data preprocessing scripts
│   ├── analysis/             # Analysis scripts (Task 1-7)
│   ├── integration/          # Layer integration scripts
│   └── reconstruction/       # Event reconstruction attempts
├── results/
│   ├── aligned_timelines/    # Multi-layer aligned data (61×~900)
│   ├── normalized_timelines/ # Attack-relative normalized data
│   ├── tables/               # Statistical summary tables
│   ├── attack_start_points.json
│   ├── temporal_patterns.json
│   ├── time_lagged_correlations.json
│   └── COMPLETION_SUMMARY.md
├── figures/                  # Publication-quality visualizations (8 figures)
│   ├── figure1_*_temporal_evolution.png
│   ├── figure2_*_lagged_correlation.png
│   └── figure3_phase_comparison.png
└── processed/
    └── reconstruction/       # Investigation reports
        ├── CRITICAL_FINDINGS.md
        └── PROGRESS_SUMMARY.md
```

## 🔬 Methodology

### 7-Task Pipeline

1. **Task 1**: Attack Start Detection (2σ anomaly detection)
2. **Task 2**: Relative Time Normalization (T_attack=0, 0-60s window)
3. **Task 3**: Multi-Layer Alignment (±2.5s tolerance)
4. **Task 4**: Temporal Evolution Characterization (3-phase analysis)
5. **Task 5**: Time-Lagged Cross-Layer Correlation (-10s to +10s)
6. **Task 6**: Visualization (8 figures, 300 DPI)
7. **Task 7**: Statistical Summary Tables

### Key Parameters

- **Alignment tolerance**: ±2.5 seconds (5s total window)
- **Resampling**: 1-second intervals
- **Missing data handling**: Forward fill (max 5 seconds)
- **Detection threshold**: Benign baseline + 2σ
- **Confirmation window**: 10 seconds

## 🚀 Usage

### Prerequisites

```bash
pip install pandas numpy scipy matplotlib seaborn
```

### Run Analysis Pipeline

```bash
# Task 1: Detect attack starts
python3 scripts/analysis/task1_detect_attack_starts.py

# Task 2: Normalize to attack-relative time
python3 scripts/analysis/task2_normalize_relative_time.py

# Task 3: Align layers with ±2.5s window
python3 scripts/analysis/task3_align_multilayer.py

# Task 4: Characterize temporal evolution
python3 scripts/analysis/task4_temporal_evolution.py

# Task 5: Compute lagged correlations
python3 scripts/analysis/task5_time_lagged_correlation.py

# Task 6: Generate figures
python3 scripts/analysis/task6_visualization.py

# Task 7: Create summary tables
python3 scripts/analysis/task7_summary_tables.py
```

## 📊 Results

### Generated Outputs (31 files)

**Figures (8)**: Publication-quality 300 DPI PNG files
- 4× Multi-layer temporal evolution plots
- 3× Time-lagged correlation heatmaps
- 1× Phase comparison bar chart

**Data (11)**: Aligned and normalized timelines
- 4× Aligned timelines (61 rows × ~900 columns)
- Attack start points, temporal patterns, correlations (JSON)

**Tables (4)**: Markdown statistical summaries
- Attack detection results
- Temporal pattern summary
- Lagged correlation analysis
- Combined summary with key findings

### View Results

```bash
# View figures
ls -lh figures/

# Read summary tables
cat results/tables/summary_all_tables.md

# Check aligned data
head results/aligned_timelines/dos_aligned.csv
```

## ⚠️ Limitations

1. **Not True Event Reconstruction**: Attack-relative alignment, not absolute temporal reconstruction
2. **Data Quality**: Power data has 82% missing rate in attack scenarios
3. **Temporal Approximation**: ±2.5s window introduces smoothing
4. **Dataset Issue**: Network (Dec 21) vs Power (Dec 24-30) - different recording sessions

## 📖 Citation

If you use this code or methodology, please cite:

```
Multi-Layer Cyber Event Reconstruction for EV Charging Infrastructure
Attack-Relative Time Normalization Strategy ("얼추 맞추기")
Dataset: CICEVSE2024 - EV Charging Security Dataset
Analysis Date: 2025-10-25
```

## 📝 License

This project is for research and educational purposes. Dataset credit: CICEVSE2024.

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description

## 📧 Contact

For questions or collaboration:
- Open an issue in this repository
- Refer to `results/COMPLETION_SUMMARY.md` for detailed analysis

---

**Generated**: 2025-10-25
**Status**: ✅ Complete (All 7 tasks)
**Next Steps**: Classification modeling, feature selection, or data recollection for true reconstruction
