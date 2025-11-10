# ⚠️ WARNING: INVALID EXPERIMENTAL RESULTS

**Date Identified**: 2025-11-10
**Status**: 🚫 DO NOT USE THESE RESULTS

---

## Critical Data Leakage Issue

All machine learning experiments in this directory contain **severe data leakage** that invalidates the results.

### Problem

- ❌ **Data structure misunderstood**: 244 rows ≠ 244 independent samples
- ❌ **Temporal leakage**: Train/test split within same session time series
- ❌ **Insufficient samples**: Only 4 independent sessions (1 per class)
- ❌ **100% accuracy**: Result of temporal autocorrelation, not true classification

### What Happened

```
Each "aligned" file contains 61 time points of ONE session:
  - benign_aligned.csv:        1 session × 61 timepoints
  - dos_aligned.csv:           1 session × 61 timepoints
  - recon_aligned.csv:         1 session × 61 timepoints
  - cryptojacking_aligned.csv: 1 session × 61 timepoints

Train/test split randomly assigned time points:
  - Times 0-48sec → Training
  - Times 49-60sec → Test (from SAME session!)

Result: Model learned temporal continuity, NOT attack detection
```

### Invalid Files

```
results/ml_experiments/
├── host_only/
│   ├── ❌ model.pkl (invalid)
│   ├── ❌ metrics.json (100% accuracy - data leakage)
│   ├── ❌ confusion_matrix.png (misleading)
│   └── ❌ classification_report.txt (invalid)
│
├── 2layer/
│   ├── ❌ model.pkl (invalid)
│   ├── ❌ metrics.json (100% accuracy - data leakage)
│   ├── ❌ confusion_matrix.png (misleading)
│   └── ❌ classification_report.txt (invalid)
│
└── comparison/
    ├── ❌ summary_report.md (conclusions invalid)
    ├── ❌ performance_comparison.csv (meaningless)
    └── ❌ All visualizations (misleading)
```

---

## Correct Approach

### Option 1: Use Original Individual Session Files

**Required data**:
```
CICEVSE2024_Dataset/Host Events/Individual Files/
├── benign_session_001.csv
├── benign_session_002.csv
├── ...
├── dos_tcpflood_001.csv
├── dos_synflood_001.csv
├── ...

Minimum: 10+ independent sessions per attack type
```

**Download**: https://www.unb.ca/cic/datasets/evse-dataset-2024.html

### Option 2: Time Series Classification (4 samples only)

```python
# With only 4 sessions, use LOOCV
# Each 61-timepoint sequence = 1 sample
X.shape = (4, 61, 887)  # 4 sequences

# Use LSTM/GRU/TCN
# Leave-One-Out Cross-Validation
# Report as proof-of-concept only
```

### Option 3: Focus on Temporal Analysis

```
Accept that current data is for:
  ✅ Attack propagation timing
  ✅ Cross-layer correlation
  ✅ Pattern visualization
  ❌ NOT supervised classification
```

---

## See Full Documentation

**→ Read**: `/home/user/EV_charging_forensics/EXPERIMENTAL_ISSUES_AND_CORRECTIONS.md`

This document contains:
- Detailed root cause analysis
- Correct experimental approaches
- Lessons learned
- Recommended next steps

---

## Action Required

**DO NOT**:
- ❌ Publish these results
- ❌ Include in papers/reports
- ❌ Use these metrics

**DO**:
- ✅ Read correction document
- ✅ Decide on correct approach
- ✅ Re-run with proper methodology

---

**Created**: 2025-11-10
**Severity**: CRITICAL
**Impact**: All ML classification results invalid
