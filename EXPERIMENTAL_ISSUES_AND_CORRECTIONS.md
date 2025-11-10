# Experimental Issues and Corrections

**Date**: 2025-11-10
**Status**: ⚠️ CRITICAL ISSUES IDENTIFIED - EXPERIMENTS INVALID

---

## 🚨 Critical Issue: Data Leakage in ML Experiments

### Problem Summary

The machine learning experiments conducted in `results/ml_experiments/` contain **severe data leakage** that invalidates all results.

### What Went Wrong

#### 1. **Misunderstood Data Structure**

**Assumption (WRONG)**:
```
244 samples = 61 time points × 4 scenarios
Each row = independent attack sample
Train/Test split: 195/49 random samples
```

**Reality**:
```
4 samples = 4 aggregate scenarios
Each 61 rows = single session's time series (0-60 seconds)
```

#### 2. **Data Files Analyzed**

```
results/aligned_timelines/
├── benign_aligned.csv          (61 time points of 1 benign session)
├── dos_aligned.csv             (61 time points of 1 DoS aggregate)
├── recon_aligned.csv           (61 time points of 1 Recon aggregate)
└── cryptojacking_aligned.csv   (61 time points of 1 Crypto session)

Total: 4 independent sessions, NOT 244 samples
```

#### 3. **Temporal Data Leakage**

**What happened**:
```python
# DoS session (one continuous time series: 0-60 seconds)
Time 0-48 sec  → TRAINING SET ✅
Time 49-60 sec → TEST SET ✅

Result: 100% accuracy
```

**Why it's wrong**:
- ❌ Train and test are from **same session**
- ❌ Temporal continuity allows perfect prediction
- ❌ Model learns "next time point" not "new attack detection"
- ❌ Like predicting 49°C after seeing 0-48°C temperature curve

#### 4. **Insufficient Independent Samples**

```
Actual independent samples: 4
  - 1 benign session
  - 1 DoS aggregate session
  - 1 Recon aggregate session
  - 1 Cryptojacking session

Machine learning requirement: n ≥ 30 per class
Current state: n = 1 per class → IMPOSSIBLE
```

---

## 📊 Invalid Results

### All metrics from these experiments are INVALID:

1. ❌ `results/ml_experiments/host_only/` - 100% accuracy (data leakage)
2. ❌ `results/ml_experiments/2layer/` - 100% accuracy (data leakage)
3. ❌ `results/ml_experiments/comparison/` - All comparisons invalid
4. ❌ **RQ1 conclusion**: "Performance parity" → CANNOT BE VALIDATED

### Why 100% Accuracy Occurred

Not because features are good, but because:
```
Test samples = future time points of training session
Model learned: If t=48 looks like X, then t=49 looks like X+δ
This is temporal autocorrelation, NOT attack classification
```

---

## 🔍 Root Cause Analysis

### Original Project Purpose

This repository was designed for:
- ✅ **Temporal alignment analysis** (attack propagation timing)
- ✅ **Cross-layer correlation** (network → host → power lags)
- ✅ **Pattern visualization** (temporal evolution curves)
- ❌ **NOT for ML classification** (insufficient samples)

The `aligned_timelines/` data is:
- Aggregate timelines for **visualization**
- Attack-relative normalized for **pattern comparison**
- **NOT suitable for supervised classification**

### What Should Have Been Used

**Option A: Original CICEVSE2024 Dataset**
```
CICEVSE2024_Dataset/
└── Host Events/
    └── Individual Files/
        ├── benign_session_001.csv
        ├── benign_session_002.csv
        ├── benign_session_00N.csv
        ├── dos_tcpflood_001.csv
        ├── dos_synflood_001.csv
        ├── recon_portscan_001.csv
        ├── recon_vulnscan_001.csv
        ├── cryptojacking_001.csv
        ...

Each file = independent session = valid ML sample
Required: N sessions per attack type (N ≥ 10-20 minimum)
```

**Status**: Original dataset files NOT available in repository

---

## ✅ Correct Approaches

### Approach 1: Obtain Original Individual Sessions

**If original data available**:
```python
# Count independent sessions
sessions = {
    'benign': [],      # Need ≥10 sessions
    'dos': [],         # Need ≥10 sessions (various subtypes)
    'recon': [],       # Need ≥10 sessions (various subtypes)
    'crypto': []       # Need ≥10 sessions
}

# Session-based split (NO temporal leakage)
train_sessions, test_sessions = split_by_session(sessions)

# Each entire session goes to either train OR test
# NEVER split a single session across train/test
```

**Expected scenarios** (from CLAUDE.md):
- Benign: Multiple sessions
- DoS: 8 subtypes (slowloris, udp-flood, icmp-flood, etc.) → 8+ sessions
- Recon: 6 subtypes (port-scan, vuln-scan, os-fingerprint, etc.) → 6+ sessions
- Cryptojacking: Multiple sessions
- Backdoor: Multiple sessions

**Minimum requirement**: 10-20 independent sessions per class

### Approach 2: Time Series Classification (Current Data Only)

**With only 4 sessions**:
```python
# Treat each 61-timepoint sequence as one sample
X_shape: (4, 61, 887)  # 4 samples, 61 timesteps, 887 features

# Leave-One-Out Cross-Validation (only option with n=4)
for i in range(4):
    train_idx = [0,1,2,3]
    train_idx.remove(i)
    test_idx = i

    # Train on 3 sequences, test on 1
    # Use LSTM, Transformer, or 1D-CNN

# Expected result: ~75% accuracy (25% = random baseline for 4 classes)
```

**Model choices**:
- LSTM (Long Short-Term Memory)
- GRU (Gated Recurrent Unit)
- Temporal Convolutional Network (TCN)
- Transformer with positional encoding

**Limitations**:
- Only 3 training samples per fold
- High variance (1 test sample per fold)
- Cannot claim generalization
- Useful for proof-of-concept only

### Approach 3: Feature Aggregation per Session

```python
# Summarize 61 time points into statistics
def aggregate_session(session_timeseries):
    features = []
    for col in session_timeseries.columns:
        features.extend([
            session_timeseries[col].mean(),
            session_timeseries[col].std(),
            session_timeseries[col].min(),
            session_timeseries[col].max(),
            session_timeseries[col].quantile(0.25),
            session_timeseries[col].quantile(0.75)
        ])
    return features

# Result: 4 samples × (887 features × 6 stats) = 4 × 5,322
# Still n=4 → TOO SMALL FOR ML
```

### Approach 4: Stay Within Original Scope

**Most realistic option**:
```
Accept that this dataset is for:
  ✅ Temporal pattern analysis
  ✅ Attack propagation timing
  ✅ Cross-layer correlation
  ❌ NOT for supervised ML classification

Continue with original analyses:
  - Task 1-7 (already complete)
  - Temporal evolution characterization
  - Lag correlation analysis
  - Visualization of attack signatures
```

---

## 📁 Action Items

### Immediate Actions

1. ✅ **Mark invalid experiments**
   - Add warning to all files in `results/ml_experiments/`
   - Document data leakage in summary reports

2. ✅ **Create this correction document**
   - Explain the issue clearly
   - Provide correct approaches

3. 🔲 **Decide on path forward**:
   - **Option A**: Download CICEVSE2024 original dataset
   - **Option B**: Implement time series classification (4 samples LOOCV)
   - **Option C**: Remove ML experiments, focus on temporal analysis

### To Download Original Dataset

**Source**: https://www.unb.ca/cic/datasets/evse-dataset-2024.html

**Required files**:
```
CICEVSE2024_Dataset/
└── Host Events/
    ├── EVSE-B-HPC-Kernel-Events-Combined.csv
    └── Individual Files/
        └── [All individual session CSV files]
```

**Verification**:
```bash
# Count independent sessions
ls Individual\ Files/ | wc -l

# Should be: 30+ files minimum for valid ML
```

### If Continuing with Current Data

**Accept limitations**:
- Only 4 samples → Leave-One-Out CV
- Use time series models (LSTM/TCN)
- Report as "proof of concept" not "validated results"
- Emphasize temporal analysis (original purpose)

---

## 📝 Lessons Learned

### Mistake 1: Assumed Row Independence
```
⚠️ Never assume rows are independent samples
✅ Always check: Is this time series? Grouped data? Sessions?
```

### Mistake 2: Ignored Data Generation Process
```
⚠️ "aligned_timelines" name should have been a clue
✅ Read documentation: What was data created for?
```

### Mistake 3: Perfect Accuracy Red Flag
```
⚠️ 100% accuracy → ALWAYS investigate for leakage
✅ Cross-validate with domain experts
✅ Check temporal/spatial dependencies
```

### Mistake 4: Rushed Experimentation
```
⚠️ Saw 244 rows, assumed 244 samples, ran experiments
✅ Exploratory data analysis FIRST
✅ Understand data provenance
✅ Check for grouping structures
```

---

## ✅ Corrected Experimental Plan

### Phase 0: Data Acquisition ⚠️ REQUIRED

```bash
# Download CICEVSE2024 dataset
wget [dataset_url]

# Or request from authors
# Or work with current data constraints
```

### Phase 1: Data Understanding

```python
# Count TRUE independent samples
individual_files = list_all_session_files()
print(f"Independent sessions: {len(individual_files)}")

# By class
for attack_type in ['benign', 'dos', 'recon', 'crypto', 'backdoor']:
    sessions = filter_by_type(individual_files, attack_type)
    print(f"{attack_type}: {len(sessions)} sessions")

# Minimum requirement: 10+ per class
```

### Phase 2: Session-Based Split

```python
# Group by session ID (prevent leakage)
sessions_by_id = group_by_session_id(data)

# Stratified session split
train_sessions, test_sessions = train_test_split(
    sessions_by_id,
    test_size=0.2,
    stratify=session_labels,
    random_state=42
)

# Validation
assert set(train_sessions).isdisjoint(set(test_sessions))
```

### Phase 3: Feature Engineering

```python
# Option A: Flatten time series (if short sessions)
# Option B: Summary statistics per session
# Option C: Sliding windows (if long sessions)
# Option D: Recurrent models (LSTM) for sequences
```

### Phase 4: Modeling with Cross-Validation

```python
# Session-grouped K-fold CV
from sklearn.model_selection import GroupKFold

cv = GroupKFold(n_splits=5)
scores = cross_val_score(
    model, X, y,
    cv=cv,
    groups=session_ids  # Prevent session leakage
)
```

---

## 📚 References

### Data Leakage in Time Series

1. **Temporal Leakage**: Using future to predict present
2. **Group Leakage**: Splitting grouped data randomly
3. **Preprocessing Leakage**: Fitting scalers on full dataset

### Proper Time Series Validation

- Time series split (forward chaining)
- Session-based split (grouped CV)
- Leave-One-Session-Out CV
- Temporal gap between train/test

---

## 🎯 Recommended Next Steps

### Option A: Full Replication (Best)
1. Download CICEVSE2024 Individual Files
2. Count sessions per attack type
3. If n≥10 per class: Run proper classification
4. Session-based split + grouped CV
5. Report valid results

### Option B: Constrained Analysis (Realistic)
1. Use current 4 aggregate sessions
2. LOOCV time series classification
3. Report as "preliminary proof-of-concept"
4. Emphasize temporal pattern findings (Tasks 1-7)
5. Recommend future work with more data

### Option C: Scope Adjustment (Pragmatic)
1. Remove ML classification experiments
2. Focus on original goal: Temporal analysis
3. Publish Tasks 1-7 results
4. Discuss attack propagation patterns
5. Recommend classification as future work

---

## ⚠️ Status: AWAITING USER DECISION

**Current state**: Invalid ML results identified and documented

**User must decide**:
- [ ] Download original dataset → Approach A
- [ ] Use LOOCV with 4 sessions → Approach B
- [ ] Remove ML, focus on temporal → Approach C
- [ ] Other approach?

---

**Document created**: 2025-11-10
**Author**: MLCER Team (correcting previous errors)
**Priority**: CRITICAL - Invalid results must not be published
