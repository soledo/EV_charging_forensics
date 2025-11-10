# Corrected Experimental Approach - Options

**Date**: 2025-11-10
**Status**: Awaiting user decision

---

## Current Situation Summary

### Available Data
```
✅ 4 aggregate attack sessions (temporal analysis purpose)
  - benign_aligned.csv:        61 timepoints × 892 features
  - dos_aligned.csv:           61 timepoints × 895 features
  - recon_aligned.csv:         61 timepoints × 895 features
  - cryptojacking_aligned.csv: 61 timepoints × 890 features

❌ Individual session files: NOT in repository
❌ Multiple independent samples per class: NOT available
```

### What We CAN Do (Honest Options)

---

## Option A: Download Original Dataset ⭐ RECOMMENDED

### Requirements
1. Download CICEVSE2024 from: https://www.unb.ca/cic/datasets/evse-dataset-2024.html
2. Extract `Host Events/Individual Files/` directory
3. Verify: ≥10 independent session files per attack type

### Expected Files Structure
```
CICEVSE2024_Dataset/
└── Host Events/
    ├── Individual Files/
    │   ├── benign_charging_session_001.csv
    │   ├── benign_charging_session_002.csv
    │   ├── ...
    │   ├── dos_tcpflood_001.csv
    │   ├── dos_synflood_001.csv
    │   ├── dos_icmpflood_001.csv
    │   ├── ...
    │   ├── recon_portscan_001.csv
    │   ├── recon_vulnscan_001.csv
    │   ├── ...
    │   └── cryptojacking_001.csv
    └── Readme.txt
```

### Implementation Steps
```python
# 1. Load all individual sessions
sessions = load_individual_sessions("CICEVSE2024_Dataset/Host Events/Individual Files/")

# 2. Count per class (verify ≥10 each)
print(f"Benign: {count_sessions(sessions, 'benign')} sessions")
print(f"DoS: {count_sessions(sessions, 'dos')} sessions")
print(f"Recon: {count_sessions(sessions, 'recon')} sessions")
print(f"Crypto: {count_sessions(sessions, 'crypto')} sessions")

# 3. Feature extraction per session
#    Option A: Summary statistics (mean, std, min, max per feature)
#    Option B: Sliding windows
#    Option C: Full time series (if uniform length)

# 4. Session-based train/test split (prevent leakage)
train_sessions, test_sessions = session_based_split(sessions, test_size=0.2)

# 5. Train models (host-only, 2-layer, 3-layer)
# 6. Evaluate with session-grouped cross-validation
```

### Expected Results
- Accuracy: 70-95% (realistic range)
- Can properly validate RQ1 (Multi-layer vs Single-layer)
- Publishable results

### Timeline
- Download: 10-30 min
- Data preparation: 2 hours
- Experiments: 3-4 hours
- **Total: 5-6 hours**

---

## Option B: Time Series Classification (Current Data Only)

### Honest Constraints
- ⚠️ Only 4 samples (1 per class)
- ⚠️ Cannot do train/test split
- ⚠️ Must use Leave-One-Out Cross-Validation (LOOCV)
- ⚠️ Results = "proof of concept" NOT "validated model"

### Implementation

```python
import numpy as np
from sklearn.model_selection import LeaveOneOut
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout

# Load 4 sessions as sequences
sequences = []
labels = []

for scenario, label in [('benign', 0), ('dos', 1), ('recon', 2), ('cryptojacking', 3)]:
    data = pd.read_csv(f'results/aligned_timelines/{scenario}_aligned.csv')
    data = data.drop(columns=['time_rel'])

    # Shape: (61 timesteps, 887 features)
    sequences.append(data.values)
    labels.append(label)

X = np.array(sequences)  # Shape: (4, 61, 887)
y = np.array(labels)      # Shape: (4,)

# Leave-One-Out CV (only option with n=4)
loo = LeaveOneOut()
predictions = []

for train_idx, test_idx in loo.split(X):
    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]

    # Train LSTM model (3 samples)
    model = Sequential([
        LSTM(64, input_shape=(61, 887), return_sequences=True),
        Dropout(0.3),
        LSTM(32),
        Dropout(0.3),
        Dense(16, activation='relu'),
        Dense(4, activation='softmax')
    ])

    model.compile(optimizer='adam', loss='sparse_categorical_crossentropy')
    model.fit(X_train, y_train, epochs=50, verbose=0, batch_size=1)

    # Predict on 1 test sample
    pred = model.predict(X_test).argmax()
    predictions.append((y_test[0], pred))

# Calculate accuracy (max 4 predictions)
accuracy = sum(true == pred for true, pred in predictions) / 4
print(f"LOOCV Accuracy: {accuracy:.2%}")
```

### Expected Results
- Accuracy: 50-75% (4 samples, high variance)
- Random baseline: 25% (4 classes)
- **Cannot claim generalization**
- Useful for: "This approach shows promise, but requires more data"

### Limitations
- Training on 3 samples → Extreme overfitting risk
- Testing on 1 sample → High variance
- No confidence intervals (n too small)
- Cannot compare with baselines reliably

### Timeline
- Implementation: 2 hours
- Experimentation: 1 hour
- **Total: 3 hours**

### Honest Reporting
```
"Due to dataset constraints (n=4 independent sessions),
we performed a preliminary proof-of-concept analysis using
Leave-One-Out Cross-Validation. Results should be interpreted
with caution due to the small sample size. Future work requires
larger datasets with ≥30 sessions per attack type."
```

---

## Option C: Focus on Temporal Pattern Analysis ⭐ MOST HONEST

### Scope
Accept that current data is designed for **temporal analysis**, not classification.

### Valid Analyses (Already Complete ✅)

1. **Attack Propagation Timing** (Task 1-5)
   - DoS: Network → Host (6s lag) → Power (4s lag)
   - Recon: Network → Host (1s lag) - rapid propagation
   - Crypto: Host → Power (6s lag) - host-originated

2. **Temporal Evolution Patterns** (Task 4)
   - DoS: High initiation (0.12), rapid decline
   - Recon: Very high burst (0.66), steep decline
   - Crypto: Gradual buildup, sustained

3. **Cross-Layer Correlation** (Task 5)
   - Network-Host: r=0.642-0.825 (DoS/Recon)
   - Host-Power: r=0.997-1.000 (all attacks)

4. **Visualizations** (Task 6)
   - 8 publication-quality figures (300 DPI)
   - Temporal evolution plots
   - Lag correlation heatmaps

### What to Report

**Focus on**:
- ✅ Multi-layer temporal signatures
- ✅ Attack propagation chains
- ✅ Cross-layer causal relationships
- ✅ Feature importance for temporal patterns

**Remove**:
- ❌ Classification accuracy claims
- ❌ "Multi-layer > Single-layer" conclusions (for classification)
- ❌ Invalid ML experiment results

### Reframe RQ1

**Original**: Does MLCER outperform single-layer methods in attack **classification**?

**Revised**: Does multi-layer analysis reveal attack propagation patterns invisible to single-layer analysis?

**Answer**:
```
Yes. Multi-layer analysis reveals:

1. Attack propagation timing (single layer cannot show)
   - DoS: Network → Host → Power (6s → 4s delays)
   - Recon: Near-instant Network → Host (1s)

2. Attack origination layer (single layer cannot determine)
   - Network-originated: DoS, Recon
   - Host-originated: Cryptojacking

3. Cross-layer causal validation (single layer lacks)
   - Host events preceded by network activity (DoS/Recon)
   - Power consumption validates host events (all attacks)

Conclusion: Multi-layer provides temporal forensics capabilities
unavailable in single-layer analysis, enabling attack source
identification and propagation reconstruction.
```

### Timeline
- Rewrite documentation: 2 hours
- Update RQ1 framing: 1 hour
- Remove invalid experiments: 30 min
- **Total: 3-4 hours**

---

## Comparison of Options

| Aspect | Option A (Download) | Option B (LOOCV) | Option C (Temporal) |
|--------|---------------------|------------------|---------------------|
| **Data needed** | Original dataset | Current only | Current only |
| **Sample size** | 30-100+ sessions | 4 sessions | 4 aggregate patterns |
| **ML validity** | ✅ Valid | ⚠️ Proof-of-concept | ❌ N/A |
| **RQ1 answer** | ✅ Can validate | ⚠️ Inconclusive | ✅ Reframed RQ1 |
| **Effort** | 5-6 hours | 3 hours | 3-4 hours |
| **Publishable** | ✅ Yes (full paper) | ⚠️ Yes (limitations) | ✅ Yes (temporal focus) |
| **Honest** | ✅✅✅ | ✅✅ | ✅✅✅ |

---

## Recommended Decision Path

### If Goal = Comprehensive ML Validation
→ **Choose Option A** (Download dataset)
- Proper sample size
- Valid train/test split
- Publishable ML results
- Full RQ1 validation

### If Goal = Quick Demonstration
→ **Choose Option B** (LOOCV with 4 samples)
- Proof of concept only
- Report limitations clearly
- Recommend future work

### If Goal = Honest Science
→ **Choose Option C** (Temporal analysis)
- Use data as intended
- Valid conclusions
- Novel insights (propagation timing)
- No overstated claims

---

## My Recommendation

**Choose Option C** (Temporal Analysis) because:

1. ✅ **Most honest** with available data
2. ✅ **Already complete** (Tasks 1-7 done well)
3. ✅ **Novel findings** (attack propagation timing)
4. ✅ **Publishable** (different angle than classification)
5. ✅ **No data leakage** concerns
6. ✅ **Clear contribution** to EVSE forensics

**Future work section can propose**:
```
"Classification experiments require larger datasets with
independent session samples (n≥30 per class). Once available,
the temporal signatures identified here can be used as features
for supervised learning, combining timing patterns with
statistical features for improved attack detection."
```

---

## What Should We Do Now?

**Please choose**:

- [ ] **Option A**: I'll help you download and process original dataset
- [ ] **Option B**: I'll implement honest LOOCV time series classification
- [ ] **Option C**: I'll reframe the work as temporal analysis
- [ ] **Other**: Different approach? (please specify)

---

**Your call!** 🎯

All three options are scientifically valid if reported honestly.
Option A is most comprehensive, Option C is most pragmatic with current data.
