# Realistic Experimental Plan: Machine Learning Classification

## Executive Summary

**Goal**: Implement and validate RQ1 (Multi-layer vs Single-layer attack classification) using existing aligned dataset.

**Current State**:
- ✅ Data preprocessed and aligned (Attack-relative time normalization)
- ✅ Temporal analysis complete (Task 1-7)
- ✅ 244 samples ready (61 per scenario × 4 scenarios)
- ⚠️ Power data 82% missing → Limited power-only baseline

**Realistic Target**: Implement and compare 4 approaches within 2-3 days:
1. Host-only baseline
2. Network-only baseline
3. Host+Network (2-layer)
4. Host+Network+Power (3-layer with missing data handling)

---

## Data Inventory

### Available Data
```
results/aligned_timelines/
├── benign_aligned.csv          (61 samples × 896 features)
├── dos_aligned.csv             (61 samples × 896 features)
├── recon_aligned.csv           (61 samples × 896 features)
└── cryptojacking_aligned.csv   (61 samples × 896 features)
```

### Feature Distribution
| Layer | Features | Missing Rate | Status |
|-------|----------|--------------|--------|
| Host | 887 | 0% | ✅ Ready |
| Network | 5 | 0% | ✅ Ready |
| Power | 3 | 82% | ⚠️ Limited use |
| **Total** | **895** | **27.4%** | **Usable** |

### Sample Distribution
| Scenario | Samples | Label |
|----------|---------|-------|
| Benign | 61 | 0 |
| DoS | 61 | 1 |
| Recon | 61 | 2 |
| Cryptojacking | 61 | 3 |
| **Total** | **244** | **4 classes** |

---

## Experimental Design

### Phase 1: Data Preparation (30 min)
**Script**: `scripts/ml_experiments/prepare_datasets.py`

**Tasks**:
1. Load 4 aligned CSV files
2. Extract feature subsets:
   - Host features: columns starting with "host_"
   - Network features: columns starting with "network_"
   - Power features: columns starting with "power_"
3. Create labels: Benign=0, DoS=1, Recon=2, Cryptojacking=3
4. Split data: 80% train (195 samples), 20% test (49 samples)
   - **Stratified split**: Maintain class balance
   - **Random state**: 42 for reproducibility
5. Save prepared datasets:
   - `X_train_host.csv`, `X_test_host.csv`
   - `X_train_network.csv`, `X_test_network.csv`
   - `X_train_2layer.csv`, `X_test_2layer.csv`
   - `X_train_3layer.csv`, `X_test_3layer.csv`
   - `y_train.csv`, `y_test.csv`

**Output**:
```
processed/ml_datasets/
├── X_train_host.csv        (195 × 887)
├── X_test_host.csv         (49 × 887)
├── X_train_network.csv     (195 × 5)
├── X_test_network.csv      (49 × 5)
├── X_train_2layer.csv      (195 × 892)
├── X_test_2layer.csv       (49 × 892)
├── X_train_3layer.csv      (195 × 895, with missing values)
├── X_test_3layer.csv       (49 × 895, with missing values)
├── y_train.csv             (195 × 1)
├── y_test.csv              (49 × 1)
└── dataset_summary.json    (metadata)
```

---

### Phase 2: Baseline 1 - Host-Only Classification (1 hour)
**Script**: `scripts/ml_experiments/baseline_host_only.py`

**Algorithm**: Random Forest (proven in HPC literature)
- n_estimators: 100
- max_depth: None
- min_samples_split: 5
- random_state: 42
- class_weight: 'balanced' (handle imbalanced classes if needed)

**Feature Handling**:
- 887 features → Too many for 195 samples (overfitting risk)
- **Feature selection**: Select top 50 features by variance or correlation with label
- Alternative: PCA to 50 components

**Training**:
```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectKBest, f_classif

# Feature selection
selector = SelectKBest(f_classif, k=50)
X_train_selected = selector.fit_transform(X_train_host, y_train)
X_test_selected = selector.transform(X_test_host)

# Train Random Forest
rf_host = RandomForestClassifier(n_estimators=100, random_state=42)
rf_host.fit(X_train_selected, y_train)

# Predict
y_pred = rf_host.predict(X_test_selected)
```

**Evaluation**:
- Accuracy, Precision, Recall, F1-score (macro-averaged)
- Confusion matrix
- Per-class metrics
- Feature importance (top 20)

**Expected Performance** (based on HPC literature):
- Accuracy: 75-85%
- F1-score: 0.70-0.80

**Output**:
```
results/ml_experiments/host_only/
├── model.pkl
├── metrics.json
├── confusion_matrix.png
├── feature_importance.png
└── classification_report.txt
```

---

### Phase 3: Baseline 2 - Network-Only Classification (30 min)
**Script**: `scripts/ml_experiments/baseline_network_only.py`

**Algorithm**: Random Forest (same as Host-only)
- n_estimators: 100
- random_state: 42

**Features**: Only 5 network features (no selection needed)

**Expected Performance** (based on EVSE IDS literature):
- Accuracy: 80-90%
- F1-score: 0.75-0.85
- Note: May perform better than host-only despite fewer features (network features directly capture attack traffic)

**Output**:
```
results/ml_experiments/network_only/
├── model.pkl
├── metrics.json
├── confusion_matrix.png
└── classification_report.txt
```

---

### Phase 4: Multi-Layer Classification - 2-Layer (1 hour)
**Script**: `scripts/ml_experiments/multilayer_2layer.py`

**Approach**: Host + Network (892 features)

**Algorithm**: Random Forest with feature selection
- Select top 50 features from 892 combined features
- Or: Select top 25 from host + all 5 network features

**Hypothesis**: 2-layer should outperform both single-layer baselines
- Expected improvement: +5-10% over best baseline

**Expected Performance**:
- Accuracy: 85-92%
- F1-score: 0.80-0.88

**Output**:
```
results/ml_experiments/2layer/
├── model.pkl
├── metrics.json
├── confusion_matrix.png
├── feature_importance.png (showing host vs network feature distribution)
└── classification_report.txt
```

---

### Phase 5: Multi-Layer Classification - 3-Layer (1 hour)
**Script**: `scripts/ml_experiments/multilayer_3layer.py`

**Challenge**: Power features have 82% missing rate

**Missing Data Strategy**:
1. **Option A - Imputation**: Fill missing values with mean/median
2. **Option B - Indicator**: Add "power_available" binary feature
3. **Option C - Exclude**: Skip samples with missing power (reduces dataset to ~44 samples - NOT VIABLE)

**Recommended**: Option B (imputation + indicator)
```python
from sklearn.impute import SimpleImputer

# Impute missing power values
imputer = SimpleImputer(strategy='mean')
X_train_power = imputer.fit_transform(X_train_3layer[:, -3:])  # Last 3 columns

# Add indicator feature (1 if power available, 0 if imputed)
power_available = (~X_train_3layer[:, -3:].isna()).any(axis=1).astype(int)
X_train_augmented = np.concatenate([X_train_3layer[:, :-3], X_train_power,
                                     power_available.reshape(-1, 1)], axis=1)
```

**Expected Performance**:
- **If power helps**: Accuracy 90-95%, F1 0.85-0.90
- **If power doesn't help**: Similar to 2-layer (82% missing limits utility)

**Output**:
```
results/ml_experiments/3layer/
├── model.pkl
├── metrics.json
├── confusion_matrix.png
├── feature_importance.png
├── missing_data_analysis.json
└── classification_report.txt
```

---

### Phase 6: Comparison and Statistical Validation (1 hour)
**Script**: `scripts/ml_experiments/compare_models.py`

**Comparisons**:
1. **Performance Table**:
   ```
   | Model | Accuracy | F1-Score | Precision | Recall |
   |-------|----------|----------|-----------|--------|
   | Host-only | 78% | 0.75 | 0.76 | 0.74 |
   | Network-only | 85% | 0.82 | 0.83 | 0.81 |
   | 2-Layer | 89% | 0.87 | 0.88 | 0.86 |
   | 3-Layer | 88% | 0.86 | 0.87 | 0.85 |
   ```

2. **Statistical Test**: McNemar's test
   - Compare predictions pairwise (e.g., 2-layer vs host-only)
   - H0: Models have equal error rates
   - Reject H0 if p < 0.05 → Significant improvement

3. **Per-Class Performance**:
   - Which attack types benefit most from multi-layer?
   - Expected: DoS and Recon (strong network signals) improve most

4. **Feature Importance Analysis**:
   - In 2-layer model, what % of top 20 features are network vs host?
   - Expected: Network features dominate despite being only 5/892

**Output**:
```
results/ml_experiments/comparison/
├── performance_comparison.csv
├── mcnemar_test_results.json
├── per_class_comparison.png
├── feature_contribution_analysis.json
└── summary_report.md
```

---

## Implementation Timeline (Realistic)

| Phase | Duration | Status |
|-------|----------|--------|
| Phase 1: Data Preparation | 30 min | Pending |
| Phase 2: Host-only Baseline | 1 hour | Pending |
| Phase 3: Network-only Baseline | 30 min | Pending |
| Phase 4: 2-Layer Model | 1 hour | Pending |
| Phase 5: 3-Layer Model | 1 hour | Pending |
| Phase 6: Comparison | 1 hour | Pending |
| **Total** | **5-6 hours** | **Ready to start** |

---

## Risks and Mitigation

### Risk 1: Small Dataset (244 samples)
**Impact**: Overfitting, unstable metrics
**Mitigation**:
- Use cross-validation (5-fold stratified)
- Feature selection to reduce dimensionality
- Regularization (max_depth, min_samples_split)
- Report confidence intervals

### Risk 2: Class Imbalance
**Impact**: Bias toward majority class
**Check**: Each class has 61 samples → Balanced ✅
**Mitigation**: Not needed (balanced dataset)

### Risk 3: Feature Scaling
**Impact**: Some algorithms sensitive to scale
**Mitigation**:
- Data already normalized (checked in metadata: normalized timestamps)
- Random Forest not sensitive to scaling ✅
- If using SVM later: StandardScaler required

### Risk 4: Data Leakage
**Impact**: Overestimated performance
**Prevention**:
- Stratified train-test split (no temporal overlap between scenarios)
- Feature selection on training set only
- No test set used during hyperparameter tuning

### Risk 5: Power Missing Data (82%)
**Impact**: 3-layer may not improve over 2-layer
**Mitigation**:
- Imputation + indicator approach
- Compare 2-layer vs 3-layer carefully
- Report missing data impact
- Accept that 2-layer may be optimal given data quality

---

## Success Criteria

### Minimum Viable Results (Must Achieve)
1. ✅ All 4 models train without errors
2. ✅ Test accuracy > 60% (better than random baseline 25%)
3. ✅ Results reproducible (same metrics when re-run with seed=42)

### Expected Results (High Confidence)
1. ✅ Host-only: 70-80% accuracy
2. ✅ Network-only: 75-85% accuracy
3. ✅ 2-layer: 80-90% accuracy (improves over best single-layer)
4. ✅ Statistical significance: McNemar p < 0.05 for 2-layer vs baselines

### Stretch Goals (Aspirational)
1. 🎯 2-layer accuracy > 90%
2. 🎯 3-layer improves over 2-layer (despite missing power data)
3. 🎯 Per-class F1 > 0.80 for all attack types
4. 🎯 Feature importance reveals meaningful cross-layer interactions

---

## Deliverables

### Code (6 scripts)
1. `prepare_datasets.py` - Data preparation
2. `baseline_host_only.py` - Host baseline
3. `baseline_network_only.py` - Network baseline
4. `multilayer_2layer.py` - 2-layer model
5. `multilayer_3layer.py` - 3-layer model
6. `compare_models.py` - Statistical comparison

### Results (15+ files)
- 4× Model files (.pkl)
- 4× Metrics files (.json)
- 4× Confusion matrices (.png)
- 3× Feature importance plots (.png)
- 1× Comparison summary (.md)
- 1× McNemar test results (.json)

### Report
- `ML_EXPERIMENT_SUMMARY.md` - Full results with interpretation

---

## Next Steps After This Plan

### If Results Are Good (2-layer >> single-layer):
1. ✅ Validate RQ1 → Multi-layer superior
2. Write up results for publication
3. Implement RQ4 (protocol semantic features)
4. Try advanced models (XGBoost, Neural Networks)

### If Results Are Mixed (2-layer ≈ network-only):
1. Investigate why host features don't help
2. Check feature correlations (redundancy?)
3. Try different feature selection methods
4. Analyze per-attack performance (DoS vs Recon vs Crypto)

### If Power Data Helps (3-layer > 2-layer):
1. ✅ Validate physical layer validation concept
2. Investigate which samples had power data available
3. Recommend data recollection with better power logging

---

## References to Literature

This experimental design is grounded in:
- **IEEE 2018**: Multi-layer detection for ICS (10-15% improvement expected)
- **IEEE 2020**: HPC-based detection (85-90% accuracy expected)
- **ACM NSysS 2024**: EVSE attack detection with CICEVSE2024
- **Random Forest**: Standard for small-sample high-dimensional data

---

**Status**: 📋 Plan Complete - Ready to Implement
**Estimated Time**: 5-6 hours for full pipeline
**Start Date**: 2025-11-10
**Target Completion**: 2025-11-10 (same day if started now)
