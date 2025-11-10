#!/usr/bin/env python3
"""
Phase 2: Host-Only Baseline Classification

Uses only host features (HPC + kernel events) for attack classification.
Feature selection applied to handle high dimensionality.

Algorithm: Random Forest
Expected Performance: 70-80% accuracy

Author: MLCER Team
Date: 2025-11-10
"""

import pandas as pd
import numpy as np
from pathlib import Path
import json
import pickle
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectKBest, f_classif, mutual_info_classif
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             confusion_matrix, classification_report)
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

# Paths
DATA_DIR = Path("processed/ml_datasets")
OUTPUT_DIR = Path("results/ml_experiments/host_only")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Hyperparameters
N_FEATURES = 50  # Select top 50 features
RANDOM_STATE = 42
N_ESTIMATORS = 100

# Class names
CLASS_NAMES = ['Benign', 'DoS', 'Recon', 'Cryptojacking']

print("=" * 70)
print("Phase 2: Host-Only Baseline Classification")
print("=" * 70)

# Step 1: Load data
print("\n[1/7] Loading datasets...")
X_train_full = pd.read_csv(DATA_DIR / "X_train_host.csv")
X_test_full = pd.read_csv(DATA_DIR / "X_test_host.csv")
y_train = pd.read_csv(DATA_DIR / "y_train.csv")['label'].values
y_test = pd.read_csv(DATA_DIR / "y_test.csv")['label'].values

print(f"  X_train: {X_train_full.shape}")
print(f"  X_test: {X_test_full.shape}")
print(f"  y_train distribution: {dict(zip(*np.unique(y_train, return_counts=True)))}")

# Extract actual host features (exclude network features)
host_cols = [col for col in X_train_full.columns if not col.startswith('net_')]
X_train_full = X_train_full[host_cols]
X_test_full = X_test_full[host_cols]

print(f"  Actual host features (excluding net_*): {len(host_cols)}")

# Step 2: Handle missing values
print("\n[2/7] Handling missing values...")
missing_before = X_train_full.isna().sum().sum()
print(f"  Missing values before: {missing_before} / {X_train_full.size} ({missing_before/X_train_full.size*100:.2f}%)")

# Simple imputation: fill with column mean
X_train_filled = X_train_full.fillna(X_train_full.mean())
X_test_filled = X_test_full.fillna(X_train_full.mean())  # Use train mean for test

missing_after = X_train_filled.isna().sum().sum()
print(f"  Missing values after: {missing_after}")

# Step 3: Feature selection
print(f"\n[3/7] Selecting top {N_FEATURES} features...")
print(f"  Method: ANOVA F-statistic (f_classif)")

selector = SelectKBest(score_func=f_classif, k=min(N_FEATURES, X_train_filled.shape[1]))
X_train_selected = selector.fit_transform(X_train_filled, y_train)
X_test_selected = selector.transform(X_test_filled)

# Get selected feature names
selected_mask = selector.get_support()
selected_features = X_train_filled.columns[selected_mask].tolist()
feature_scores = selector.scores_[selected_mask]

print(f"  Selected features: {X_train_selected.shape[1]}")
print(f"  Top 10 features by F-score:")
top_10_idx = np.argsort(feature_scores)[-10:][::-1]
for idx in top_10_idx:
    print(f"    {selected_features[idx]}: {feature_scores[idx]:.2f}")

# Step 4: Train Random Forest
print(f"\n[4/7] Training Random Forest...")
print(f"  n_estimators={N_ESTIMATORS}, random_state={RANDOM_STATE}")

rf = RandomForestClassifier(
    n_estimators=N_ESTIMATORS,
    random_state=RANDOM_STATE,
    max_depth=None,
    min_samples_split=5,
    min_samples_leaf=2,
    n_jobs=-1  # Use all cores
)

rf.fit(X_train_selected, y_train)
print(f"  ✅ Training complete")

# Step 5: Predictions
print(f"\n[5/7] Making predictions...")
y_train_pred = rf.predict(X_train_selected)
y_test_pred = rf.predict(X_test_selected)

# Calculate metrics
train_acc = accuracy_score(y_train, y_train_pred)
test_acc = accuracy_score(y_test, y_test_pred)
test_precision = precision_score(y_test, y_test_pred, average='macro', zero_division=0)
test_recall = recall_score(y_test, y_test_pred, average='macro', zero_division=0)
test_f1 = f1_score(y_test, y_test_pred, average='macro', zero_division=0)

print(f"\n  Train Accuracy: {train_acc:.4f}")
print(f"  Test Accuracy:  {test_acc:.4f}")
print(f"  Test Precision: {test_precision:.4f}")
print(f"  Test Recall:    {test_recall:.4f}")
print(f"  Test F1-Score:  {test_f1:.4f}")

# Per-class metrics
print(f"\n  Per-class F1-scores:")
per_class_f1 = f1_score(y_test, y_test_pred, average=None, zero_division=0)
for i, class_name in enumerate(CLASS_NAMES):
    print(f"    {class_name}: {per_class_f1[i]:.4f}")

# Step 6: Visualizations
print(f"\n[6/7] Generating visualizations...")

# Confusion Matrix
cm = confusion_matrix(y_test, y_test_pred)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=CLASS_NAMES, yticklabels=CLASS_NAMES)
plt.title('Host-Only Model: Confusion Matrix')
plt.ylabel('True Label')
plt.xlabel('Predicted Label')
plt.tight_layout()
cm_path = OUTPUT_DIR / 'confusion_matrix.png'
plt.savefig(cm_path, dpi=300, bbox_inches='tight')
plt.close()
print(f"  Saved confusion matrix: {cm_path}")

# Feature Importance
feature_importance = rf.feature_importances_
top_20_idx = np.argsort(feature_importance)[-20:]
top_20_features = [selected_features[i] for i in top_20_idx]
top_20_importance = feature_importance[top_20_idx]

plt.figure(figsize=(10, 8))
plt.barh(range(20), top_20_importance, color='steelblue')
plt.yticks(range(20), [f.replace('host_', '')[:40] for f in top_20_features], fontsize=8)
plt.xlabel('Feature Importance')
plt.title('Host-Only Model: Top 20 Features')
plt.tight_layout()
importance_path = OUTPUT_DIR / 'feature_importance.png'
plt.savefig(importance_path, dpi=300, bbox_inches='tight')
plt.close()
print(f"  Saved feature importance: {importance_path}")

# Step 7: Save results
print(f"\n[7/7] Saving results...")

# Save model
model_path = OUTPUT_DIR / 'model.pkl'
with open(model_path, 'wb') as f:
    pickle.dump({
        'model': rf,
        'selector': selector,
        'selected_features': selected_features,
        'feature_columns': host_cols
    }, f)
print(f"  Model saved: {model_path}")

# Save metrics
metrics = {
    'model': 'Host-Only Random Forest',
    'n_features': X_train_selected.shape[1],
    'n_features_original': len(host_cols),
    'n_train_samples': len(y_train),
    'n_test_samples': len(y_test),
    'hyperparameters': {
        'n_estimators': N_ESTIMATORS,
        'random_state': RANDOM_STATE,
        'feature_selection_k': N_FEATURES
    },
    'performance': {
        'train_accuracy': float(train_acc),
        'test_accuracy': float(test_acc),
        'test_precision_macro': float(test_precision),
        'test_recall_macro': float(test_recall),
        'test_f1_macro': float(test_f1)
    },
    'per_class_f1': {CLASS_NAMES[i]: float(per_class_f1[i]) for i in range(len(CLASS_NAMES))},
    'confusion_matrix': cm.tolist(),
    'top_20_features': [
        {'feature': top_20_features[i], 'importance': float(top_20_importance[i])}
        for i in range(20)
    ]
}

metrics_path = OUTPUT_DIR / 'metrics.json'
with open(metrics_path, 'w') as f:
    json.dump(metrics, f, indent=2)
print(f"  Metrics saved: {metrics_path}")

# Save classification report
report = classification_report(y_test, y_test_pred, target_names=CLASS_NAMES)
report_path = OUTPUT_DIR / 'classification_report.txt'
with open(report_path, 'w') as f:
    f.write("Host-Only Baseline Classification Report\n")
    f.write("=" * 50 + "\n\n")
    f.write(report)
    f.write("\n\nConfusion Matrix:\n")
    f.write(str(cm))
with open(report_path, 'r') as f:
    print(f"\n{f.read()}")

print("\n" + "=" * 70)
print("✅ Host-Only Baseline Complete!")
print("=" * 70)
print(f"Test Accuracy: {test_acc:.2%}")
print(f"Test F1-Score: {test_f1:.4f}")
print(f"\nOutput directory: {OUTPUT_DIR}")
print("\nNext step: Implement 2-layer model")
print("  → python3 scripts/ml_experiments/multilayer_2layer.py")
print("=" * 70)
