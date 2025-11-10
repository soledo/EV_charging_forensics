#!/usr/bin/env python3
"""
Phase 4: 2-Layer Multi-Layer Classification

Uses Host + Network features for attack classification.
Tests whether network features improve upon host-only baseline.

Algorithm: Random Forest
Hypothesis: Multi-layer ≥ Host-only performance

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
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             confusion_matrix, classification_report)
import warnings
warnings.filterwarnings('ignore')

# Paths
DATA_DIR = Path("processed/ml_datasets")
OUTPUT_DIR = Path("results/ml_experiments/2layer")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Hyperparameters
N_FEATURES = 55  # 50 host + 5 network (select all network features explicitly)
RANDOM_STATE = 42
N_ESTIMATORS = 100

# Class names
CLASS_NAMES = ['Benign', 'DoS', 'Recon', 'Cryptojacking']

print("=" * 70)
print("Phase 4: 2-Layer Multi-Layer Classification (Host + Network)")
print("=" * 70)

# Step 1: Load data
print("\n[1/8] Loading datasets...")
X_train_full = pd.read_csv(DATA_DIR / "X_train_2layer.csv")
X_test_full = pd.read_csv(DATA_DIR / "X_test_2layer.csv")
y_train = pd.read_csv(DATA_DIR / "y_train.csv")['label'].values
y_test = pd.read_csv(DATA_DIR / "y_test.csv")['label'].values

print(f"  X_train: {X_train_full.shape}")
print(f"  X_test: {X_test_full.shape}")

# Step 2: Identify host vs network features
print("\n[2/8] Identifying feature groups...")
host_cols = [col for col in X_train_full.columns if not col.startswith('net_')]
network_cols = [col for col in X_train_full.columns if col.startswith('net_')]

print(f"  Host features: {len(host_cols)}")
print(f"  Network features: {len(network_cols)}")
print(f"  Network features: {network_cols}")

# Handle missing values
X_train_filled = X_train_full.fillna(X_train_full.mean())
X_test_filled = X_test_full.fillna(X_train_full.mean())

# Step 3: Feature selection strategy
print(f"\n[3/8] Feature selection strategy...")
print(f"  Strategy: Select top {N_FEATURES - len(network_cols)} host + ALL {len(network_cols)} network")

# Select top host features
X_train_host = X_train_filled[host_cols]
X_test_host = X_test_filled[host_cols]

selector_host = SelectKBest(score_func=f_classif, k=min(N_FEATURES - len(network_cols), len(host_cols)))
X_train_host_selected = selector_host.fit_transform(X_train_host, y_train)
X_test_host_selected = selector_host.transform(X_test_host)

selected_host_mask = selector_host.get_support()
selected_host_features = np.array(host_cols)[selected_host_mask].tolist()

# Add all network features
X_train_network = X_train_filled[network_cols].values
X_test_network = X_test_filled[network_cols].values

# Combine
X_train_selected = np.concatenate([X_train_host_selected, X_train_network], axis=1)
X_test_selected = np.concatenate([X_test_host_selected, X_test_network], axis=1)

selected_features = selected_host_features + network_cols

print(f"  Total selected features: {X_train_selected.shape[1]}")
print(f"    - Host: {len(selected_host_features)}")
print(f"    - Network: {len(network_cols)}")

# Get feature scores
host_scores = selector_host.scores_[selected_host_mask]
feature_scores = np.concatenate([host_scores, np.zeros(len(network_cols))])  # Network scores calculated separately

# Calculate network feature importance separately
from sklearn.feature_selection import f_classif as calc_f
network_f_scores, _ = calc_f(X_train_network, y_train)
feature_scores[-len(network_cols):] = network_f_scores

print(f"\n  Top 10 features by F-score:")
top_10_idx = np.argsort(feature_scores)[-10:][::-1]
for idx in top_10_idx:
    feat_type = "NET" if selected_features[idx].startswith('net_') else "HOST"
    print(f"    [{feat_type}] {selected_features[idx]}: {feature_scores[idx]:.2f}")

# Step 4: Train Random Forest
print(f"\n[4/8] Training Random Forest...")
rf = RandomForestClassifier(
    n_estimators=N_ESTIMATORS,
    random_state=RANDOM_STATE,
    max_depth=None,
    min_samples_split=5,
    min_samples_leaf=2,
    n_jobs=-1
)

rf.fit(X_train_selected, y_train)
print(f"  ✅ Training complete")

# Step 5: Predictions
print(f"\n[5/8] Making predictions...")
y_train_pred = rf.predict(X_train_selected)
y_test_pred = rf.predict(X_test_selected)

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

per_class_f1 = f1_score(y_test, y_test_pred, average=None, zero_division=0)
print(f"\n  Per-class F1-scores:")
for i, class_name in enumerate(CLASS_NAMES):
    print(f"    {class_name}: {per_class_f1[i]:.4f}")

# Step 6: Feature importance analysis
print(f"\n[6/8] Analyzing feature importance...")
feature_importance = rf.feature_importances_

# Separate host vs network importance
host_importance = feature_importance[:len(selected_host_features)]
network_importance = feature_importance[len(selected_host_features):]

total_host_imp = host_importance.sum()
total_network_imp = network_importance.sum()

print(f"  Total host importance: {total_host_imp:.4f} ({total_host_imp/(total_host_imp+total_network_imp)*100:.1f}%)")
print(f"  Total network importance: {total_network_imp:.4f} ({total_network_imp/(total_host_imp+total_network_imp)*100:.1f}%)")

# Top features overall
top_20_idx = np.argsort(feature_importance)[-20:]
top_20_features = [selected_features[i] for i in top_20_idx]
top_20_importance = feature_importance[top_20_idx]
top_20_types = ['Network' if f.startswith('net_') else 'Host' for f in top_20_features]

# Step 7: Visualizations
print(f"\n[7/8] Generating visualizations...")

# Confusion Matrix
cm = confusion_matrix(y_test, y_test_pred)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Greens',
            xticklabels=CLASS_NAMES, yticklabels=CLASS_NAMES)
plt.title('2-Layer Model: Confusion Matrix')
plt.ylabel('True Label')
plt.xlabel('Predicted Label')
plt.tight_layout()
plt.savefig(OUTPUT_DIR / 'confusion_matrix.png', dpi=300, bbox_inches='tight')
plt.close()
print(f"  Saved confusion matrix")

# Feature Importance with Host/Network distinction
plt.figure(figsize=(10, 8))
colors = ['steelblue' if t == 'Host' else 'coral' for t in top_20_types]
plt.barh(range(20), top_20_importance, color=colors)
plt.yticks(range(20), [f.replace('host_', '').replace('net_', 'NET:')[:40] for f in top_20_features], fontsize=8)
plt.xlabel('Feature Importance')
plt.title('2-Layer Model: Top 20 Features (Blue=Host, Orange=Network)')
plt.tight_layout()
plt.savefig(OUTPUT_DIR / 'feature_importance.png', dpi=300, bbox_inches='tight')
plt.close()
print(f"  Saved feature importance")

# Layer contribution pie chart
plt.figure(figsize=(8, 6))
plt.pie([total_host_imp, total_network_imp],
        labels=['Host Features', 'Network Features'],
        autopct='%1.1f%%',
        colors=['steelblue', 'coral'],
        startangle=90)
plt.title('2-Layer Model: Feature Importance by Layer')
plt.tight_layout()
plt.savefig(OUTPUT_DIR / 'layer_contribution.png', dpi=300, bbox_inches='tight')
plt.close()
print(f"  Saved layer contribution")

# Step 8: Save results
print(f"\n[8/8] Saving results...")

metrics = {
    'model': '2-Layer Random Forest (Host + Network)',
    'n_features': X_train_selected.shape[1],
    'n_host_features': len(selected_host_features),
    'n_network_features': len(network_cols),
    'hyperparameters': {
        'n_estimators': N_ESTIMATORS,
        'random_state': RANDOM_STATE
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
    'layer_importance': {
        'host_total': float(total_host_imp),
        'network_total': float(total_network_imp),
        'host_percentage': float(total_host_imp/(total_host_imp+total_network_imp)*100),
        'network_percentage': float(total_network_imp/(total_host_imp+total_network_imp)*100)
    },
    'top_20_features': [
        {
            'feature': top_20_features[i],
            'importance': float(top_20_importance[i]),
            'layer': top_20_types[i]
        }
        for i in range(20)
    ]
}

with open(OUTPUT_DIR / 'metrics.json', 'w') as f:
    json.dump(metrics, f, indent=2)

# Save model
with open(OUTPUT_DIR / 'model.pkl', 'wb') as f:
    pickle.dump({
        'model': rf,
        'selector_host': selector_host,
        'selected_features': selected_features,
        'network_features': network_cols
    }, f)

# Classification report
report = classification_report(y_test, y_test_pred, target_names=CLASS_NAMES)
with open(OUTPUT_DIR / 'classification_report.txt', 'w') as f:
    f.write("2-Layer Model Classification Report\n")
    f.write("=" * 50 + "\n\n")
    f.write(f"Features: {len(selected_host_features)} host + {len(network_cols)} network\n\n")
    f.write(report)
    f.write("\n\nLayer Importance:\n")
    f.write(f"  Host: {total_host_imp:.4f} ({total_host_imp/(total_host_imp+total_network_imp)*100:.1f}%)\n")
    f.write(f"  Network: {total_network_imp:.4f} ({total_network_imp/(total_host_imp+total_network_imp)*100:.1f}%)\n")

print("\n" + "=" * 70)
print("✅ 2-Layer Model Complete!")
print("=" * 70)
print(f"Test Accuracy: {test_acc:.2%}")
print(f"Test F1-Score: {test_f1:.4f}")
print(f"\nLayer Contribution:")
print(f"  Host: {total_host_imp/(total_host_imp+total_network_imp)*100:.1f}%")
print(f"  Network: {total_network_imp/(total_host_imp+total_network_imp)*100:.1f}%")
print(f"\nOutput directory: {OUTPUT_DIR}")
print("\nNext step: Compare models")
print("  → python3 scripts/ml_experiments/compare_models.py")
print("=" * 70)
