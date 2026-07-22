"""
PLEXUS ML Pipeline — Step 4: XGBoost Training
===============================================
Loads cleaned data + feature spec, trains a tuned XGBoost classifier,
evaluates on a held-out test set, and saves the production model + scaler.

Usage:
    python3 ml/train/train_xgboost.py

Output:
    ml/artifacts/model.joblib      — trained XGBoost classifier
    ml/artifacts/scaler.joblib     — fitted StandardScaler
    ml/artifacts/metrics.json      — full evaluation report
"""

import json
import logging
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

# ─── Logging Setup ───────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("train_xgboost")

# ─── Configuration ────────────────────────────────────────────────────────────
BASE_DIR     = Path(__file__).resolve().parent.parent.parent
ARTIFACT_DIR = BASE_DIR / "ml" / "artifacts"
DATA_PATH    = ARTIFACT_DIR / "cleaned_data.parquet"
SPEC_PATH    = ARTIFACT_DIR / "feature_spec.json"
MODEL_PATH   = ARTIFACT_DIR / "model.joblib"
SCALER_PATH  = ARTIFACT_DIR / "scaler.joblib"
METRICS_PATH = ARTIFACT_DIR / "metrics.json"

RANDOM_STATE = 42
TEST_SIZE    = 0.20   # 80% train / 20% test

# XGBoost hyperparameters (tuned for CICIDS2017 profile)
XGB_PARAMS = {
    "n_estimators"       : 300,
    "max_depth"          : 6,
    "learning_rate"      : 0.1,
    "subsample"          : 0.8,
    "colsample_bytree"   : 0.8,
    "min_child_weight"   : 5,
    "gamma"              : 0.1,
    "reg_alpha"          : 0.1,    # L1 regularisation
    "reg_lambda"         : 1.0,    # L2 regularisation
    "eval_metric"        : "logloss",
    "use_label_encoder"  : False,
    "random_state"       : RANDOM_STATE,
    "n_jobs"             : -1,
    "tree_method"        : "hist",   # fast histogram-based splits
}


def load_spec(path: Path) -> list[str]:
    """Load the selected feature names from feature_spec.json."""
    if not path.exists():
        log.error("Feature spec not found: %s", path)
        log.error("Run ml/train/export_features.py first.")
        sys.exit(1)
    with open(path) as f:
        spec = json.load(f)
    return spec["selected_features"]


def stratified_split(X: pd.DataFrame, y: pd.Series):
    """Stratified 80/20 train/test split preserving class ratios."""
    sss = StratifiedShuffleSplit(n_splits=1, test_size=TEST_SIZE, random_state=RANDOM_STATE)
    for train_idx, test_idx in sss.split(X, y):
        X_train = X.iloc[train_idx].reset_index(drop=True)
        X_test  = X.iloc[test_idx].reset_index(drop=True)
        y_train = y.iloc[train_idx].reset_index(drop=True)
        y_test  = y.iloc[test_idx].reset_index(drop=True)
    return X_train, X_test, y_train, y_test


def compute_scale_pos_weight(y_train: pd.Series) -> float:
    """Ratio of negatives to positives — XGBoost class imbalance correction."""
    n_benign = int((y_train == 0).sum())
    n_attack = int((y_train == 1).sum())
    ratio = n_benign / max(n_attack, 1)
    log.info("  scale_pos_weight = %.2f  (Benign: %d / Attack: %d)",
             ratio, n_benign, n_attack)
    return ratio


def evaluate(y_true, y_pred, y_prob) -> dict:
    """Compute and return all evaluation metrics."""
    cm = confusion_matrix(y_true, y_pred).tolist()
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    metrics = {
        "accuracy"         : round(float(accuracy_score(y_true, y_pred)),  6),
        "precision"        : round(float(precision_score(y_true, y_pred)), 6),
        "recall"           : round(float(recall_score(y_true, y_pred)),    6),
        "f1_score"         : round(float(f1_score(y_true, y_pred)),        6),
        "roc_auc"          : round(float(roc_auc_score(y_true, y_prob)),   6),
        "false_positive_rate": round(float(fpr),                           6),
        "confusion_matrix" : cm,
        "TP": int(tp), "TN": int(tn), "FP": int(fp), "FN": int(fn),
    }
    return metrics


def print_metrics(metrics: dict) -> None:
    log.info("  %-25s %s", "Accuracy",           f"{metrics['accuracy']*100:.3f}%")
    log.info("  %-25s %s", "Precision (Attack)",  f"{metrics['precision']*100:.3f}%")
    log.info("  %-25s %s", "Recall (Attack)",     f"{metrics['recall']*100:.3f}%")
    log.info("  %-25s %s", "F1 Score (Attack)",   f"{metrics['f1_score']:.6f}")
    log.info("  %-25s %s", "ROC-AUC",             f"{metrics['roc_auc']:.6f}")
    log.info("  %-25s %s", "False Positive Rate", f"{metrics['false_positive_rate']*100:.3f}%")
    cm = metrics["confusion_matrix"]
    log.info("  Confusion Matrix:")
    log.info("             Pred: Benign   Pred: Attack")
    log.info("  True: Benign    %8d   %8d", cm[0][0], cm[0][1])
    log.info("  True: Attack    %8d   %8d", cm[1][0], cm[1][1])


def main() -> None:
    log.info("=" * 60)
    log.info("PLEXUS — XGBoost Training Pipeline")
    log.info("=" * 60)

    # ── 1. Validate inputs ────────────────────────────────────────────────
    if not DATA_PATH.exists():
        log.error("Cleaned data not found. Run clean_data.py first.")
        sys.exit(1)

    # ── 2. Load data + feature spec ───────────────────────────────────────
    log.info("Loading dataset: %s", DATA_PATH.name)
    df = pd.read_parquet(DATA_PATH)
    log.info("  Full shape: %s", df.shape)

    features = load_spec(SPEC_PATH)
    log.info("  Using %d selected features from feature_spec.json", len(features))

    # Verify all features exist in cleaned data
    missing = [f for f in features if f not in df.columns]
    if missing:
        log.error("Features missing from cleaned dataset: %s", missing)
        sys.exit(1)

    X = df[features]
    y = df["label"]

    # ── 3. Train/test split ───────────────────────────────────────────────
    log.info("")
    log.info("Stratified 80/20 train/test split ...")
    X_train, X_test, y_train, y_test = stratified_split(X, y)
    log.info("  Train: %d  |  Test: %d", len(X_train), len(X_test))

    # ── 4. Scale features ─────────────────────────────────────────────────
    log.info("")
    log.info("Fitting StandardScaler on training set ...")
    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc  = scaler.transform(X_test)

    # ── 5. Compute class weight ───────────────────────────────────────────
    log.info("")
    log.info("Computing class imbalance correction ...")
    spw = compute_scale_pos_weight(y_train)

    # ── 6. Build and train XGBoost ────────────────────────────────────────
    log.info("")
    log.info("Training XGBoost ...")
    log.info("  Hyperparameters:")
    for k, v in XGB_PARAMS.items():
        log.info("    %-25s %s", k, v)
    log.info("    %-25s %s", "scale_pos_weight", round(spw, 4))

    model = XGBClassifier(**XGB_PARAMS, scale_pos_weight=spw)

    t0 = time.time()
    model.fit(
        X_train_sc, y_train,
        eval_set=[(X_test_sc, y_test)],
        verbose=False,
    )
    train_time = time.time() - t0
    log.info("  Training complete in %.1fs", train_time)

    # ── 7. Evaluate ───────────────────────────────────────────────────────
    log.info("")
    log.info("── Evaluation on Test Set ──────────────────────────────")
    y_pred = model.predict(X_test_sc)
    y_prob = model.predict_proba(X_test_sc)[:, 1]
    metrics = evaluate(y_test, y_pred, y_prob)
    print_metrics(metrics)

    log.info("")
    log.info("Full Classification Report:")
    report = classification_report(
        y_test, y_pred,
        target_names=["Benign", "Attack"],
        digits=4
    )
    for line in report.splitlines():
        log.info("  %s", line)

    # ── 8. Save model + scaler ────────────────────────────────────────────
    log.info("")
    log.info("Saving artifacts ...")
    joblib.dump(model,  MODEL_PATH,  compress=3)
    joblib.dump(scaler, SCALER_PATH, compress=3)
    log.info("  ✓ Model  → %s  (%.1f KB)", MODEL_PATH.name,  MODEL_PATH.stat().st_size / 1024)
    log.info("  ✓ Scaler → %s  (%.1f KB)", SCALER_PATH.name, SCALER_PATH.stat().st_size / 1024)

    # ── 9. Save metrics report ────────────────────────────────────────────
    full_report = {
        "algorithm"        : "XGBoost",
        "features_used"    : features,
        "n_features"       : len(features),
        "train_samples"    : len(X_train),
        "test_samples"     : len(X_test),
        "train_time_sec"   : round(train_time, 2),
        "hyperparameters"  : {**XGB_PARAMS, "scale_pos_weight": round(spw, 4)},
        "metrics"          : metrics,
    }
    with open(METRICS_PATH, "w") as f:
        json.dump(full_report, f, indent=2)
    log.info("  ✓ Metrics → %s", METRICS_PATH.name)

    log.info("")
    log.info("=" * 60)
    log.info("✓ Training complete!")
    log.info("  Accuracy  : %.3f%%", metrics["accuracy"] * 100)
    log.info("  F1 Score  : %.6f",   metrics["f1_score"])
    log.info("  ROC-AUC   : %.6f",   metrics["roc_auc"])
    log.info("=" * 60)


if __name__ == "__main__":
    main()
