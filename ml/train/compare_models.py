"""
PLEXUS ML Pipeline — Step 5: Algorithm Comparison (Optional)
=============================================================
Benchmarks XGBoost vs LightGBM vs Random Forest on the same 20-feature split.
Use this to empirically confirm XGBoost is the best choice.

Usage:
    python3 ml/train/compare_models.py

Output:
    Printed comparison table + ml/artifacts/comparison_results.json
"""

import json
import logging
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    f1_score,
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
log = logging.getLogger("compare_models")

# ─── Configuration ────────────────────────────────────────────────────────────
BASE_DIR     = Path(__file__).resolve().parent.parent.parent
ARTIFACT_DIR = BASE_DIR / "ml" / "artifacts"
DATA_PATH    = ARTIFACT_DIR / "cleaned_data.parquet"
SPEC_PATH    = ARTIFACT_DIR / "feature_spec.json"
OUT_PATH     = ARTIFACT_DIR / "comparison_results.json"

RANDOM_STATE = 42
TEST_SIZE    = 0.20


def load_spec() -> list[str]:
    if not SPEC_PATH.exists():
        log.error("Feature spec not found. Run export_features.py first.")
        sys.exit(1)
    with open(SPEC_PATH) as f:
        return json.load(f)["selected_features"]


def split_scale(X: pd.DataFrame, y: pd.Series):
    sss = StratifiedShuffleSplit(n_splits=1, test_size=TEST_SIZE, random_state=RANDOM_STATE)
    for train_idx, test_idx in sss.split(X, y):
        X_train = X.iloc[train_idx]
        X_test  = X.iloc[test_idx]
        y_train = y.iloc[train_idx]
        y_test  = y.iloc[test_idx]

    spw = int((y_train == 0).sum()) / max(int((y_train == 1).sum()), 1)
    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc  = scaler.transform(X_test)
    return X_train_sc, X_test_sc, y_train, y_test, spw


def run_model(name: str, model, X_train, X_test, y_train, y_test) -> dict:
    """Train a model and return key metrics + timing."""
    log.info("  Training %-20s ...", name)

    t0 = time.time()
    model.fit(X_train, y_train)
    train_time = time.time() - t0

    t1 = time.time()
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    infer_ms = (time.time() - t1) / len(X_test) * 1000  # ms per sample

    return {
        "algorithm"    : name,
        "accuracy"     : round(float(accuracy_score(y_test, y_pred)), 6),
        "f1_attack"    : round(float(f1_score(y_test, y_pred)),       6),
        "roc_auc"      : round(float(roc_auc_score(y_test, y_prob)),  6),
        "train_sec"    : round(train_time, 2),
        "infer_ms_per_sample": round(infer_ms, 4),
    }


def main() -> None:
    log.info("=" * 60)
    log.info("PLEXUS — Algorithm Comparison")
    log.info("=" * 60)

    # ── Load data ─────────────────────────────────────────────────────────
    if not DATA_PATH.exists():
        log.error("Cleaned data not found. Run clean_data.py first.")
        sys.exit(1)

    log.info("Loading dataset and feature spec ...")
    df = pd.read_parquet(DATA_PATH)
    features = load_spec()

    X = df[features]
    y = df["label"]
    log.info("  %d samples | %d features", len(df), len(features))

    X_train, X_test, y_train, y_test, spw = split_scale(X, y)

    # ── Define models ─────────────────────────────────────────────────────
    models = {
        "XGBoost": XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            min_child_weight=5,
            scale_pos_weight=spw,
            eval_metric="logloss",
            use_label_encoder=False,
            random_state=RANDOM_STATE,
            n_jobs=-1,
            tree_method="hist",
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            class_weight="balanced",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        ),
    }

    # Try to import LightGBM — optional dependency
    try:
        from lightgbm import LGBMClassifier
        models["LightGBM"] = LGBMClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=spw,
            random_state=RANDOM_STATE,
            n_jobs=-1,
            verbose=-1,
        )
        log.info("  LightGBM detected and included in comparison.")
    except ImportError:
        log.warning("  LightGBM not installed — skipping (pip install lightgbm to include).")

    # ── Run all models ────────────────────────────────────────────────────
    log.info("")
    log.info("Running %d models on identical train/test split ...", len(models))
    results = []
    for name, model in models.items():
        result = run_model(name, model, X_train, X_test, y_train, y_test)
        results.append(result)

    # ── Print comparison table ────────────────────────────────────────────
    log.info("")
    log.info("=" * 75)
    log.info("── Algorithm Comparison Results ─────────────────────────────────────")
    log.info("=" * 75)
    log.info(
        "  %-20s %10s %10s %10s %12s %16s",
        "Algorithm", "Accuracy", "F1(Attack)", "ROC-AUC",
        "Train (s)", "Infer (ms/sample)"
    )
    log.info("  " + "-" * 73)

    best_f1 = max(r["f1_attack"] for r in results)
    for r in results:
        star = " ★ BEST" if r["f1_attack"] == best_f1 else ""
        log.info(
            "  %-20s %9.3f%% %10.6f %10.6f %12.2f %16.4f%s",
            r["algorithm"],
            r["accuracy"] * 100,
            r["f1_attack"],
            r["roc_auc"],
            r["train_sec"],
            r["infer_ms_per_sample"],
            star,
        )
    log.info("=" * 75)

    # ── Save results ─────────────────────────────────────────────────────
    with open(OUT_PATH, "w") as f:
        json.dump({"comparison": results}, f, indent=2)
    log.info("")
    log.info("✓ Comparison results saved → %s", OUT_PATH)

    # ── Recommendation ────────────────────────────────────────────────────
    winner = max(results, key=lambda r: r["f1_attack"])
    log.info("")
    log.info("Recommendation: Use %s (F1=%.6f, AUC=%.6f)",
             winner["algorithm"], winner["f1_attack"], winner["roc_auc"])


if __name__ == "__main__":
    main()
