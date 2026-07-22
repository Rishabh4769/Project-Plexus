"""
PLEXUS ML Pipeline — Step 3: Feature Export
=============================================
Loads cleaned data, trains a base Random Forest for Gini importance,
and exports the top-20 feature list to ml/artifacts/feature_spec.json.

Usage:
    python3 ml/train/export_features.py

Output:
    ml/artifacts/feature_spec.json
"""

import json
import logging
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# ─── Logging Setup ───────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("export_features")

# ─── Configuration ────────────────────────────────────────────────────────────
BASE_DIR     = Path(__file__).resolve().parent.parent.parent
ARTIFACT_DIR = BASE_DIR / "ml" / "artifacts"
DATA_PATH    = ARTIFACT_DIR / "cleaned_data.parquet"
OUT_PATH     = ARTIFACT_DIR / "feature_spec.json"

TOP_N        = 20       # number of features to select
RF_TREES     = 50       # trees for importance estimation (speed vs accuracy)
RF_MAX_DEPTH = 16
RANDOM_STATE = 42


def main() -> None:
    log.info("=" * 60)
    log.info("PLEXUS — Feature Importance & Export (Top %d)", TOP_N)
    log.info("=" * 60)

    # ── 1. Load cleaned data ──────────────────────────────────────────────
    if not DATA_PATH.exists():
        log.error("Cleaned data not found: %s", DATA_PATH)
        log.error("Run ml/data_cleaning/clean_data.py first.")
        sys.exit(1)

    log.info("Loading cleaned dataset from %s ...", DATA_PATH.name)
    df = pd.read_parquet(DATA_PATH)
    log.info("Shape: %s", df.shape)

    X = df.drop(columns=["label"])
    y = df["label"]
    log.info("Features: %d | Benign: %d | Attack: %d",
             X.shape[1], int((y == 0).sum()), int((y == 1).sum()))

    # ── 2. Train base RF for importance ───────────────────────────────────
    log.info("")
    log.info("Training base Random Forest (%d trees, max_depth=%d) ...", RF_TREES, RF_MAX_DEPTH)
    rf = RandomForestClassifier(
        n_estimators=RF_TREES,
        max_depth=RF_MAX_DEPTH,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        class_weight="balanced",
    )
    t0 = time.time()
    rf.fit(X, y)
    elapsed = time.time() - t0
    log.info("Training complete in %.1fs", elapsed)

    # ── 3. Rank features ──────────────────────────────────────────────────
    importances = pd.Series(rf.feature_importances_, index=X.columns)
    importances = importances.sort_values(ascending=False)

    log.info("")
    log.info("── Full Feature Ranking ─────────────────────────────────")
    log.info("  %-4s %-40s %10s", "#", "Feature", "Importance")
    log.info("  " + "-" * 58)
    for rank, (feat, imp) in enumerate(importances.items(), start=1):
        marker = " ◄ SELECTED" if rank <= TOP_N else ""
        log.info("  %-4d %-40s %10.6f%s", rank, feat[:40], imp, marker)

    # ── 4. Build feature spec ─────────────────────────────────────────────
    selected = importances.head(TOP_N).index.tolist()
    all_ranked = [
        {"feature": feat, "importance": round(float(imp), 8)}
        for feat, imp in importances.items()
    ]

    spec = {
        "top_n": TOP_N,
        "selected_features": selected,
        "all_ranked": all_ranked,
    }

    with open(OUT_PATH, "w") as f:
        json.dump(spec, f, indent=2)

    log.info("")
    log.info("── Selected Top %d Features ──────────────────────────────", TOP_N)
    for i, feat in enumerate(selected, start=1):
        log.info("  %02d. %s", i, feat)

    log.info("")
    log.info("✓ Feature spec saved → %s", OUT_PATH)


if __name__ == "__main__":
    main()
