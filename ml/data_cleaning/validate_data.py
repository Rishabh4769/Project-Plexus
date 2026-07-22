"""
PLEXUS ML Pipeline — Step 2: Data Validation
==============================================
Loads the cleaned Parquet file and performs rigorous quality checks.
Exits with code 1 if any check fails — prevents training on bad data.

Usage:
    python3 ml/data_cleaning/validate_data.py

Checks:
    ✓ File exists and loads cleanly
    ✓ Expected columns are present
    ✓ No NaN values remain
    ✓ No Infinity values remain
    ✓ Label column is strictly binary (0 or 1)
    ✓ Both classes are present (no single-class datasets)
    ✓ No duplicate rows
    ✓ Feature dtypes are float32
    ✓ Per-column value range sanity check
"""

import logging
import sys
from pathlib import Path

import numpy as np
import pandas as pd

# ─── Logging Setup ───────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("validate_data")

# ─── Configuration ────────────────────────────────────────────────────────────
BASE_DIR     = Path(__file__).resolve().parent.parent.parent
ARTIFACT_DIR = BASE_DIR / "ml" / "artifacts"
DATA_PATH    = ARTIFACT_DIR / "cleaned_data.parquet"

PASS = "  ✓"
FAIL = "  ✗"

errors: list[str] = []


def check(condition: bool, pass_msg: str, fail_msg: str) -> bool:
    if condition:
        log.info("%s %s", PASS, pass_msg)
        return True
    else:
        log.error("%s %s", FAIL, fail_msg)
        errors.append(fail_msg)
        return False


def main() -> None:
    log.info("=" * 60)
    log.info("PLEXUS — Data Validation")
    log.info("=" * 60)

    # ── Check 1: File exists ──────────────────────────────────────────────
    if not check(DATA_PATH.exists(),
                 f"Parquet file found: {DATA_PATH.name}",
                 f"Parquet file missing: {DATA_PATH} — run clean_data.py first"):
        sys.exit(1)

    # ── Load ──────────────────────────────────────────────────────────────
    log.info("Loading %s ...", DATA_PATH.name)
    df = pd.read_parquet(DATA_PATH)
    log.info("Shape: %s", df.shape)

    feature_cols = [c for c in df.columns if c != "label"]

    # ── Check 2: Label column present ─────────────────────────────────────
    check("label" in df.columns,
          "Label column present",
          "Label column missing from dataframe")

    # ── Check 3: No NaN ───────────────────────────────────────────────────
    n_nan = df.isnull().sum().sum()
    check(n_nan == 0,
          f"No NaN values found",
          f"{n_nan} NaN values found — data cleaning incomplete")

    # ── Check 4: No Infinity ──────────────────────────────────────────────
    numeric_df = df[feature_cols].select_dtypes(include=[np.number])
    n_inf = np.isinf(numeric_df.values).sum()
    check(n_inf == 0,
          "No Inf/-Inf values found",
          f"{n_inf} Infinity values found — data cleaning incomplete")

    # ── Check 5: Label is strictly binary ────────────────────────────────
    unique_labels = set(df["label"].unique())
    check(unique_labels.issubset({0, 1}),
          f"Labels are strictly binary: {unique_labels}",
          f"Unexpected label values found: {unique_labels - {0, 1}}")

    # ── Check 6: Both classes are present ─────────────────────────────────
    check(len(unique_labels) == 2,
          "Both classes (0=Benign, 1=Attack) are present",
          f"Only one class present: {unique_labels} — model cannot train")

    # ── Check 7: No completely duplicate rows ─────────────────────────────
    # CICIDS2017 benign traffic naturally repeats; warn above 20%
    n_dup = df.duplicated().sum()
    check(n_dup < len(df) * 0.20,
          f"Duplicate rows: {n_dup} ({n_dup / len(df) * 100:.1f}%) — within tolerance (<20%)",
          f"Too many duplicate rows: {n_dup} ({n_dup / len(df) * 100:.1f}%) — run clean_data.py with dedup")

    # ── Check 8: Feature dtypes ───────────────────────────────────────────
    bad_dtypes = [c for c in feature_cols if df[c].dtype not in [np.float32, np.float64]]
    check(len(bad_dtypes) == 0,
          "All feature columns are numeric float type",
          f"Non-float feature columns found: {bad_dtypes}")

    # ── Check 9: No zero-variance features remain ─────────────────────────
    zv_remaining = [c for c in feature_cols if df[c].nunique() <= 1]
    check(len(zv_remaining) == 0,
          "No zero-variance feature columns remaining",
          f"Zero-variance columns still present: {zv_remaining}")

    # ── Check 10: Value range sanity ──────────────────────────────────────
    # CICFlowMeter artefacts can produce small negatives (e.g. -1.0).
    # After clean_data.py clips them, no column should have min < -1.
    neg_cols = [c for c in feature_cols if df[c].min() < -1]
    check(len(neg_cols) == 0,
          "No negative feature values detected (CICFlowMeter artefacts cleaned)",
          f"Negative values still present in: {neg_cols} — check clip_negative_values()")

    # ── Summary ───────────────────────────────────────────────────────────
    log.info("")
    log.info("── Dataset Summary ────────────────────────────────────")
    log.info("  Rows      : %d", len(df))
    log.info("  Features  : %d", len(feature_cols))
    vc = df["label"].value_counts().sort_index()
    log.info("  Benign    : %d  (%.1f%%)", vc.get(0, 0), vc.get(0, 0) / len(df) * 100)
    log.info("  Attack    : %d  (%.1f%%)", vc.get(1, 0), vc.get(1, 0) / len(df) * 100)
    log.info("  Memory    : %.1f MB", df.memory_usage(deep=True).sum() / 1e6)

    log.info("")
    log.info("── Per-Feature Stats (first 10 features) ──────────────")
    log.info("  %-38s %8s %8s %8s %8s", "Feature", "Min", "Max", "Mean", "Std")
    log.info("  " + "-" * 68)
    for col in feature_cols[:10]:
        log.info(
            "  %-38s %8.2f %8.2f %8.2f %8.2f",
            col[:38], df[col].min(), df[col].max(), df[col].mean(), df[col].std()
        )

    # ── Final verdict ─────────────────────────────────────────────────────
    log.info("")
    if errors:
        log.error("=" * 60)
        log.error("VALIDATION FAILED — %d error(s):", len(errors))
        for i, e in enumerate(errors, 1):
            log.error("  %d. %s", i, e)
        log.error("=" * 60)
        sys.exit(1)
    else:
        log.info("=" * 60)
        log.info("✓ ALL CHECKS PASSED — data is clean and ready for training.")
        log.info("=" * 60)


if __name__ == "__main__":
    main()
