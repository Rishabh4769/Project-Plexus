"""
PLEXUS ML Pipeline — Step 1: Data Cleaning
============================================
Loads Monday + Tuesday + Friday PortScan CSVs from CICIDS2017,
cleans them thoroughly, and saves a merged Parquet file ready for training.

Usage:
    python3 ml/data_cleaning/clean_data.py

Output:
    ml/artifacts/cleaned_data.parquet
"""

import json
import logging
import os
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

# ─── Logging Setup ───────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("clean_data")

# ─── Configuration ────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).resolve().parent.parent.parent   # project root
DATA_DIR   = BASE_DIR / "data_cleaning" / "datasets"
ARTIFACT_DIR = BASE_DIR / "ml" / "artifacts"
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

DATASET_FILES = {
    "Monday"          : DATA_DIR / "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday"         : DATA_DIR / "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Friday_PortScan" : DATA_DIR / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
}

# Columns that are identifiers / leakage — must be dropped
METADATA_COLS = [
    "Flow ID",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Protocol",
    "Timestamp",
]

# Columns confirmed zero-variance from exploratory analysis
ZERO_VAR_COLS = [
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "CWE Flag Count",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
]

# Max rows loaded per file (keeps RAM ≤ ~2 GB for large CSVs)
ROWS_PER_FILE = 100_000


def load_csv(name: str, path: Path) -> pd.DataFrame:
    """Load one CICIDS2017 CSV and attach a source tag."""
    if not path.exists():
        log.error("File not found: %s", path)
        sys.exit(1)

    log.info("[%s] Loading from %s", name, path.name)
    t0 = time.time()
    df = pd.read_csv(path, nrows=ROWS_PER_FILE, low_memory=False)
    elapsed = time.time() - t0

    # Strip leading/trailing whitespace from column names (CICIDS2017 quirk)
    df.columns = df.columns.str.strip()
    log.info("[%s] Loaded %d rows × %d cols in %.1fs", name, len(df), df.shape[1], elapsed)
    return df


def encode_label(series: pd.Series) -> pd.Series:
    """Convert string labels → binary: BENIGN=0, any attack=1."""
    return series.str.strip().str.upper().apply(lambda x: 0 if x == "BENIGN" else 1)


def drop_columns(df: pd.DataFrame, cols_to_drop: list[str]) -> pd.DataFrame:
    """Drop columns that exist in the dataframe, warn on missing."""
    present   = [c for c in cols_to_drop if c in df.columns]
    missing   = [c for c in cols_to_drop if c not in df.columns]
    if missing:
        log.warning("  Columns not found (skipped): %s", missing)
    df = df.drop(columns=present)
    log.info("  Dropped %d column(s): %s", len(present), present)
    return df


def detect_zero_variance(df: pd.DataFrame, exclude: list[str]) -> list[str]:
    """Find columns that have only one unique value across the dataframe."""
    feature_cols = [c for c in df.columns if c not in exclude]
    zv = [c for c in feature_cols if df[c].nunique(dropna=False) <= 1]
    return zv


def clean_infinities(df: pd.DataFrame) -> pd.DataFrame:
    """Replace +/-Infinity with NaN, then fill all NaN with 0.0."""
    inf_mask = df.isin([np.inf, -np.inf])
    n_inf = inf_mask.sum().sum()
    if n_inf:
        log.info("  Replaced %d Inf/-Inf values → NaN", n_inf)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    n_nan = df.isnull().sum().sum()
    if n_nan:
        log.info("  Filled %d NaN values → 0.0", n_nan)
    df.fillna(0.0, inplace=True)
    return df


def clip_negative_values(df: pd.DataFrame) -> pd.DataFrame:
    """
    CICFlowMeter has a known bug where certain computed features (Flow Bytes/s,
    Fwd/Bwd Header Length, min_seg_size_forward) can be negative due to integer
    overflow or division artefacts. Clip these to 0 — they cannot be negative
    in a valid network flow.
    """
    feature_cols = [c for c in df.columns if c != "label"]
    neg_cols = [c for c in feature_cols if df[c].min() < 0]
    if neg_cols:
        log.info("  Clipping %d column(s) with negative values to 0: %s", len(neg_cols), neg_cols)
        df[neg_cols] = df[neg_cols].clip(lower=0)
    else:
        log.info("  No negative-value columns detected.")
    return df


def deduplicate(df: pd.DataFrame) -> pd.DataFrame:
    """
    CICIDS2017 Benign traffic is largely repeated (same flows captured across
    multiple days). Remove exact duplicate rows to reduce noise and prevent
    the model from memorising repeated benign patterns.
    """
    before = len(df)
    df = df.drop_duplicates().reset_index(drop=True)
    removed = before - len(df)
    log.info("  Removed %d duplicate rows (%.1f%% of data)", removed, removed / before * 100)
    return df


def fix_dtypes(df: pd.DataFrame) -> pd.DataFrame:
    """Coerce all feature columns to float32 to save memory."""
    feature_cols = [c for c in df.columns if c != "label"]
    df[feature_cols] = df[feature_cols].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    df[feature_cols] = df[feature_cols].astype("float32")
    return df


def print_class_distribution(df: pd.DataFrame) -> None:
    vc = df["label"].value_counts().sort_index()
    total = len(df)
    log.info(
        "  Class distribution — Benign: %d (%.1f%%)  |  Attack: %d (%.1f%%)",
        vc.get(0, 0), vc.get(0, 0) / total * 100,
        vc.get(1, 0), vc.get(1, 0) / total * 100,
    )


def main() -> None:
    log.info("=" * 60)
    log.info("PLEXUS — Data Cleaning Pipeline")
    log.info("=" * 60)

    # ── 1. Load all datasets ─────────────────────────────────────────────
    frames = []
    for name, path in DATASET_FILES.items():
        df = load_csv(name, path)

        # Encode label immediately and drop original Label column
        if "Label" not in df.columns:
            log.error("[%s] 'Label' column missing! Check CSV header.", name)
            sys.exit(1)

        df["label"] = encode_label(df["Label"])
        df = df.drop(columns=["Label"])

        vc = df["label"].value_counts().to_dict()
        log.info("[%s] Labels → Benign: %d | Attack: %d", name, vc.get(0, 0), vc.get(1, 0))
        frames.append(df)

    # ── 2. Merge ──────────────────────────────────────────────────────────
    log.info("")
    log.info("Merging datasets ...")
    df = pd.concat(frames, ignore_index=True)
    log.info("Combined shape: %s", df.shape)
    print_class_distribution(df)

    # ── 3. Drop metadata / identifier columns ─────────────────────────────
    log.info("")
    log.info("Dropping metadata columns ...")
    df = drop_columns(df, METADATA_COLS)

    # ── 4. Drop known zero-variance columns ───────────────────────────────
    log.info("Dropping known zero-variance columns ...")
    df = drop_columns(df, ZERO_VAR_COLS)

    # ── 5. Auto-detect any remaining zero-variance columns ────────────────
    extra_zv = detect_zero_variance(df, exclude=["label"])
    if extra_zv:
        log.info("Auto-detected additional zero-variance columns: %s", extra_zv)
        df = drop_columns(df, extra_zv)

    # ── 6. Clean infinities and NaN ───────────────────────────────────────
    log.info("")
    log.info("Cleaning Inf / NaN values ...")
    df = clean_infinities(df)

    # ── 6b. Clip known CICFlowMeter negative-value artefacts ──────────────
    log.info("Clipping negative feature values (CICFlowMeter artefacts) ...")
    df = clip_negative_values(df)

    # ── 6c. Remove duplicate rows ─────────────────────────────────────────
    log.info("Deduplicating rows ...")
    df = deduplicate(df)

    # ── 7. Fix data types ─────────────────────────────────────────────────
    log.info("Casting feature columns to float32 ...")
    df = fix_dtypes(df)

    # ── 8. Shuffle ────────────────────────────────────────────────────────
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    log.info("Dataset shuffled.")

    # ── 9. Final summary ─────────────────────────────────────────────────
    log.info("")
    log.info("── Final Dataset Summary ──────────────────────────────")
    log.info("  Shape      : %s", df.shape)
    log.info("  Features   : %d  (excl. label)", df.shape[1] - 1)
    log.info("  Memory     : %.1f MB", df.memory_usage(deep=True).sum() / 1e6)
    print_class_distribution(df)

    # ── 10. Save to Parquet ───────────────────────────────────────────────
    out_path = ARTIFACT_DIR / "cleaned_data.parquet"
    df.to_parquet(out_path, index=False)
    log.info("")
    log.info("✓ Saved cleaned dataset → %s", out_path)

    # ── 11. Save column manifest ──────────────────────────────────────────
    feature_cols = [c for c in df.columns if c != "label"]
    manifest = {
        "total_features": len(feature_cols),
        "feature_columns": feature_cols,
        "dropped_metadata": METADATA_COLS,
        "dropped_zero_variance": ZERO_VAR_COLS + extra_zv,
        "rows": len(df),
        "class_distribution": df["label"].value_counts().to_dict(),
    }
    manifest_path = ARTIFACT_DIR / "column_manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    log.info("✓ Saved column manifest  → %s", manifest_path)
    log.info("")
    log.info("Data cleaning complete. Run validate_data.py to verify.")


if __name__ == "__main__":
    main()
