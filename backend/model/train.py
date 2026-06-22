"""
Production-grade Multi-Label Android APK Threat Classification Pipeline.

Usage:
    python train.py --data path/to/full_dataset.csv
    python train.py --data path/to/full_dataset.csv --output-dir artifacts/
"""

from __future__ import annotations

import argparse
import json
import logging
import pickle
import sys
import warnings
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any
import sqlite3
import numpy as np
import pandas as pd
import shap
import matplotlib
matplotlib.use("Agg")
import os
import urllib.request
from pathlib import Path
import matplotlib.pyplot as plt


from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    f1_score, precision_score, recall_score,
    roc_auc_score, average_precision_score,
    hamming_loss, accuracy_score,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.multioutput import MultiOutputClassifier
from lightgbm import LGBMClassifier

warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)

# ─────────────────────────── Logging ───────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("apk_classifier")


# ─────────────────────────── Constants ─────────────────────────────────────

# TARGET_LABELS: list[str] = [
#     "banking_trojan",
#     "sms_stealer",     # dataset column: label_sms_trojan
#     "spyware",
#     "ransomware",
#     "adware",
#     "obfuscated_loader",
#     "benign",
# ]

# # Map canonical label names → actual CSV column names
# LABEL_COLUMN_MAP: dict[str, str] = {
#     "banking_trojan":   "label_banking_trojan",
#     "sms_stealer":      "label_sms_trojan",
#     "spyware":          "label_spyware",
#     "ransomware":       "label_ransomware",
#     "adware":           "label_adware",
#     "obfuscated_loader": "label_obfuscated_loader",
#     "benign":           "label_benign",
# }

TARGET_LABELS: list[str] = [
    "banking_trojan",
    "sms_stealer",    
    "spyware",
    "obfuscated_loader",
    "benign",
]

# Map canonical label names → actual CSV column names
LABEL_COLUMN_MAP: dict[str, str] = {
    "banking_trojan":    "label_banking_trojan",
    "sms_stealer":       "label_sms_stealer",
    "spyware":           "label_spyware",
    "obfuscated_loader": "label_obfuscated_loader",
    "benign":            "label_benign",
}

# Columns that should never be used as features
METADATA_PATTERNS: list[str] = [
    "sample_id", "family", "variant", "epoch",
    "is_benign", "is_hard_benign", "label_names",
]

# Columns that look like leakage (checked by pattern matching)
LEAKAGE_PATTERNS: list[str] = [
    "family", "variant", "label_names",
    "hash", "sha", "md5", "filename", "apk_name",
    "timestamp", "date", "time",
    "soft_",   # soft labels derived from targets
]

LGBM_PARAMS: dict[str, Any] = {
    "n_estimators":       1000,
    "num_leaves":         15,
    "max_depth":          5,
    "min_child_samples":  50,
    "min_gain_to_split":  0.1,
    "feature_fraction":   0.8,
    "bagging_fraction":   0.8,
    "bagging_freq":       5,
    "lambda_l1":          1.0,
    "lambda_l2":          1.0,
    "learning_rate":      0.03,
    "random_state":       42,
    "n_jobs":             -1,
    "verbose":            -1,
}


# ─────────────────────────── Dataclasses ────────────────────────────────────

@dataclass
class FeatureReport:
    original_feature_count:   int = 0
    after_zero_variance:      int = 0
    after_high_correlation:   int = 0
    removed_zero_variance:    list[str] = field(default_factory=list)
    removed_high_correlation: list[str] = field(default_factory=list)
    correlation_groups:       list[list[str]] = field(default_factory=list)
    final_features:           list[str] = field(default_factory=list)


@dataclass
class LeakageReport:
    detected_leakage_columns: list[str] = field(default_factory=list)
    reason:                   dict[str, str] = field(default_factory=dict)
    warning_issued:           bool = False


@dataclass
class MetricsBundle:
    f1_macro:       float = 0.0
    f1_micro:       float = 0.0
    precision_macro: float = 0.0
    recall_macro:   float = 0.0
    roc_auc_macro:  float = 0.0
    pr_auc_macro:   float = 0.0
    hamming_loss:   float = 0.0
    exact_match:    float = 0.0
    per_label:      dict[str, dict[str, float]] = field(default_factory=dict)


# ─────────────────────────── Data Loading ───────────────────────────────────

# def load_dataset(csv_path: str) -> pd.DataFrame:
#     """Load CSV dataset; handle common encoding issues."""
#     logger.info("Loading dataset from %s", csv_path)
#     df = pd.read_csv(csv_path, low_memory=False)
#     logger.info("Loaded %d rows × %d columns", *df.shape)
#     return df


def load_dataset(sqlite_path: str, labels_path: str) -> pd.DataFrame:
    """Load features from SQLite and labels from CSV, then merge them on apk_hash."""
    logger.info("Loading features from %s and labels from %s", sqlite_path, labels_path)
    
    # 1. Load the labels CSV
    labels_df = pd.read_csv(labels_path, low_memory=False)
    
    # 2. Connect to the SQLite database and pull the 'features' table
    conn = sqlite3.connect(sqlite_path)
    try:
        features_df = pd.read_sql_query("SELECT * FROM features", conn)
    finally:
        conn.close()
        
    # 3. Merge them together using the apk_hash
    df = pd.merge(features_df, labels_df, on="apk_hash", how="inner")
    
    logger.info("Merged dataset shape: %d rows × %d columns", *df.shape)
    return df

# def split_dataset(
#     df: pd.DataFrame,
#     val_ratio: float = 0.15,
#     test_ratio: float = 0.15,
#     random_state: int = 42,
# ) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
#     """
#     Create stratified splits:
#       - train / val / test_random (from normal samples)
#       - test_family_split  (unseen families)
#       - test_temporal_split (latest epoch)
#       - test_hard_benign   (is_hard_benign==True samples)
#     """
#     from sklearn.model_selection import train_test_split

#     # Hard benign split
#     hard_benign = df[df["is_hard_benign"] == True].copy()

#     # Temporal split: hold out last epoch
#     max_epoch = df["epoch"].max()
#     temporal = df[(df["epoch"] == max_epoch) & (df["is_hard_benign"] != True)].copy()

#     # Family split: hold out families appearing infrequently
#     family_counts = df["family"].value_counts()
#     rare_families = family_counts[family_counts <= 3].index
#     family_split = df[
#         (df["family"].isin(rare_families)) &
#         (df["is_hard_benign"] != True) &
#         (df["epoch"] != max_epoch)
#     ].copy()

#     # Remaining data for train/val/test
#     used_idx = set(hard_benign.index) | set(temporal.index) | set(family_split.index)
#     main = df[~df.index.isin(used_idx)].copy()

#     # Stratify by first target label with enough samples
#     strat_col = LABEL_COLUMN_MAP["banking_trojan"]
#     main_train, main_temp = train_test_split(
#         main, test_size=(val_ratio + test_ratio),
#         stratify=main[strat_col], random_state=random_state
#     )
#     main_val, main_test = train_test_split(
#         main_temp, test_size=test_ratio / (val_ratio + test_ratio),
#         stratify=main_temp[strat_col], random_state=random_state
#     )

#     logger.info(
#         "Split sizes → train:%d  val:%d  test:%d  family:%d  temporal:%d  hard_benign:%d",
#         len(main_train), len(main_val), len(main_test),
#         len(family_split), len(temporal), len(hard_benign),
#     )

    # # Ensure evaluation sets are non-empty (fallback: sample from main)
    # def _ensure_nonempty(split_df: pd.DataFrame, name: str, fallback: pd.DataFrame) -> pd.DataFrame:
    #     if len(split_df) < 5:
    #         logger.warning("%s split has < 5 samples – sampling 50 from main test set.", name)
    #         sample = fallback.sample(min(50, len(fallback)), random_state=random_state)
    #         split_df = pd.concat([split_df, sample]).drop_duplicates()
    #     return split_df

    # family_split  = _ensure_nonempty(family_split,  "family_split",  main_test)
    # temporal       = _ensure_nonempty(temporal,       "temporal_split", main_test)
    # hard_benign    = _ensure_nonempty(hard_benign,    "hard_benign",    main_test)

    # return main_train, main_val, main_test, family_split, temporal, hard_benign
    
def split_dataset(
    df: pd.DataFrame,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Standard stratified split (advanced temporal/family splits disabled)."""
    from sklearn.model_selection import train_test_split

    strat_col = LABEL_COLUMN_MAP["banking_trojan"]
    
    main_train, temp = train_test_split(
        df, test_size=(val_ratio + test_ratio),
        stratify=df[strat_col], random_state=random_state
    )
    
    main_val, main_test = train_test_split(
        temp, test_size=test_ratio / (val_ratio + test_ratio),
        stratify=temp[strat_col], random_state=random_state
    )

    logger.info(
        "Split sizes → train:%d  val:%d  test:%d",
        len(main_train), len(main_val), len(main_test)
    )

    empty_df = pd.DataFrame(columns=df.columns)
    return main_train, main_val, main_test, empty_df, empty_df, empty_df


# ─────────────────────────── Leakage Detection ─────────────────────────────

def detect_leakage(df: pd.DataFrame, feature_cols: list[str]) -> LeakageReport:
    """Detect and report potential data leakage columns."""
    report = LeakageReport()

    for col in feature_cols:
        col_lower = col.lower()

        # Pattern matching
        for pattern in LEAKAGE_PATTERNS:
            if pattern in col_lower:
                report.detected_leakage_columns.append(col)
                report.reason[col] = f"Matches leakage pattern: '{pattern}'"
                break

        # High cardinality string columns
        if col in df.columns and df[col].dtype == object:
            unique_ratio = df[col].nunique() / len(df)
            if unique_ratio > 0.5:
                if col not in report.detected_leakage_columns:
                    report.detected_leakage_columns.append(col)
                    report.reason[col] = f"High-cardinality string column (ratio={unique_ratio:.2f})"

    report.detected_leakage_columns = list(set(report.detected_leakage_columns))

    if report.detected_leakage_columns:
        report.warning_issued = True
        logger.warning(
            "⚠  Leakage detection: removing %d suspicious columns: %s",
            len(report.detected_leakage_columns),
            report.detected_leakage_columns,
        )

    return report


# ─────────────────────────── Feature Engineering ───────────────────────────

def identify_columns(df: pd.DataFrame) -> tuple[list[str], list[str]]:
    """Identify feature and target columns automatically."""
    target_cols = list(LABEL_COLUMN_MAP.values())
    meta_cols = METADATA_PATTERNS + [c for c in df.columns if c.startswith("soft_")]

    feature_cols = [
        c for c in df.columns
        if c not in target_cols and c not in meta_cols
    ]
    return feature_cols, target_cols


def clean_features(
    df: pd.DataFrame,
    feature_cols: list[str],
    corr_threshold: float = 0.95,
) -> tuple[pd.DataFrame, FeatureReport]:
    """Remove zero-variance, duplicates, and highly correlated features."""
    report = FeatureReport()
    report.original_feature_count = len(feature_cols)

    X = df[feature_cols].copy()

    # Coerce to numeric; drop non-numeric
    X = X.apply(pd.to_numeric, errors="coerce")

    # Fill missing values with median
    X = X.fillna(X.median())

    # Zero-variance features
    variances = X.var()
    zero_var_cols = variances[variances == 0].index.tolist()
    X = X.drop(columns=zero_var_cols)
    report.removed_zero_variance = zero_var_cols
    report.after_zero_variance = len(X.columns)
    logger.info("Removed %d zero-variance features.", len(zero_var_cols))

    # High-correlation removal
    corr_matrix = X.corr().abs()
    upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))

    to_drop: set[str] = set()
    groups: list[list[str]] = []

    for col in upper.columns:
        correlated = upper.index[upper[col] > corr_threshold].tolist()
        if correlated and col not in to_drop:
            group = [col] + correlated
            groups.append(group)
            for c in correlated:
                to_drop.add(c)

    X = X.drop(columns=list(to_drop))
    report.removed_high_correlation = list(to_drop)
    report.correlation_groups = groups
    report.after_high_correlation = len(X.columns)
    report.final_features = list(X.columns)

    logger.info(
        "Removed %d highly-correlated features (threshold=%.2f). Final: %d features.",
        len(to_drop), corr_threshold, len(X.columns),
    )

    return X, report


def prepare_xy(
    df: pd.DataFrame,
    feature_cols: list[str],
    fit_medians: pd.Series | None = None,
) -> tuple[np.ndarray, np.ndarray, pd.Series]:
    """Prepare X (features) and Y (labels) arrays."""
    X = df[feature_cols].copy()
    X = X.apply(pd.to_numeric, errors="coerce")

    if fit_medians is None:
        fit_medians = X.median()
    X = X.fillna(fit_medians)

    Y_cols = [LABEL_COLUMN_MAP[t] for t in TARGET_LABELS]
    Y = df[Y_cols].values.astype(int)

    return X.values.astype(np.float32), Y, fit_medians


# ─────────────────────────── Metrics ───────────────────────────────────────

def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray,
    label_names: list[str] | None = None,
) -> MetricsBundle:
    """Compute full multi-label metrics bundle."""
    if label_names is None:
        label_names = TARGET_LABELS

    mb = MetricsBundle()
    mb.f1_macro       = f1_score(y_true, y_pred, average="macro",  zero_division=0)
    mb.f1_micro       = f1_score(y_true, y_pred, average="micro",  zero_division=0)
    mb.precision_macro = precision_score(y_true, y_pred, average="macro", zero_division=0)
    mb.recall_macro   = recall_score(y_true, y_pred, average="macro",  zero_division=0)
    mb.hamming_loss   = hamming_loss(y_true, y_pred)
    mb.exact_match    = accuracy_score(y_true, y_pred)

    # ROC-AUC and PR-AUC per label then averaged
    roc_aucs, pr_aucs = [], []
    for i, lbl in enumerate(label_names):
        if y_true[:, i].sum() > 0:
            try:
                roc_aucs.append(roc_auc_score(y_true[:, i], y_prob[:, i]))
                pr_aucs.append(average_precision_score(y_true[:, i], y_prob[:, i]))
            except Exception:
                pass

    mb.roc_auc_macro = float(np.mean(roc_aucs)) if roc_aucs else 0.0
    mb.pr_auc_macro  = float(np.mean(pr_aucs))  if pr_aucs  else 0.0

    # Per-label metrics
    for i, lbl in enumerate(label_names):
        mb.per_label[lbl] = {
            "f1":        float(f1_score(y_true[:, i], y_pred[:, i], zero_division=0)),
            "precision": float(precision_score(y_true[:, i], y_pred[:, i], zero_division=0)),
            "recall":    float(recall_score(y_true[:, i], y_pred[:, i], zero_division=0)),
            "support":   int(y_true[:, i].sum()),
        }
        if y_true[:, i].sum() > 0:
            try:
                mb.per_label[lbl]["roc_auc"] = float(roc_auc_score(y_true[:, i], y_prob[:, i]))
                mb.per_label[lbl]["pr_auc"]  = float(average_precision_score(y_true[:, i], y_prob[:, i]))
            except Exception:
                mb.per_label[lbl]["roc_auc"] = 0.0
                mb.per_label[lbl]["pr_auc"]  = 0.0

    return mb


def print_metrics(name: str, mb: MetricsBundle) -> None:
    logger.info("── %s ──", name)
    logger.info("  F1  Macro=%.4f  Micro=%.4f", mb.f1_macro, mb.f1_micro)
    logger.info("  Precision=%.4f  Recall=%.4f", mb.precision_macro, mb.recall_macro)
    logger.info("  ROC-AUC=%.4f  PR-AUC=%.4f", mb.roc_auc_macro, mb.pr_auc_macro)
    logger.info("  Hamming=%.4f  ExactMatch=%.4f", mb.hamming_loss, mb.exact_match)
    for lbl, m in mb.per_label.items():
        logger.info(
            "    %-22s  F1=%.3f  Prec=%.3f  Rec=%.3f  n=%d",
            lbl, m["f1"], m["precision"], m["recall"], m["support"],
        )


# ─────────────────────────── Threshold Optimization ────────────────────────

def optimize_thresholds(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    label_names: list[str],
) -> dict[str, float]:
    """Grid search per-label threshold maximizing F1 on validation set."""
    thresholds: dict[str, float] = {}

    for i, lbl in enumerate(label_names):
        best_t, best_f1 = 0.5, 0.0
        for t in np.arange(0.05, 0.96, 0.01):
            preds = (y_prob[:, i] >= t).astype(int)
            f1 = f1_score(y_true[:, i], preds, zero_division=0)
            if f1 > best_f1:
                best_f1 = f1
                best_t  = float(t)
        thresholds[lbl] = round(best_t, 3)
        logger.info("  Threshold %-22s → %.3f  (val F1=%.4f)", lbl, best_t, best_f1)

    return thresholds


def apply_thresholds(
    y_prob: np.ndarray,
    thresholds: dict[str, float],
    label_names: list[str],
) -> np.ndarray:
    y_pred = np.zeros_like(y_prob, dtype=int)
    for i, lbl in enumerate(label_names):
        y_pred[:, i] = (y_prob[:, i] >= thresholds[lbl]).astype(int)
    return y_pred


# ─────────────────────────── Model Training ─────────────────────────────────

def build_lgbm_model() -> MultiOutputClassifier:
    base = LGBMClassifier(objective="binary", **LGBM_PARAMS)
    return MultiOutputClassifier(base, n_jobs=1)


def build_logreg_model() -> MultiOutputClassifier:
    base = LogisticRegression(
        max_iter=1000, C=0.1,
        class_weight="balanced",
        random_state=42, n_jobs=-1,
    )
    return MultiOutputClassifier(base, n_jobs=-1)


def train_lgbm_with_early_stopping(
    X_train: np.ndarray,
    Y_train: np.ndarray,
    X_val: np.ndarray,
    Y_val: np.ndarray,
    feature_names: list[str],
) -> MultiOutputClassifier:
    """Train LightGBM with per-label early stopping."""
    from lightgbm import early_stopping, log_evaluation

    estimators: list[LGBMClassifier] = []

    for i, lbl in enumerate(TARGET_LABELS):
        logger.info("  Training label: %s", lbl)
        clf = LGBMClassifier(objective="binary", **LGBM_PARAMS)
        clf.fit(
            X_train, Y_train[:, i],
            eval_set=[(X_val, Y_val[:, i])],
            eval_metric="binary_logloss",
            callbacks=[
                early_stopping(stopping_rounds=50, verbose=False),
                log_evaluation(period=-1),
            ],
            feature_name=feature_names,
        )
        logger.info(
            "    Best iteration: %d  (train labels: %d pos / %d total)",
            clf.best_iteration_, Y_train[:, i].sum(), len(Y_train),
        )
        estimators.append(clf)

    # Wrap in MultiOutputClassifier-like object
    model = _MultiLabelWrapper(estimators)
    return model


class _MultiLabelWrapper:
    """Thin wrapper that exposes predict/predict_proba for a list of per-label estimators."""

    def __init__(self, estimators: list[LGBMClassifier]) -> None:
        self.estimators_ = estimators

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        probs = np.column_stack([
            est.predict_proba(X)[:, 1] for est in self.estimators_
        ])
        return probs

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.predict_proba(X) >= 0.5).astype(int)

    @property
    def feature_importances_(self) -> np.ndarray:
        return np.mean(
            [est.feature_importances_ for est in self.estimators_], axis=0
        )

    def get_estimator(self, idx: int) -> LGBMClassifier:
        return self.estimators_[idx]


# ─────────────────────────── Calibration ────────────────────────────────────

def calibrate_model(
    model: _MultiLabelWrapper,
    X_val: np.ndarray,
    Y_val: np.ndarray,
    X_train: np.ndarray,
    Y_train: np.ndarray,
    feature_names: list[str],
) -> _MultiLabelWrapper:
    """Apply probability calibration per label; choose Platt or Isotonic."""
    from sklearn.metrics import brier_score_loss

    calibrated_estimators: list = []

    for i, lbl in enumerate(TARGET_LABELS):
        est = model.estimators_[i]
        raw_probs = est.predict_proba(X_val)[:, 1]

        best_method = "sigmoid"
        best_brier  = brier_score_loss(Y_val[:, i], raw_probs)

        for method in ("sigmoid", "isotonic"):
            try:
                # sklearn ≥1.2: use cv="prefit"; older: pass as positional
                try:
                    cal = CalibratedClassifierCV(est, method=method, cv="prefit")
                except TypeError:
                    cal = CalibratedClassifierCV(est, cv=5, method=method)
                cal.fit(X_val, Y_val[:, i])
                cal_probs = cal.predict_proba(X_val)[:, 1]
                brier = brier_score_loss(Y_val[:, i], cal_probs)
                if brier < best_brier:
                    best_brier  = brier
                    best_method = method
            except Exception as exc:
                logger.debug("Calibration %s failed for %s: %s", method, lbl, exc)

        # Fit best method
        try:
            try:
                cal_final = CalibratedClassifierCV(est, method=best_method, cv="prefit")
            except TypeError:
                cal_final = CalibratedClassifierCV(est, cv=5, method=best_method)
            cal_final.fit(X_val, Y_val[:, i])
            calibrated_estimators.append(cal_final)
            logger.info("  Calibrated %-22s with %-9s  Brier=%.4f", lbl, best_method, best_brier)
        except Exception as exc:
            logger.warning("  Calibration failed for %s (%s) – keeping raw.", lbl, exc)
            calibrated_estimators.append(est)

    return _MultiLabelWrapper(calibrated_estimators)


# ─────────────────────────── Cross Validation ───────────────────────────────

def cross_validate_model(
    X: np.ndarray,
    Y: np.ndarray,
    n_splits: int = 5,
) -> dict[str, Any]:
    """5-fold cross-validation reporting mean ± std for multiple metrics."""
    logger.info("Running %d-fold cross-validation...", n_splits)

    kf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    # Stratify on first label
    strat_y = Y[:, 0]

    cv_results: dict[str, list[float]] = {
        "f1_macro": [], "f1_micro": [], "precision_macro": [], "recall_macro": [],
    }

    for fold, (train_idx, val_idx) in enumerate(kf.split(X, strat_y)):
        X_tr, X_vl = X[train_idx], X[val_idx]
        Y_tr, Y_vl = Y[train_idx], Y[val_idx]

        fold_estimators: list[LGBMClassifier] = []
        for i in range(Y.shape[1]):
            clf = LGBMClassifier(objective="binary", **LGBM_PARAMS)
            clf.fit(X_tr, Y_tr[:, i])
            fold_estimators.append(clf)

        probs = np.column_stack([e.predict_proba(X_vl)[:, 1] for e in fold_estimators])
        preds = (probs >= 0.5).astype(int)

        cv_results["f1_macro"].append(f1_score(Y_vl, preds, average="macro",  zero_division=0))
        cv_results["f1_micro"].append(f1_score(Y_vl, preds, average="micro",  zero_division=0))
        cv_results["precision_macro"].append(precision_score(Y_vl, preds, average="macro", zero_division=0))
        cv_results["recall_macro"].append(recall_score(Y_vl, preds, average="macro",    zero_division=0))

        logger.info(
            "  Fold %d | F1 Macro=%.4f  Micro=%.4f",
            fold + 1, cv_results["f1_macro"][-1], cv_results["f1_micro"][-1],
        )

    summary: dict[str, Any] = {}
    for metric, values in cv_results.items():
        summary[metric] = {
            "mean": float(np.mean(values)),
            "std":  float(np.std(values)),
            "values": [float(v) for v in values],
        }
        logger.info(
            "  CV %-20s  mean=%.4f ± %.4f",
            metric, summary[metric]["mean"], summary[metric]["std"],
        )

    return summary


# ─────────────────────────── Explainability ─────────────────────────────────

def generate_shap_plots(
    model: _MultiLabelWrapper,
    X: np.ndarray,
    feature_names: list[str],
    output_dir: Path,
) -> None:
    """Generate SHAP summary plots per label and global importance."""
    logger.info("Generating SHAP explanations (this may take a minute)...")

    plots_dir = output_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)

    # Sample for SHAP (max 500 for speed)
    n_shap = min(500, len(X))
    idx    = np.random.default_rng(42).choice(len(X), n_shap, replace=False)
    X_shap = X[idx]

    global_importance: dict[str, dict[str, float]] = {}

    for i, lbl in enumerate(TARGET_LABELS):
        est = model.estimators_[i]
        # Unwrap CalibratedClassifierCV if needed
        raw_est = est
        if hasattr(est, "calibrated_classifiers_"):
            raw_est = est.calibrated_classifiers_[0].estimator

        try:
            explainer  = shap.TreeExplainer(raw_est)
            shap_vals  = explainer.shap_values(X_shap)
            if isinstance(shap_vals, list):
                shap_vals = shap_vals[1]  # binary: take positive class

            # Per-label summary plot
            fig, ax = plt.subplots(figsize=(10, 8))
            shap.summary_plot(
                shap_vals, X_shap,
                feature_names=feature_names,
                max_display=20,
                show=False,
            )
            plt.title(f"SHAP Summary – {lbl}")
            plt.tight_layout()
            plot_path = plots_dir / f"shap_summary_{lbl}.png"
            plt.savefig(plot_path, dpi=100, bbox_inches="tight")
            plt.close()

            # Top-20 features
            mean_abs = np.abs(shap_vals).mean(axis=0)
            top_idx  = np.argsort(mean_abs)[::-1][:20]
            global_importance[lbl] = {
                feature_names[j]: float(mean_abs[j]) for j in top_idx
            }
            logger.info("  SHAP plot saved: %s", plot_path)

        except Exception as exc:
            logger.warning("  SHAP failed for %s: %s", lbl, exc)
            global_importance[lbl] = {}

    # Save global importance JSON
    imp_path = output_dir / "global_shap_importance.json"
    imp_path.write_text(json.dumps(global_importance, indent=2))
    logger.info("Global SHAP importance saved: %s", imp_path)


# ─────────────────────────── Generalization Report ──────────────────────────

def generalization_report(
    train_f1:   float,
    val_f1:     float,
    test_f1:    float,
    family_f1:  float,
    temporal_f1: float,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "train_f1_macro":    round(train_f1,    4),
        "val_f1_macro":      round(val_f1,      4),
        "test_f1_macro":     round(test_f1,     4),
        "family_f1_macro":   round(family_f1,   4),
        "temporal_f1_macro": round(temporal_f1, 4),
        "flags":             [],
        "conclusions":       [],
    }

    if train_f1 - val_f1 > 0.10:
        msg = f"⚠ OVERFIT: train_f1 ({train_f1:.4f}) − val_f1 ({val_f1:.4f}) > 0.10"
        report["flags"].append(msg)
        logger.warning(msg)

    if val_f1 - test_f1 > 0.10:
        msg = f"⚠ OVERFIT: val_f1 ({val_f1:.4f}) − test_f1 ({test_f1:.4f}) > 0.10"
        report["flags"].append(msg)
        logger.warning(msg)

    # Family / temporal conclusions are only meaningful when those splits exist.
    # They are disabled in split_dataset() (empty -> f1_macro == 0.0); reporting a
    # gap against an empty split would falsely claim the model fails to generalize.
    if family_f1 > 0.0:
        gap = test_f1 - family_f1
        if gap > 0.10:
            report["conclusions"].append(
                f"Model does NOT generalize well to unseen families (gap={gap:.4f}). "
                "Consider collecting more diverse training data or domain adaptation."
            )
        else:
            report["conclusions"].append(
                f"Model generalizes acceptably to unseen families (gap={gap:.4f})."
            )
    else:
        report["conclusions"].append(
            "Unseen-family generalization not evaluated (family split disabled)."
        )

    if temporal_f1 > 0.0:
        t_gap = test_f1 - temporal_f1
        if t_gap > 0.10:
            report["conclusions"].append(
                f"Model shows temporal degradation (gap={t_gap:.4f}). "
                "Newer malware samples may exhibit concept drift."
            )
        else:
            report["conclusions"].append(
                f"Temporal generalization is adequate (gap={t_gap:.4f})."
            )
    else:
        report["conclusions"].append(
            "Temporal generalization not evaluated (temporal split disabled)."
        )

    logger.info("── Generalization Report ──")
    for k, v in report.items():
        if isinstance(v, list):
            for item in v:
                logger.info("  %s", item)
        else:
            logger.info("  %-22s = %s", k, v)

    return report


# ─────────────────────────── Baseline Comparison ────────────────────────────

def compare_baselines(
    X_train: np.ndarray,
    Y_train: np.ndarray,
    X_val:   np.ndarray,
    Y_val:   np.ndarray,
    X_test:  np.ndarray,
    Y_test:  np.ndarray,
) -> dict[str, Any]:
    """Train LogisticRegression baseline and compare to LightGBM."""
    logger.info("Training Logistic Regression baseline...")
    lr_model = build_logreg_model()
    lr_model.fit(X_train, Y_train)

    lr_probs = np.column_stack([
        est.predict_proba(X_test)[:, 1] for est in lr_model.estimators_
    ])
    lr_preds = (lr_probs >= 0.5).astype(int)
    lr_f1_macro = f1_score(Y_test, lr_preds, average="macro",  zero_division=0)
    lr_f1_micro = f1_score(Y_test, lr_preds, average="micro",  zero_division=0)
    lr_pr_auc   = float(np.mean([
        average_precision_score(Y_test[:, i], lr_probs[:, i])
        for i in range(Y_test.shape[1]) if Y_test[:, i].sum() > 0
    ]))

    logger.info(
        "LogReg baseline  F1 Macro=%.4f  Micro=%.4f  PR-AUC=%.4f",
        lr_f1_macro, lr_f1_micro, lr_pr_auc,
    )

    return {
        "logreg": {
            "f1_macro": float(lr_f1_macro),
            "f1_micro": float(lr_f1_micro),
            "pr_auc":   float(lr_pr_auc),
        }
    }


# ─────────────────────────── Inference API ──────────────────────────────────

class APKClassifier:
    """Production inference API for multi-label APK threat classification."""

    def __init__(
        self,
        model: _MultiLabelWrapper,
        thresholds: dict[str, float],
        feature_names: list[str],
        fit_medians: pd.Series,
    ) -> None:
        self.model         = model
        self.thresholds    = thresholds
        self.feature_names = feature_names
        self.fit_medians   = fit_medians

    def predict_apk(self, features_dict: dict[str, float]) -> dict[str, dict[str, Any]]:
        """
        Returns per-label probability and binary prediction.

        Args:
            features_dict: mapping of feature_name → numeric value

        Returns:
            {
                "banking_trojan": {"probability": 0.87, "prediction": True},
                ...
            }
        """
        # Build feature vector
        row = pd.Series(features_dict)
        X   = np.array([
            float(row.get(f, self.fit_medians.get(f, 0.0)))
            for f in self.feature_names
        ], dtype=np.float32).reshape(1, -1)

        probs = self.model.predict_proba(X)[0]

        result: dict[str, dict[str, Any]] = {}
        for i, lbl in enumerate(TARGET_LABELS):
            prob = float(probs[i])
            result[lbl] = {
                "probability": round(prob, 4),
                "prediction":  prob >= self.thresholds[lbl],
            }

        return result

    @classmethod
    def load(cls, artifacts_dir: str | Path) -> "APKClassifier":
        artifacts_dir = Path(artifacts_dir)
        with open(artifacts_dir / "model.pkl", "rb") as f:
            payload = pickle.load(f)
        return cls(**payload)

    def save(self, artifacts_dir: str | Path) -> None:
        artifacts_dir = Path(artifacts_dir)
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "model":         self.model,
            "thresholds":    self.thresholds,
            "feature_names": self.feature_names,
            "fit_medians":   self.fit_medians,
        }
        with open(artifacts_dir / "model.pkl", "wb") as f:
            pickle.dump(payload, f, protocol=4)
        logger.info("Model saved to %s/model.pkl", artifacts_dir)

# # ─────────────────────────── ──────────────────────────────────

# def ensure_data_exists(features_path: str, labels_path: str):
#     """Downloads the datasets if they aren't already locally available."""
#     os.makedirs("data", exist_ok=True)
    
#     # Replace these with your actual direct download links!
#     URLS = {
#         features_path: "YOUR_DIRECT_LINK_TO_SQLITE_HERE",
#         labels_path: "YOUR_DIRECT_LINK_TO_LABELS_CSV_HERE"
#     }

#     for path, url in URLS.items():
#         if not os.path.exists(path):
#             logger.info(f"Downloading missing dataset to {path}...")
#             try:
#                 urllib.request.urlretrieve(url, path)
#                 logger.info(f"Successfully downloaded {path}")
#             except Exception as e:
#                 logger.error(f"Failed to download {path}: {e}")
#                 raise SystemExit("Dataset download failed. Please check the URLs.")


# ─────────────────────────── Main Pipeline ──────────────────────────────────

# def run_pipeline(data_path: str, output_dir: str) -> None:
#     output_dir_path = Path(output_dir)
#     output_dir_path.mkdir(parents=True, exist_ok=True)
#     (output_dir_path / "plots").mkdir(exist_ok=True)

#     np.random.seed(42)

#     # ── 1. Load & split ──────────────────────────────────────────────────
#     df = load_dataset(data_path)
#     df = df.drop_duplicates()
#     logger.info("After dedup: %d rows", len(df))
def run_pipeline(features_path: str, labels_path: str, output_dir: str) -> None:
    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)
    (output_dir_path / "plots").mkdir(exist_ok=True)

    np.random.seed(42)

# ── 1. Load & Data Prep ──────────────────────────────────────────────
    df = load_dataset(features_path, labels_path)
    df = df.drop_duplicates()
    logger.info("After dedup: %d rows", len(df))

    # Dynamically grab all columns that aren't the hash or the labels
    label_cols = list(LABEL_COLUMN_MAP.values())
    feature_cols = [col for col in df.columns if col not in label_cols and col != "apk_hash"]

    # ── 2. Leakage detection ─────────────────────────────────────────────
    leakage_report = detect_leakage(df, feature_cols)
    safe_features  = [c for c in feature_cols if c not in leakage_report.detected_leakage_columns]

    # ── 3. Split Dataset ─────────────────────────────────────────────────
    # THIS is the crucial missing line that creates all your dataframes!
    train_df, val_df, test_df, family_df, temporal_df, hard_benign_df = split_dataset(df)

    # ── 4. Feature cleaning (fit on train only) ──────────────────────────
    X_train_raw, feat_report = clean_features(train_df, safe_features)
    final_features = feat_report.final_features

    # ── 5. Prepare arrays ────────────────────────────────────────────────
    X_train, Y_train, fit_medians = prepare_xy(train_df, final_features)
    X_val,   Y_val,   _           = prepare_xy(val_df,   final_features, fit_medians)
    X_test,  Y_test,  _           = prepare_xy(test_df,  final_features, fit_medians)
    
    # We pass the empty dataframes from our simplified split logic here
    # so the rest of the evaluation pipeline doesn't crash
    X_fam,   Y_fam,   _           = prepare_xy(family_df,   final_features, fit_medians)
    X_tmp,   Y_tmp,   _           = prepare_xy(temporal_df, final_features, fit_medians)
    X_hbn,   Y_hbn,   _           = prepare_xy(hard_benign_df, final_features, fit_medians)

    # ── 6. Cross-validation ──────────────────────────────────────────────
    X_trainval = np.vstack([X_train, X_val])
    Y_trainval = np.vstack([Y_train, Y_val])
    cv_results = cross_validate_model(X_trainval, Y_trainval)

    # ── 7. Train LGBM with early stopping ────────────────────────────────
    logger.info("Training LightGBM with early stopping...")
    lgbm_model = train_lgbm_with_early_stopping(
        X_train, Y_train, X_val, Y_val, final_features
    )

    # ── 8. Calibration ───────────────────────────────────────────────────
    logger.info("Calibrating probabilities...")
    lgbm_model = calibrate_model(lgbm_model, X_val, Y_val, X_train, Y_train, final_features)

    # ── 9. Threshold optimization ─────────────────────────────────────────
    logger.info("Optimizing thresholds on validation set...")
    val_probs  = lgbm_model.predict_proba(X_val)
    thresholds = optimize_thresholds(Y_val, val_probs, TARGET_LABELS)

    # ── 10. Baseline comparison ───────────────────────────────────────────
    # Logistic Regression cannot handle missing values (NaNs) natively.
    # We temporarily fill NaNs with 0.0 just to allow the baseline to run.
    X_train_imputed = np.nan_to_num(X_train, nan=0.0)
    X_val_imputed   = np.nan_to_num(X_val, nan=0.0)
    X_test_imputed  = np.nan_to_num(X_test, nan=0.0)

    baseline_results = compare_baselines(
        X_train_imputed, Y_train, 
        X_val_imputed, Y_val, 
        X_test_imputed, Y_test
    )

    # ── 11. Evaluate all splits ───────────────────────────────────────────
    eval_sets = {
        "train":       (X_train, Y_train),
        "validation":  (X_val,   Y_val),
        "test_random": (X_test,  Y_test),
        "test_family": (X_fam,   Y_fam),
        "test_temporal":(X_tmp,  Y_tmp),
        "test_hard_benign": (X_hbn, Y_hbn),
    }

    all_metrics: dict[str, dict] = {}

    for split_name, (Xs, Ys) in eval_sets.items():
        # If the array is empty (like our disabled advanced splits), skip it
        if len(Xs) == 0:
            logger.info("Skipping %s evaluation (empty split)", split_name)
            # Inject dummy metrics so the generalization report (Step 13) doesn't crash
            all_metrics[split_name] = {"f1_macro": 0.0, "f1_micro": 0.0}
            continue

        probs = lgbm_model.predict_proba(Xs)
        preds = apply_thresholds(probs, thresholds, TARGET_LABELS)
        mb    = compute_metrics(Ys, preds, probs)
        print_metrics(split_name, mb)
        # Assuming mb is a dataclass; if not, use `mb` directly or adjust as needed
        all_metrics[split_name] = asdict(mb) if hasattr(mb, "__dataclass_fields__") else mb

    # ── 12. Add LGBM to baseline comparison ──────────────────────────────
    lgbm_test_probs = lgbm_model.predict_proba(X_test)
    lgbm_test_preds = apply_thresholds(lgbm_test_probs, thresholds, TARGET_LABELS)
    lgbm_f1_macro   = f1_score(Y_test, lgbm_test_preds, average="macro",  zero_division=0)
    lgbm_f1_micro   = f1_score(Y_test, lgbm_test_preds, average="micro",  zero_division=0)
    lgbm_pr_auc     = float(np.mean([
        average_precision_score(Y_test[:, i], lgbm_test_probs[:, i])
        for i in range(Y_test.shape[1]) if Y_test[:, i].sum() > 0
    ]))

    baseline_results["lgbm"] = {
        "f1_macro": float(lgbm_f1_macro),
        "f1_micro": float(lgbm_f1_micro),
        "pr_auc":   float(lgbm_pr_auc),
    }

    # Warn if improvement is < 2%
    lr_f1  = baseline_results["logreg"]["f1_macro"]
    lgb_f1 = baseline_results["lgbm"]["f1_macro"]
    if (lgb_f1 - lr_f1) < 0.02:
        logger.warning(
            "⚠ LightGBM F1 improvement over LogReg is < 2%% (%.4f vs %.4f). "
            "Model may not be learning meaningful non-linear patterns.",
            lgb_f1, lr_f1,
        )

    # ── 13. Generalization analysis ───────────────────────────────────────
    gen_report = generalization_report(
        train_f1    = all_metrics["train"]["f1_macro"],
        val_f1      = all_metrics["validation"]["f1_macro"],
        test_f1     = all_metrics["test_random"]["f1_macro"],
        family_f1   = all_metrics["test_family"]["f1_macro"],
        temporal_f1 = all_metrics["test_temporal"]["f1_macro"],
    )

    # ── 14. SHAP explainability ───────────────────────────────────────────
    generate_shap_plots(lgbm_model, X_test, final_features, output_dir_path)

    # ── 15. Save artifacts ────────────────────────────────────────────────
    classifier = APKClassifier(
        model         = lgbm_model,
        thresholds    = thresholds,
        feature_names = final_features,
        fit_medians   = fit_medians,
    )
    classifier.save(output_dir_path)

    (output_dir_path / "thresholds.json").write_text(json.dumps(thresholds, indent=2))
    (output_dir_path / "metrics.json").write_text(
        json.dumps({
            "evaluation": all_metrics,
            "baselines":  baseline_results,
        }, indent=2)
    )
    (output_dir_path / "cv_results.json").write_text(json.dumps(cv_results, indent=2))
    (output_dir_path / "feature_report.json").write_text(json.dumps(asdict(feat_report), indent=2))
    (output_dir_path / "leakage_report.json").write_text(json.dumps(asdict(leakage_report), indent=2))
    (output_dir_path / "generalization_report.json").write_text(
        json.dumps(gen_report, indent=2)
    )

    logger.info("All artifacts saved to %s/", output_dir_path)
    logger.info("Pipeline complete. ✓")

    # ── 16. Demo inference ────────────────────────────────────────────────
    logger.info("── Inference API demo ──")
    sample_features = dict(zip(final_features, X_test[0].tolist()))
    result = classifier.predict_apk(sample_features)
    logger.info("Sample prediction:\n%s", json.dumps(result, indent=2))


# ─────────────────────────── CLI ─────────────────────────────────────────────

# def parse_args() -> argparse.Namespace:
#     parser = argparse.ArgumentParser(
#         description="Multi-Label Android APK Threat Classifier Training Pipeline"
#     )
#     parser.add_argument(
#         "--data",
#         type=str,
#         default="dataset/full_dataset.csv",
#         help="Path to the dataset CSV file",
#     )
#     parser.add_argument(
#         "--output-dir",
#         type=str,
#         default="artifacts",
#         help="Directory to save artifacts",
#     )
#     return parser.parse_args()


# if __name__ == "__main__":
#     args = parse_args()
#     run_pipeline(data_path=args.data, output_dir=args.output_dir)


# def parse_args() -> argparse.Namespace:
#     parser = argparse.ArgumentParser(
#         description="Multi-Label Android APK Threat Classifier Training Pipeline"
#     )
#     parser.add_argument(
#         "--features",
#         type=str,
#         default="data/feature_store.sqlite",
#         help="Path to the SQLite feature store",
#     )
#     parser.add_argument(
#         "--labels",
#         type=str,
#         default="data/labels.csv",
#         help="Path to the dataset CSV file",
#     )
#     parser.add_argument(
#         "--output-dir",
#         type=str,
#         default="artifacts",
#         help="Directory to save artifacts",
#     )
#     return parser.parse_args()

# if __name__ == "__main__":
#     args = parse_args()
#     run_pipeline(
#         features_path=args.features, 
#         labels_path=args.labels, 
#         output_dir=args.output_dir
#     )

def parse_args():
    # Resolve defaults relative to this file so `python model/train.py` works from
    # backend/ regardless of cwd: data lives in backend/, artifacts in model/.
    here = Path(__file__).resolve().parent          # .../backend/model
    backend_dir = here.parent                        # .../backend
    parser = argparse.ArgumentParser(description="Train the APK classifier.")
    parser.add_argument("--features", type=str,
                        default=str(backend_dir / "feature_store.sqlite"),
                        help="Path to SQLite features")
    parser.add_argument("--labels", type=str,
                        default=str(backend_dir / "labels.csv"),
                        help="Path to labels CSV")
    parser.add_argument("--output_dir", type=str,
                        default=str(here / "artifacts"),
                        help="Output directory")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_pipeline(
        features_path=args.features,
        labels_path=args.labels,
        output_dir=args.output_dir,
    )