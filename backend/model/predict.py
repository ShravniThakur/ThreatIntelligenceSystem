"""
model/predict.py — lightweight serving path for the multi-label APK classifier.
==============================================================================

Loads ``artifacts/model.pkl`` (a dict of {model, thresholds, feature_names,
fit_medians}) and exposes :func:`classify`, which takes the pipeline's
``feature_row`` (the 85-feature ``FeatureVector`` as a dict — the model's
``feature_names`` are exactly those columns) and returns per-label probabilities
+ thresholded predictions for the model's threat categories (label order taken
from the model artifact, not hardcoded here).

Two deliberate choices for a clean integration:
  * **No training deps.** ``model.pkl`` was pickled with the wrapper class living
    in ``__main__`` (train.py run as a script) and references lightgbm/pandas/
    sklearn — but NOT shap/matplotlib. We re-declare a minimal ``_MultiLabelWrapper``
    here and use a custom Unpickler to remap the ``__main__`` reference onto it, so
    serving needs only numpy + pandas + lightgbm + scikit-learn, never shap.
  * **Never raises, fully optional.** If those ML deps or the pickle are missing,
    :func:`classify` returns ``{"available": False, "error": ...}`` and the pipeline
    carries on. The result is flagged ``"prototype": True`` (experimental — surfaced
    with a disclaimer) and is NOT fed into the fusion verdict.
"""

from __future__ import annotations

import os
import pickle
from typing import Any, Dict, Optional

# Fallback label order, used only if the loaded model.pkl carries no label info.
# The authoritative label order at serving time is derived from the model
# artifact itself (the ``thresholds`` keys, which train.py writes in TARGET_LABELS
# order), so the serving path tracks whatever label set the model was trained on
# — 5, 7, or otherwise — without code changes here.
_DEFAULT_LABELS = [
    "banking_trojan",
    "sms_stealer",
    "spyware",
    "obfuscated_loader",
    "benign",
]

_ARTIFACTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "artifacts")
_MODEL_PKL = os.path.join(_ARTIFACTS, "model.pkl")


# --------------------------------------------------------------------------- #
# Minimal re-declaration of the pickled wrapper (methods used at inference).
# Unpickling restores instance state (estimators_) via __dict__, bypassing
# __init__ — so this only needs predict_proba over the per-label estimators.
# --------------------------------------------------------------------------- #


class _MultiLabelWrapper:
    """Per-label LightGBM estimators exposed as one predict_proba matrix."""

    def __init__(self, estimators: Optional[list] = None) -> None:
        self.estimators_ = estimators or []

    def predict_proba(self, X):
        import numpy as np
        return np.column_stack([est.predict_proba(X)[:, 1] for est in self.estimators_])

    def predict(self, X):
        return (self.predict_proba(X) >= 0.5).astype(int)


class _RemapUnpickler(pickle.Unpickler):
    """Resolve the wrapper class (pickled under __main__) onto our local copy."""

    def find_class(self, module: str, name: str):
        if name == "_MultiLabelWrapper":
            return _MultiLabelWrapper
        return super().find_class(module, name)


# --------------------------------------------------------------------------- #
# Loaded model holder
# --------------------------------------------------------------------------- #


class _Model:
    def __init__(self, model, thresholds, feature_names, fit_medians,
                 labels=None) -> None:
        self.model = model
        self.thresholds = thresholds or {}
        self.feature_names = list(feature_names or [])
        self.fit_medians = fit_medians
        # Authoritative label order: prefer an explicit list, else the thresholds
        # keys (train.py inserts them in TARGET_LABELS order), else the fallback.
        self.labels = list(labels) if labels else (
            list(self.thresholds.keys()) or list(_DEFAULT_LABELS))

    def _median(self, feature: str) -> float:
        try:
            v = self.fit_medians.get(feature, 0.0)
        except Exception:  # noqa: BLE001 - fit_medians may be a dict or Series
            v = 0.0
        try:
            return float(v) if v is not None else 0.0
        except (TypeError, ValueError):
            return 0.0

    def predict_apk(self, feature_row: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """feature_row (name->value) -> {label: {probability, prediction}}."""
        import pandas as pd
        vals: Dict[str, float] = {}
        for f in self.feature_names:
            v = feature_row.get(f, None)
            if v is None or v == "":
                v = self._median(f)
            try:
                vals[f] = float(v)
            except (TypeError, ValueError):
                vals[f] = self._median(f)
        # A NAMED single-row frame (columns in the fitted order) so LightGBM
        # matches features by name — correct, and silences the "X does not have
        # valid feature names" warning a bare numpy array triggers.
        X = pd.DataFrame([vals], columns=self.feature_names)
        probs = self.model.predict_proba(X)[0]
        out: Dict[str, Dict[str, Any]] = {}
        for i, lbl in enumerate(self.labels):
            p = float(probs[i])
            thr = float(self.thresholds.get(lbl, 0.5))
            out[lbl] = {"probability": round(p, 4), "prediction": bool(p >= thr)}
        return out


# --------------------------------------------------------------------------- #
# Lazy, cached load (load once; cache failures so we don't retry every request)
# --------------------------------------------------------------------------- #

_LOADED = False
_CLASSIFIER: Optional[_Model] = None
_LOAD_ERROR: Optional[str] = None


def _load() -> _Model:
    if not os.path.isfile(_MODEL_PKL):
        raise FileNotFoundError(f"model.pkl not found at {_MODEL_PKL}")
    with open(_MODEL_PKL, "rb") as fh:
        payload = _RemapUnpickler(fh).load()
    if not isinstance(payload, dict):
        raise ValueError("model.pkl payload is not the expected dict")
    return _Model(
        payload.get("model"),
        payload.get("thresholds"),
        payload.get("feature_names"),
        payload.get("fit_medians"),
        payload.get("labels"),
    )


def _get():
    global _LOADED, _CLASSIFIER, _LOAD_ERROR
    if _LOADED:
        return _CLASSIFIER, _LOAD_ERROR
    _LOADED = True
    try:
        _CLASSIFIER = _load()
    except ImportError as exc:
        _LOAD_ERROR = (f"ML deps not installed ({exc}). "
                       "pip install lightgbm pandas scikit-learn")
    except Exception as exc:  # noqa: BLE001
        _LOAD_ERROR = f"model load failed: {exc}"
    return _CLASSIFIER, _LOAD_ERROR


def _unavailable(error: str) -> Dict[str, Any]:
    return {
        "available": False,
        "prototype": True,
        "labels": {},
        "ranked": [],
        "predicted": [],
        "top_label": "",
        "top_probability": 0.0,
        "error": error,
    }


def classify(feature_row: Dict[str, Any]) -> Dict[str, Any]:
    """Classify one APK's feature_row across the model's threat categories. Never raises.

    Returns a JSON-serialisable dict. ``available`` is False (with ``error``) when
    the prototype model / its deps are absent. ``prototype`` is always True — the
    classifier is experimental and surfaced with a disclaimer, not a real verdict.
    """
    clf, err = _get()
    if clf is None:
        return _unavailable(err or "model unavailable")
    try:
        labels = clf.predict_apk(feature_row or {})
        ranked = sorted(
            ({"label": l, **v} for l, v in labels.items()),
            key=lambda d: d["probability"], reverse=True,
        )
        predicted = [l for l, v in labels.items() if v["prediction"]]
        top = ranked[0] if ranked else {"label": "", "probability": 0.0}
        return {
            "available": True,
            "prototype": True,
            "labels": labels,
            "ranked": ranked,
            "predicted": predicted,
            "top_label": top["label"],
            "top_probability": top["probability"],
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001 - classification must never crash the job
        return _unavailable(f"classification failed: {exc}")


# --------------------------------------------------------------------------- #
# __main__ — quick check against a saved static report (needs the ML deps)
# --------------------------------------------------------------------------- #


def main() -> int:
    import json
    import sys
    import dataclasses
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, here)
    from feature_store_pipeline import extract_from_reports  # noqa: E402

    argv = sys.argv[1:]
    static_path = argv[0] if argv else os.path.join(here, "reports", "BOI Mobile.static.json")
    if not os.path.exists(static_path):
        print(f"Pass a static report path (none at {static_path}).")
        return 0
    with open(static_path, encoding="utf-8") as fh:
        static_json = json.load(fh)
    fv = extract_from_reports(static_json, None)
    res = classify(dataclasses.asdict(fv))
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
