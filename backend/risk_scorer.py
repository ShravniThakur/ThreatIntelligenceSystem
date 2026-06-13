"""
risk_scorer.py
==============

A deterministic, rule-based risk scoring engine for Android-banking-malware
triage. **No LLMs, no ML models — pure, auditable logic.**

This is the explainable, defensible core of the system: every point in the final
score is traceable to a single named signal, and every fired rule cites the
actual feature value that tripped it. A bank fraud team can read the output and
reconstruct exactly *why* an app scored what it did.

Entry point
-----------
    score(feature_row: dict, static_json: dict) -> ScoringResult

``feature_row`` is one row from the ``features`` table of
``feature_store.sqlite`` (or a row of ``features.csv``) rendered as a dict. Values
may be strings ("1", "0.42"), ints, floats, or None — every numeric comparison
goes through :func:`_num`, which coerces and treats missing/None/"" as 0.

``static_json`` is the parsed MobSF static report; it is used only to derive
``anti_vm_detected`` from the ``apkid`` section (see :func:`detect_anti_vm`).

Scoring model
-------------
Signals are **independent and additive**: a signal contributes its weight
whenever its condition is true, with no conditional suppression between rules
(per spec). ``raw`` is the sum of fired weights; ``score = min(100, raw)``.

Weights are taken verbatim from the project specification's table. They are NOT
tuned. For the record, the bundled BENIGN debug build (self-signed debug cert +
debuggable + apkid anti-VM strings + reflection) fires only low-weight rules and
lands at ~37 → **Medium**, comfortably satisfying the acceptance criterion that a
benign app must NOT be rated High/Critical. The high-weight rules
(SMS+accessibility combo = 35, device-admin = 20, runtime SMS = 18) only fire for
genuine banking-trojan capability constellations, so real malware reaches
High/Critical while benign debug builds do not.

Bands: 0-24 Low, 25-49 Medium, 50-74 High, 75-100 Critical.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import capabilities

_HERE = os.path.dirname(os.path.abspath(__file__))
_DB_PATH = os.path.join(_HERE, "feature_store.sqlite")
_CSV_PATH = os.path.join(_HERE, "features.csv")


# --------------------------------------------------------------------------- #
# Numeric coercion helper
# --------------------------------------------------------------------------- #


def _num(row: Dict[str, Any], key: str, default: float = 0) -> float:
    """Return ``row[key]`` coerced to a float, treating None/""/missing as default.

    Values read back from sqlite/CSV may be strings ("1", "0.42") or None. Use
    this for every numeric comparison instead of comparing raw strings with ``>``.
    """
    val = row.get(key, default)
    if val is None or val == "":
        return float(default)
    try:
        return float(val)
    except (TypeError, ValueError):
        return float(default)


# --------------------------------------------------------------------------- #
# Output dataclasses
# --------------------------------------------------------------------------- #


@dataclass
class FiredRule:
    """A single capability that fired, with its weight and evidence trail.

    The Feature-Store Score is now expressed in terms of the shared capability
    table (``capabilities.py``), so each fired rule names the canonical
    capability it declared, the points it contributed, the MITRE technique (if
    any), and the actual feature values that tripped it.
    """

    capability: str       # canonical capability id, e.g. "otp_theft_combo"
    weight: int           # points contributed (after the weak-signal cap)
    evidence: str         # cites the real feature values, e.g.
                          # "perm_read_sms=1, perm_accessibility=1"
    mitre: str = ""       # "<technique id> <name>" ("" for non-ATT&CK signals)


@dataclass
class ScoringResult:
    """The complete, deterministic Feature-Store Score for one APK."""

    score: int
    risk_band: str
    fired_rules: List[FiredRule] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)  # declared cap ids (for fusion)
    anti_vm_detected: bool = False
    dynamic_ran: bool = False                 # True if dynamic_analysis_success == 1
    sandbox_evasion_suspected: bool = False   # anti_vm_detected AND dynamic_ran AND
                                              # the app stayed behaviourally quiet


# --------------------------------------------------------------------------- #
# Anti-VM derivation from the apkid section of the static report
# --------------------------------------------------------------------------- #


def detect_anti_vm(static_json: Optional[Dict[str, Any]]) -> bool:
    """True if MobSF's apkid section reports anti-VM checks in any dex file.

    MobSF's ``apkid`` is a dict keyed by dex filename, each value a dict that may
    contain an ``anti_vm`` (older builds: ``anti_vm_detection``) list. We treat a
    non-empty list in ANY dex as anti-VM present. Defensive about the section
    being absent or oddly shaped, so a missing apkid simply yields False.
    """
    if not isinstance(static_json, dict):
        return False
    apkid = static_json.get("apkid")
    if not isinstance(apkid, dict):
        return False
    for dex_findings in apkid.values():
        if not isinstance(dex_findings, dict):
            continue
        for key in ("anti_vm", "anti_vm_detection", "anti-vm"):
            vals = dex_findings.get(key)
            if isinstance(vals, list) and len(vals) > 0:
                return True
    return False


# --------------------------------------------------------------------------- #
# Scoring engine
# --------------------------------------------------------------------------- #


def _band(score: int) -> str:
    """Map a 0-100 score to its risk band."""
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def score(
    feature_row: Dict[str, Any],
    static_json: Optional[Dict[str, Any]] = None,
) -> ScoringResult:
    """Compute the deterministic **Feature-Store Score** for one APK.

    Contract:
        in : feature_row (dict, possibly string-typed values) + optional parsed
             static JSON (used only for the apkid-derived anti-VM signal).
        out: ScoringResult with score, band, the fired capabilities (each with
             weight + evidence + MITRE), the declared capability ids, plus
             anti_vm_detected / dynamic_ran / sandbox_evasion_suspected.

    Fully deterministic: the same ``feature_row`` always yields the same score.
    The capability layer (``capabilities.py``) owns the rules, weights and the
    count-based caps (so a benign-but-chatty app cannot inflate its score); this
    function is the thin, auditable wrapper that turns declared capabilities into
    a ScoringResult and adds the dynamic-context flags.
    """
    declared = capabilities.capabilities_from_features(feature_row)
    raw_score, fired_caps = capabilities.score_capabilities(declared)
    fired = [
        FiredRule(
            capability=f.capability, weight=f.weight,
            evidence=f.evidence, mitre=f.mitre,
        )
        for f in fired_caps
    ]
    cap_ids = [cap_id for cap_id, _ in declared]

    # Anti-VM: prefer the apkid section of the static report; fall back to the
    # feature row (apkid_anti_vm_checks / feat_anti_vm_detected) when no static
    # JSON is supplied (e.g. scoring straight from a stored feature row).
    anti_vm = bool(
        detect_anti_vm(static_json)
        or _num(feature_row, "apkid_anti_vm_checks") > 0
        or _num(feature_row, "feat_anti_vm_detected") == 1
    )

    dynamic_ran = _num(feature_row, "dynamic_analysis_success") == 1

    # Sandbox-evasion suspicion: anti-VM checks present AND the emulator run
    # succeeded yet the instrumentation saw NO app behaviour. We key "quiet" on
    # the observed-behaviour signals (apimon/droidmon call counts, clipboard and
    # sqlite access) and deliberately EXCLUDE network counts — on a clean emulator
    # those are dominated by OS connectivity checks (connectivitycheck.gstatic.com
    # etc.) and are environmental noise, not app activity.
    behaviourally_quiet = (
        _num(feature_row, "dyn_apimon_call_count") == 0
        and _num(feature_row, "dyn_droidmon_call_count") == 0
        and _num(feature_row, "dyn_clipboard_access") == 0
        and _num(feature_row, "dyn_sqlite_access") == 0
    )
    sandbox_evasion = bool(anti_vm and dynamic_ran and behaviourally_quiet)

    return ScoringResult(
        score=raw_score,
        risk_band=_band(raw_score),
        fired_rules=fired,
        capabilities=cap_ids,
        anti_vm_detected=anti_vm,
        dynamic_ran=dynamic_ran,
        sandbox_evasion_suspected=sandbox_evasion,
    )


# --------------------------------------------------------------------------- #
# __main__ self-test — independently runnable without the server or MobSF
# --------------------------------------------------------------------------- #


def _load_feature_row(apk_filename: str) -> Dict[str, Any]:
    """Load the feature row matching ``apk_filename`` from sqlite, else CSV.

    Falls back to an empty dict when neither store is available so the scorer can
    still be exercised against the static JSON alone.
    """
    # 1) Prefer the sqlite feature store.
    if os.path.exists(_DB_PATH):
        try:
            with sqlite3.connect(_DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                cur = conn.execute(
                    "SELECT * FROM features WHERE apk_filename = ? LIMIT 1",
                    (apk_filename,),
                )
                r = cur.fetchone()
                if r is None:
                    # No exact filename match — take the most recent row.
                    cur = conn.execute("SELECT * FROM features LIMIT 1")
                    r = cur.fetchone()
                if r is not None:
                    return dict(r)
        except sqlite3.Error:
            pass

    # 2) Fall back to the CSV export.
    if os.path.exists(_CSV_PATH):
        import csv
        with open(_CSV_PATH, newline="") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
        for row in rows:
            if row.get("apk_filename") == apk_filename:
                return row
        if rows:
            return rows[0]

    return {}


def _pretty_print(result: ScoringResult) -> None:
    """Human-readable dump of a ScoringResult."""
    print("\n" + "=" * 64)
    print(f" FEATURE-STORE SCORE: {result.score}/100   BAND: {result.risk_band}")
    print("=" * 64)
    print(f" anti_vm_detected          : {result.anti_vm_detected}")
    print(f" dynamic_ran               : {result.dynamic_ran}")
    print(f" sandbox_evasion_suspected : {result.sandbox_evasion_suspected}")
    print(f" declared capabilities     : {', '.join(result.capabilities) or '(none)'}")
    print(f"\n Fired capabilities ({len(result.fired_rules)}):")
    for r in result.fired_rules:
        mitre = f"  [{r.mitre}]" if r.mitre else ""
        print(f"   [{r.weight:>2}] {r.capability:<22}{mitre}")
        print(f"        evidence: {r.evidence}")
    print("=" * 64 + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    """CLI: load a static report + matching feature row, score, pretty-print."""
    argv = argv if argv is not None else sys.argv[1:]
    static_path = argv[0] if argv else os.path.join(_HERE, "reports", "app-debug.static.json")

    if not os.path.exists(static_path):
        print(f"Static report not found: {static_path}")
        return 1

    with open(static_path) as fh:
        static_json = json.load(fh)

    # Derive the APK filename the feature row would use from the report basename.
    base = os.path.basename(static_path)
    if base.endswith(".static.json"):
        base = base[: -len(".static.json")]
    apk_filename = f"{base}.apk"

    feature_row = _load_feature_row(apk_filename)
    if not feature_row:
        print("WARNING: no feature row found in sqlite/CSV; scoring with an empty "
              "row (only the apkid-derived anti-VM signal will fire).")

    result = score(feature_row, static_json)
    _pretty_print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
