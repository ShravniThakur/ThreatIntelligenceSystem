"""
dna_fingerprint.py — APK structural DNA fingerprinting.
======================================================

Asks "what does this app look like *structurally*?" and compares that shape
against a reference database of known malware families (seeded from MalwareBazaar
by ``seed_malwarebazaar.py``). Two complementary similarity layers:

  1. **Feature-vector cosine** — over the STATIC subset of the 85-feature
     ``FeatureVector`` (permission constellation, API-shape counts, string-entropy
     stats, APKiD/compiler, manifest, certificate, static network). Captures the
     structural "constellation" that survives renaming/obfuscation. Reported as a
     percentage: "87% similar to FluBot".

  2. **DEX TLSH** — a locality-sensitive fuzzy hash over the concatenated
     ``classes*.dex`` bytes. Captures code/byte structure and survives re-signing
     and resource swaps, so it catches *repackaged clones* (the fake-YONO case)
     that the feature vector alone can't see. Reported as a TLSH distance + a
     "clone" flag.

Why a static subset, computed from the real extractor
-----------------------------------------------------
Both the seeder and the live pipeline build the vector from the SAME
``FeatureVector`` extraction (``feature_store_pipeline.extract_from_reports``), so
seed and query vectors are strictly comparable — no train/serve skew. We take only
STATIC columns because the seeder runs static-only while the live pipeline also
runs dynamic; any ``dyn_*`` (or dynamic-derived) feature would otherwise disagree
between the two. The subset is derived programmatically from
``FeatureVector.column_names()`` so it stays correct as the feature set evolves.

Storage / similarity
---------------------
Fingerprints are stored as a numpy BLOB in the existing ``feature_store.sqlite``
(``dna_fingerprints`` table). Comparison is brute-force EXACT cosine in numpy — at
this scale (hundreds–low thousands of vectors) that is sub-10ms and exact; a vector
DB (FAISS/Chroma) is ANN approximation that only pays off past ~100k vectors. The
compare path is isolated in :func:`compare` so an ANN index can be swapped in later
without touching callers.

Entry points
------------
    build_vector(feature_row) -> np.ndarray            # the static fingerprint vector
    dex_tlsh(apk_path)         -> Optional[str]         # DEX-bytes TLSH ("" layer optional)
    compare(vector, tlsh, conn) -> DNAResult            # nearest family + clone check
    analyze_dna(feature_row, apk_path, ...) -> DNAResult  # orchestrator for main.py (never raises)
    store_fingerprint(...)                              # persist a fingerprint (seed or analyzed)
"""

from __future__ import annotations

import io
import math
import os
import re
import sqlite3
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import numpy as np
    _HAVE_NUMPY = True
except ImportError:                       # pragma: no cover
    np = None
    _HAVE_NUMPY = False

from feature_store_pipeline import FeatureVector

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "feature_store.sqlite")

# Bump whenever STATIC_FINGERPRINT_COLS or the normalisation below changes, so
# vectors built by different code never get compared. compare() filters on it.
VECTOR_VERSION = 1


# --------------------------------------------------------------------------- #
# The static fingerprint column set — derived from FeatureVector
# --------------------------------------------------------------------------- #

# Identity / bookkeeping — not features.
_EXCLUDE_BOOKKEEPING = {
    "apk_hash", "apk_filename", "analysis_timestamp", "confidence_level",
    "static_analysis_success", "dynamic_analysis_success",
}
# Dynamic-DERIVED static-looking feature: feat_hidden_network = (dyn_static_domain_delta>5),
# so it depends on the dynamic run and must be excluded to stay seed/live-consistent.
_EXCLUDE_DYNAMIC_DERIVED = {"feat_hidden_network"}


def _static_fingerprint_cols() -> List[str]:
    """All STATIC FeatureVector columns (drop dyn_*, dynamic-derived, bookkeeping)."""
    cols = []
    for c in FeatureVector.column_names():
        if c.startswith("dyn_"):
            continue
        if c in _EXCLUDE_BOOKKEEPING or c in _EXCLUDE_DYNAMIC_DERIVED:
            continue
        cols.append(c)
    return cols


STATIC_FINGERPRINT_COLS: List[str] = _static_fingerprint_cols()


# --------------------------------------------------------------------------- #
# Per-column normalisation (so cosine treats heterogeneous features fairly)
# --------------------------------------------------------------------------- #

_BINARY_PREFIXES = ("perm_", "feat_")
_BINARY_EXTRA = {
    "manifest_debuggable", "manifest_allow_backup", "manifest_unprotected_exported",
    "cert_debug_signed", "code_ecb_mode", "code_logging_sensitive", "binary_all_stripped",
}
_LOG_CAP = math.log1p(50.0)               # count columns are log1p-scaled, capped ~50


def _num(v: Any) -> float:
    if v is None or v == "":
        return 0.0
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _is_binary(col: str) -> bool:
    return col.startswith(_BINARY_PREFIXES) or col in _BINARY_EXTRA


def _normalize(col: str, raw: Any) -> float:
    """Map a feature value into [0,1] by column kind (ratio/entropy/binary/count)."""
    v = _num(raw)
    name = col.lower()
    if "ratio" in name:
        return max(0.0, min(v, 1.0))
    if "entropy" in name:                 # Shannon entropy of bytes, max ~8
        return max(0.0, min(v / 8.0, 1.0))
    if _is_binary(col):
        return 1.0 if v != 0 else 0.0
    # default: a count-like column -> log-scale
    return min(math.log1p(max(v, 0.0)) / _LOG_CAP, 1.0)


def build_vector(feature_row: Dict[str, Any]):
    """Build the normalised static fingerprint vector (float32) from a feature row.

    ``feature_row`` is ``dataclasses.asdict(FeatureVector)`` (or a sqlite row dict).
    Requires numpy. Deterministic: same row -> same vector.
    """
    if not _HAVE_NUMPY:
        raise RuntimeError("numpy is required to build DNA fingerprint vectors")
    vals = [_normalize(c, feature_row.get(c)) for c in STATIC_FINGERPRINT_COLS]
    return np.asarray(vals, dtype=np.float32)


def _serialize(arr) -> bytes:
    buf = io.BytesIO()
    np.save(buf, arr)
    return buf.getvalue()


def _deserialize(blob: bytes):
    return np.load(io.BytesIO(blob))


def _cosine(a, b) -> float:
    na, nb = float(np.linalg.norm(a)), float(np.linalg.norm(b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


# --------------------------------------------------------------------------- #
# DEX-bytes TLSH (the second, code-structure layer) — optional dependency
# --------------------------------------------------------------------------- #

_TLSH_CLONE_DISTANCE = 50   # tlsh.diff: 0=identical; <=~50 ≈ repackaged clone
_TLSH_MIN_BYTES = 256       # tlsh needs at least this many bytes


def dex_tlsh(apk_path: Optional[str]) -> Optional[str]:
    """TLSH over the concatenated classes*.dex bytes. None if unavailable.

    Concatenates dex entries in sorted name order (classes.dex, classes2.dex, …)
    for determinism. Returns None if py-tlsh isn't installed, there's no dex, or
    the payload is too small for TLSH. Never raises.
    """
    if not apk_path or not os.path.isfile(apk_path):
        return None
    try:
        import tlsh
    except ImportError:
        return None
    try:
        buf = bytearray()
        with zipfile.ZipFile(apk_path) as z:
            for name in sorted(z.namelist()):
                if re.fullmatch(r"classes\d*\.dex", name):
                    buf += z.read(name)
        if len(buf) < _TLSH_MIN_BYTES:
            return None
        h = tlsh.hash(bytes(buf))
        return h if h and h != "TNULL" else None
    except Exception:  # noqa: BLE001 - tlsh is best-effort, never fatal
        return None


def _tlsh_diff(h1: Optional[str], h2: Optional[str]) -> Optional[int]:
    if not h1 or not h2:
        return None
    try:
        import tlsh
        return int(tlsh.diff(h1, h2))
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- #
# Result dataclasses
# --------------------------------------------------------------------------- #


@dataclass
class FamilyScore:
    family: str
    similarity: float            # 0.0-1.0 cosine to the nearest sample of this family
    nearest_hash: str = ""
    sample_count: int = 0


@dataclass
class DNAResult:
    """Structural-DNA assessment for one APK."""

    fingerprinted: bool = False
    top_family: str = ""
    top_similarity: float = 0.0          # 0.0-1.0 (UI shows as %)
    band: str = "none"                   # strong | moderate | weak | none
    per_family: List[FamilyScore] = field(default_factory=list)
    # DEX-TLSH clone layer
    tlsh_nearest_family: str = ""
    tlsh_distance: Optional[int] = None  # lower = more similar
    tlsh_clone: bool = False
    # bookkeeping
    reference_size: int = 0              # number of labelled seeds compared against
    vector_version: int = VECTOR_VERSION
    error: Optional[str] = None


def _band(sim: float) -> str:
    if sim >= 0.85:
        return "strong"
    if sim >= 0.70:
        return "moderate"
    if sim >= 0.55:
        return "weak"
    return "none"


# --------------------------------------------------------------------------- #
# SQLite schema + storage (shared by the seeder and the live pipeline)
# --------------------------------------------------------------------------- #

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS dna_fingerprints (
    apk_hash        TEXT PRIMARY KEY,
    apk_filename    TEXT,
    family_label    TEXT NOT NULL DEFAULT '',   -- '' for analysed (unknown) APKs
    label_source    TEXT NOT NULL DEFAULT 'analyzed',  -- malwarebazaar | analyzed
    mb_tlsh         TEXT,                        -- MalwareBazaar's file TLSH (metadata only)
    dex_tlsh        TEXT,                        -- OUR DEX-bytes TLSH (used for compare)
    feature_vector  BLOB,
    vector_version  INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL
);
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the dna_fingerprints table (and add dex_tlsh on older DBs)."""
    conn.execute(_CREATE_TABLE)
    # Forward-compat: a pre-existing table (from an early seeder) may lack dex_tlsh.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(dna_fingerprints)")}
    if "dex_tlsh" not in cols:
        conn.execute("ALTER TABLE dna_fingerprints ADD COLUMN dex_tlsh TEXT")
    conn.commit()


def store_fingerprint(conn: sqlite3.Connection, apk_hash: str, apk_filename: str,
                      vector, dex_hash: Optional[str], *, family: str = "",
                      source: str = "analyzed", mb_tlsh: Optional[str] = None) -> None:
    """Upsert one fingerprint. ``family`` is '' for analysed (unknown) APKs."""
    conn.execute(
        """
        INSERT OR REPLACE INTO dna_fingerprints
            (apk_hash, apk_filename, family_label, label_source, mb_tlsh, dex_tlsh,
             feature_vector, vector_version, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (apk_hash, apk_filename, family or "", source, mb_tlsh, dex_hash,
         _serialize(vector) if vector is not None else None,
         VECTOR_VERSION, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def _load_labelled(conn: sqlite3.Connection):
    """Yield (family, apk_hash, vector, dex_tlsh) for labelled malware seeds only."""
    cur = conn.execute(
        """
        SELECT family_label, apk_hash, feature_vector, dex_tlsh
        FROM dna_fingerprints
        WHERE vector_version = ? AND family_label != '' AND feature_vector IS NOT NULL
        """,
        (VECTOR_VERSION,),
    )
    for family, apk_hash, blob, dtlsh in cur:
        try:
            vec = _deserialize(blob)
        except Exception:  # noqa: BLE001 - skip a corrupt row, never crash compare
            continue
        yield family, apk_hash, vec, dtlsh


# --------------------------------------------------------------------------- #
# Comparison (brute-force exact cosine + TLSH nearest) — isolate to swap in ANN
# --------------------------------------------------------------------------- #


def compare(vector, dex_hash: Optional[str], conn: sqlite3.Connection) -> DNAResult:
    """Compare a query fingerprint against the labelled malware seeds. Never raises."""
    if not _HAVE_NUMPY:
        return DNAResult(error="numpy not installed")
    try:
        best_per_family: Dict[str, FamilyScore] = {}
        counts: Dict[str, int] = {}
        tlsh_best_dist: Optional[int] = None
        tlsh_best_family = ""
        n_ref = 0

        for family, apk_hash, vec, dtlsh in _load_labelled(conn):
            n_ref += 1
            counts[family] = counts.get(family, 0) + 1
            sim = _cosine(vector, vec)
            fs = best_per_family.get(family)
            if fs is None or sim > fs.similarity:
                best_per_family[family] = FamilyScore(
                    family=family, similarity=round(sim, 4), nearest_hash=apk_hash)
            d = _tlsh_diff(dex_hash, dtlsh)
            if d is not None and (tlsh_best_dist is None or d < tlsh_best_dist):
                tlsh_best_dist, tlsh_best_family = d, family

        if n_ref == 0:
            return DNAResult(fingerprinted=True, reference_size=0,
                             error="reference DB empty — run seed_malwarebazaar.py")

        for fam, fs in best_per_family.items():
            fs.sample_count = counts.get(fam, 0)
        ranked = sorted(best_per_family.values(), key=lambda f: f.similarity, reverse=True)
        top = ranked[0]

        return DNAResult(
            fingerprinted=True,
            top_family=top.family,
            top_similarity=top.similarity,
            band=_band(top.similarity),
            per_family=ranked,
            tlsh_nearest_family=tlsh_best_family,
            tlsh_distance=tlsh_best_dist,
            tlsh_clone=(tlsh_best_dist is not None and tlsh_best_dist <= _TLSH_CLONE_DISTANCE),
            reference_size=n_ref,
        )
    except Exception as exc:  # noqa: BLE001
        return DNAResult(error=f"DNA compare failed: {exc}")


# --------------------------------------------------------------------------- #
# Orchestrator for the live pipeline (never raises)
# --------------------------------------------------------------------------- #


def analyze_dna(feature_row: Dict[str, Any], apk_path: Optional[str],
                apk_hash: str, apk_filename: str = "",
                db_path: str = DB_PATH) -> DNAResult:
    """Fingerprint one analysed APK, compare to seeds, and STORE its fingerprint.

    Storing the analysed fingerprint (family '', source 'analyzed') is what feeds
    the future Campaign Store clustering. Degrades gracefully: numpy missing or any
    error -> a DNAResult with ``error`` set, never an exception into run_job.
    """
    if not _HAVE_NUMPY:
        return DNAResult(error="numpy not installed — DNA fingerprinting skipped")
    conn = None
    try:
        vector = build_vector(feature_row)
        dhash = dex_tlsh(apk_path)
        conn = sqlite3.connect(db_path)
        ensure_schema(conn)
        result = compare(vector, dhash, conn)
        # Persist the analysed fingerprint for campaign clustering (even if the
        # reference DB is empty — the data still accumulates).
        store_fingerprint(conn, apk_hash, apk_filename, vector, dhash,
                          family="", source="analyzed")
        return result
    except Exception as exc:  # noqa: BLE001 - DNA must never crash the job
        return DNAResult(error=f"DNA fingerprinting failed: {exc}")
    finally:
        if conn is not None:
            conn.close()


# --------------------------------------------------------------------------- #
# __main__ — quick, MobSF-free sanity over a saved static report
# --------------------------------------------------------------------------- #


def main(argv: Optional[List[str]] = None) -> int:
    import json
    import sys
    import dataclasses
    from feature_store_pipeline import extract_from_reports

    argv = argv if argv is not None else sys.argv[1:]
    here = os.path.dirname(os.path.abspath(__file__))
    static_path = argv[0] if argv else os.path.join(here, "reports", "BOI Mobile.static.json")
    print(f"Static fingerprint columns ({len(STATIC_FINGERPRINT_COLS)}):")
    print("  " + ", ".join(STATIC_FINGERPRINT_COLS))
    if not os.path.exists(static_path):
        print(f"\n(no static report at {static_path} — pass one to build a vector)")
        return 0
    with open(static_path, encoding="utf-8") as fh:
        static_json = json.load(fh)
    fv = extract_from_reports(static_json, None)
    if not _HAVE_NUMPY:
        print("\nnumpy not installed — install it to build vectors.")
        return 0
    vec = build_vector(dataclasses.asdict(fv))
    print(f"\nVector dim={vec.shape[0]}  L2-norm={float(np.linalg.norm(vec)):.4f}  "
          f"nonzero={int((vec != 0).sum())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
