"""
build_benign_dataset.py
=======================
Benign half of the training set. Two sources, one ingestion path:

  * F-Droid   — downloads open-source APKs from the official F-Droid repo
                (index-v1.json), the easy/legal bulk benign source.
  * local dir — ingests every *.apk in a folder you point it at (use this for
                your BankAPKS/ commercial bank apps — the high-value benign
                ANCHORS F-Droid can't give you, since it has no commercial
                banking/UPI apps).

Each APK is run through FeatureStorePipeline.analyze_apk(run_dynamic=False) — the
SAME static-only pipeline build_dataset.py uses — and written to the SAME
feature_store.sqlite + labels.csv, labeled benign (label_benign=1, all malicious
labels 0). Mirrors build_dataset.py: auto-resume (skip hashes already in the
store), static-failure rows are discarded (not labeled), safe to stop/restart.

Usage:
    python build_benign_dataset.py --fdroid --limit 500
    python build_benign_dataset.py --apk-dir "../BankAPKS"
    python build_benign_dataset.py --fdroid --limit 1500 --apk-dir "../BankAPKS"

Output (shared with the malware build):
    backend/feature_store.sqlite   — 85-feature rows
    labels.csv                     — apk_hash + label columns
    build_benign_dataset.log
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import logging
import os
import sqlite3
import sys
import tempfile
import time
from typing import Dict, Iterator, List, Optional, Tuple

import requests

# ── Add backend to path (this file lives in backend/) ────────────────────────
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from feature_store_pipeline import FeatureStorePipeline  # noqa: E402

# ── Config ───────────────────────────────────────────────────────────────────
FDROID_REPO = "https://f-droid.org/repo"
FDROID_INDEX = f"{FDROID_REPO}/index-v1.json"
DB_PATH = os.path.join(HERE, "feature_store.sqlite")
LABELS_CSV = os.path.join(HERE, "labels.csv")
RATE_SLEEP = 1.0   # seconds between F-Droid downloads (be polite to the mirror)

# MUST match build_dataset.py LABEL_COLS exactly (same labels.csv schema).
LABEL_COLS = [
    "label_banking_trojan",
    "label_spyware",
    "label_sms_stealer",
    "label_obfuscated_loader",
    "label_benign",
]
# A benign row: benign=1, every malicious label 0 (mutually exclusive anchor).
BENIGN_ROW: Dict[str, int] = {c: (1 if c == "label_benign" else 0) for c in LABEL_COLS}

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(HERE, "build_benign_dataset.log"), encoding="utf-8"),
    ],
)
LOG = logging.getLogger("build_benign")


# ── Label CSV helpers (shared schema with build_dataset.py) ──────────────────

def load_existing_labels() -> Dict[str, Dict[str, int]]:
    labels: Dict[str, Dict[str, int]] = {}
    if not os.path.exists(LABELS_CSV):
        return labels
    with open(LABELS_CSV, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            h = row.get("apk_hash", "")
            if h:
                labels[h] = {c: int(row.get(c, 0)) for c in LABEL_COLS}
    return labels


def save_labels(labels: Dict[str, Dict[str, int]]) -> None:
    with open(LABELS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["apk_hash"] + LABEL_COLS)
        writer.writeheader()
        for h, row in labels.items():
            writer.writerow({"apk_hash": h, **row})


def already_processed(apk_hash: str) -> bool:
    """True if this hash already has a feature row (resume — skip the MobSF run)."""
    if not apk_hash or not os.path.exists(DB_PATH):
        return False
    try:
        with sqlite3.connect(DB_PATH) as conn:
            return conn.execute(
                "SELECT 1 FROM features WHERE apk_hash = ?", (apk_hash,)
            ).fetchone() is not None
    except sqlite3.Error:
        return False


# ── F-Droid source ───────────────────────────────────────────────────────────

def fdroid_candidates(limit: Optional[int]) -> List[Tuple[str, str, str]]:
    """Return [(package, apkName, sha256)] for the latest build of each app.

    Iterates packages in sorted order (deterministic, so resume is stable) and
    takes each app's newest version. F-Droid's index gives the APK's sha256, so
    we can resume-skip BEFORE downloading and verify integrity AFTER.
    """
    LOG.info("Fetching F-Droid index (this is a ~tens-of-MB download)…")
    resp = requests.get(FDROID_INDEX, timeout=120)
    resp.raise_for_status()
    packages = (resp.json() or {}).get("packages") or {}
    out: List[Tuple[str, str, str]] = []
    for pkg in sorted(packages):
        versions = packages.get(pkg) or []
        if not versions:
            continue
        v = versions[0]  # index lists newest first
        apk_name = v.get("apkName")
        sha = (v.get("hash") or "").lower()
        if apk_name and len(sha) == 64 and v.get("hashType", "sha256") == "sha256":
            out.append((pkg, apk_name, sha))
    LOG.info("F-Droid: %d apps with a usable latest APK", len(out))
    return out[:limit] if limit else out


def fdroid_download(apk_name: str, expected_sha: str) -> Optional[bytes]:
    """Download one F-Droid APK and verify its sha256. None on failure/mismatch."""
    try:
        r = requests.get(f"{FDROID_REPO}/{apk_name}", timeout=180)
        if r.status_code != 200:
            LOG.warning("  download %s: HTTP %s", apk_name, r.status_code)
            return None
        data = r.content
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected_sha:
            LOG.warning("  download %s: sha256 mismatch (corrupt) — skipping", apk_name)
            return None
        return data
    except Exception as exc:  # noqa: BLE001 - one bad download must not stop the sweep
        LOG.warning("  download %s failed: %s", apk_name, exc)
        return None


# ── Shared ingestion: one APK file → benign-labeled feature row ──────────────

def ingest_apk_file(pipeline: FeatureStorePipeline, apk_path: str,
                    labels: Dict[str, Dict[str, int]], stats: Dict[str, int]) -> None:
    """Run one local APK through the static pipeline and label it benign.

    Discards the row on static-analysis failure (empty features) exactly like
    build_dataset.py, deleting it so a later run can retry. Never raises.
    """
    try:
        fv = pipeline.analyze_apk(apk_path, run_dynamic=False, cleanup_scan=True)
    except Exception as exc:  # noqa: BLE001
        LOG.warning("  ✗ pipeline failed for %s: %s", os.path.basename(apk_path), exc)
        stats["failed"] += 1
        return
    if int(fv.static_analysis_success) != 1:
        LOG.warning("  ✗ static analysis failed for %s — discarding row", fv.apk_hash[:16])
        with sqlite3.connect(DB_PATH) as c:
            c.execute("DELETE FROM features WHERE apk_hash = ?", (fv.apk_hash,))
        stats["failed"] += 1
        return
    # Benign label is fixed; never merge over an existing (possibly malicious) row.
    if fv.apk_hash not in labels:
        labels[fv.apk_hash] = dict(BENIGN_ROW)
        save_labels(labels)
    LOG.info("  ✓ %s  benign  (%s)", fv.apk_hash[:16], fv.apk_filename)
    stats["success"] += 1


# ── Local-directory source ────────────────────────────────────────────────────

def iter_local_apks(apk_dir: str) -> Iterator[str]:
    for name in sorted(os.listdir(apk_dir)):
        if name.lower().endswith(".apk"):
            yield os.path.join(apk_dir, name)


# ── Main ──────────────────────────────────────────────────────────────────────

def run(use_fdroid: bool, limit: Optional[int], apk_dir: Optional[str]) -> None:
    pipeline = FeatureStorePipeline()
    labels = load_existing_labels()
    stats = {"success": 0, "failed": 0, "skipped": 0}

    LOG.info("Benign build | fdroid=%s limit=%s apk_dir=%s | auto-resume: ON",
             use_fdroid, limit or "all", apk_dir or "—")

    # ── Local directory (e.g. BankAPKS/) ──
    if apk_dir:
        if not os.path.isdir(apk_dir):
            LOG.error("apk-dir not found: %s", apk_dir)
        else:
            LOG.info("\n=== LOCAL DIR: %s ===", apk_dir)
            for path in iter_local_apks(apk_dir):
                fv_hash = _sha256_file(path)
                if already_processed(fv_hash):
                    LOG.info("  SKIP (already in feature store): %s", os.path.basename(path))
                    stats["skipped"] += 1
                    if fv_hash not in labels:        # backfill a missing label
                        labels[fv_hash] = dict(BENIGN_ROW); save_labels(labels)
                    continue
                ingest_apk_file(pipeline, path, labels, stats)

    # ── F-Droid ──
    if use_fdroid:
        candidates = fdroid_candidates(limit)
        with tempfile.TemporaryDirectory(prefix="fdroid_apks_") as tmp:
            for pkg, apk_name, sha in candidates:
                if already_processed(sha):
                    LOG.info("  SKIP (already in feature store): %s", pkg)
                    stats["skipped"] += 1
                    if sha not in labels:
                        labels[sha] = dict(BENIGN_ROW); save_labels(labels)
                    continue
                LOG.info("  Downloading %s …", pkg)
                data = fdroid_download(apk_name, sha)
                if data is None:
                    stats["failed"] += 1
                    time.sleep(RATE_SLEEP)
                    continue
                apk_path = os.path.join(tmp, apk_name)
                with open(apk_path, "wb") as fh:
                    fh.write(data)
                try:
                    ingest_apk_file(pipeline, apk_path, labels, stats)
                finally:
                    if os.path.exists(apk_path):
                        os.unlink(apk_path)
                time.sleep(RATE_SLEEP)

    save_labels(labels)
    benign_total = sum(1 for r in labels.values() if r.get("label_benign", 0) == 1)
    LOG.info("\n=== DONE ===  success=%d  failed=%d  skipped=%d",
             stats["success"], stats["failed"], stats["skipped"])
    LOG.info("benign rows in labels.csv now: %d", benign_total)
    LOG.info("Features: %s", DB_PATH)
    LOG.info("Labels:   %s", LABELS_CSV)


def _sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Build the benign half of the dataset (F-Droid + local APKs)")
    p.add_argument("--fdroid", action="store_true", help="Download benign APKs from F-Droid")
    p.add_argument("--limit", type=int, default=None, help="Max F-Droid apps (default: all)")
    p.add_argument("--apk-dir", default=None, help="Also ingest every *.apk in this folder (e.g. ../BankAPKS)")
    args = p.parse_args()
    if not args.fdroid and not args.apk_dir:
        p.error("nothing to do — pass --fdroid and/or --apk-dir")
    run(use_fdroid=args.fdroid, limit=args.limit, apk_dir=args.apk_dir)
