"""
build_dataset.py
================
Downloads Android malware APKs from MalwareBazaar by family signature,
runs each through FeatureStorePipeline.analyze_apk() which handles all
MobSF interaction internally, and saves type labels to labels.csv.

Always resumes automatically — APKs already in feature_store.sqlite
are skipped every run. Safe to stop and restart at any time.

Usage:
    python build_dataset.py [--limit N] [--dry-run]

Options:
    --limit N    Max APKs per family (default: all available)
    --dry-run    Query MB metadata only, no downloads or MobSF

Output:
    backend/feature_store.sqlite  — 85-feature rows (written by pipeline)
    labels.csv                    — apk_hash + label columns
    build_dataset.log             — full processing log
"""

from __future__ import annotations

import argparse
import csv
import io
import logging
import os
import sqlite3
import sys
import tempfile
import time
from collections import defaultdict
from typing import Dict, List, Optional

import requests

try:
    import pyzipper
except ImportError:
    print("ERROR: pip install pyzipper", file=sys.stderr)
    sys.exit(1)

try:
    from dotenv import load_dotenv
    _ENV = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    load_dotenv(_ENV if os.path.exists(_ENV) else None)
except ImportError:
    pass

# ── Add backend to path ──────────────────────────────────────────────────────
HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(HERE, "backend") if os.path.isdir(
    os.path.join(HERE, "backend")) else HERE
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from feature_store_pipeline import FeatureStorePipeline  # noqa: E402

# ── Config ───────────────────────────────────────────────────────────────────
MB_API     = "https://mb-api.abuse.ch/api/v1/"
AUTH_KEY   = '924260019646a0f560d36cf0be8934aafada72bc05c91fe4'
DB_PATH    = os.path.join(BACKEND_DIR, "feature_store.sqlite")
LABELS_CSV = os.path.join(HERE, "labels.csv")
ZIP_PW     = b"infected"
RATE_SLEEP = 2.5   # seconds between MB API calls (rate limit courtesy)

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(HERE, "build_dataset.log"),
                            encoding="utf-8"),
    ],
)
LOG = logging.getLogger("build_dataset")

# ── Label columns ─────────────────────────────────────────────────────────────
LABEL_COLS = [
    "label_banking_trojan",
    "label_spyware",
    "label_sms_stealer",
    "label_obfuscated_loader",
    "label_benign",
]

# ── Family → type mapping ─────────────────────────────────────────────────────
# Based on documented malware behavior from threat intelligence reports.
# Multi-label: families that genuinely exhibit multiple behaviors get multiple 1s.
FAMILY_TYPE_MAP: Dict[str, List[str]] = {
    # ── Banking trojans (overlay attacks, OTP interception) ──────────────────
    "BankBot":    ["banking_trojan"],
    "SharkBot":   ["banking_trojan"],
    "NGate":      ["banking_trojan"],                 # NFC-relay card theft
    "BrasDex":    ["banking_trojan"],
    "AntiDot":    ["banking_trojan"],
    "Sova":       ["banking_trojan"],
    "BlackRock":  ["banking_trojan"],
    # Banking trojans with RAT / remote-control capability → also spyware
    "ERMAC":      ["banking_trojan", "spyware"],
    "Octo":       ["banking_trojan", "spyware"],
    "GodFather":  ["banking_trojan", "spyware"],
    "Vultur":     ["banking_trojan", "spyware"],      # VNC / screen-streaming RAT
    "TrickMo":    ["banking_trojan", "spyware"],
    "Coper":      ["banking_trojan", "spyware"],
    "Hook":       ["banking_trojan", "spyware"],      # ERMAC fork with full RAT
    "MMRat":      ["banking_trojan", "spyware"],      # banking RAT (SE Asia), not a loader
    "Cerberus":   ["banking_trojan", "spyware"],
    "Anubis":     ["banking_trojan", "spyware"],
    "Hydra":      ["banking_trojan", "spyware"],
    "Alien":      ["banking_trojan", "spyware"],
    # SMS-worm / OTP-stealing banking trojans → also sms_stealer.
    # This is what now populates the sms_stealer class (Joker returned 0 on MB).
    "FluBot":     ["banking_trojan", "sms_stealer"],
    "MoqHao":     ["banking_trojan", "sms_stealer"],
    "Wroba":      ["banking_trojan", "sms_stealer"],
    "TeaBot":     ["banking_trojan", "sms_stealer"],
    # ── Spyware / RAT (surveillance focused, no banking overlay) ─────────────
    "SpyNote":    ["spyware"],
    "AhMyth":     ["spyware"],
    "PromptSpy":  ["spyware"],
    "Hermit":     ["spyware"],
    "Dracarys":   ["spyware"],
    "SpyMax":     ["spyware"],
    "AndroRAT":   ["spyware"],
    "SpyLoan":    ["spyware"],                         # loan-shark surveillanceware
    # "Pegasus":  ["spyware"],   # DISABLED: MB "Pegasus" samples are frequently
    #                            # mislabeled/unrelated — verify before trusting.
    # ── Obfuscated loaders / droppers ────────────────────────────────────────
    "Triada":     ["obfuscated_loader"],
    "Arsink":     ["obfuscated_loader"],
    "SpinOk":     ["obfuscated_loader"],
    # ── DISABLED: returned 0 APKs on MalwareBazaar (wrong/inactive signature).
    #    Confirm a live signature has samples before re-enabling.
    # "Joker":    ["sms_stealer"],
    # "JackSkid": ["obfuscated_loader"],
}


def family_to_labels(signature: Optional[str]) -> Dict[str, int]:
    """Convert a MalwareBazaar family signature to a label dict."""
    row = {col: 0 for col in LABEL_COLS}
    if not signature:
        return row
    for family, types in FAMILY_TYPE_MAP.items():
        if family.lower() == signature.lower():
            for t in types:
                col = f"label_{t}"
                if col in row:
                    row[col] = 1
            return row
    return row  # no match → all zeros


def _merge_labels(existing: Optional[Dict[str, int]],
                  new: Dict[str, int]) -> Dict[str, int]:
    """Union two label dicts. A sample can appear under multiple MalwareBazaar
    family signatures, each contributing its own multi-label types; merging
    (rather than overwriting) keeps every type a sample legitimately exhibits."""
    if not existing:
        return dict(new)
    return {col: (int(existing.get(col, 0)) | int(new.get(col, 0)))
            for col in LABEL_COLS}


# ── MalwareBazaar helpers ────────────────────────────────────────────────────

def mb_query_signature(sig: str, limit: int = 1000) -> List[dict]:
    """Query MalwareBazaar by family signature, return APK samples only."""
    try:
        resp = requests.post(
            MB_API,
            headers={"Auth-Key": AUTH_KEY},
            data={"query": "get_siginfo", "signature": sig, "limit": limit},
            timeout=30,
        )
        resp.raise_for_status()
        body = resp.json()
        if body.get("query_status") not in ("ok",):
            LOG.warning("MB query '%s': status=%s", sig, body.get("query_status"))
            return []
        samples = body.get("data") or []
        return [s for s in samples
                if s.get("file_type", "").lower() == "apk"
                or "apk" in (s.get("tags") or [])]
    except Exception as exc:
        LOG.error("MB query '%s' failed: %s", sig, exc)
        return []


def mb_download(sha256: str) -> Optional[bytes]:
    """Download and decrypt a MalwareBazaar APK. Returns raw bytes or None."""
    try:
        resp = requests.post(
            MB_API,
            headers={"Auth-Key": AUTH_KEY},
            files={
                "query":       (None, "get_file"),
                "sha256_hash": (None, sha256),
            },
            timeout=120,
            stream=True,
        )
        if resp.status_code != 200:
            LOG.warning("Download %s: HTTP %s", sha256[:16], resp.status_code)
            return None
        zip_bytes = resp.content
        if not zip_bytes.startswith(b"PK"):
            LOG.warning("Download %s: response is not a zip", sha256[:16])
            return None
        with pyzipper.AESZipFile(io.BytesIO(zip_bytes)) as zf:
            zf.setpassword(ZIP_PW)
            names = zf.namelist()
            if not names:
                return None
            return zf.read(names[0])
    except Exception as exc:
        LOG.warning("Download %s failed: %s", sha256[:16], exc)
        return None


# ── Label CSV helpers ─────────────────────────────────────────────────────────

def load_existing_labels() -> Dict[str, Dict[str, int]]:
    """Load labels.csv into memory keyed by apk_hash."""
    labels: Dict[str, Dict[str, int]] = {}
    if not os.path.exists(LABELS_CSV):
        return labels
    with open(LABELS_CSV, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            h = row.get("apk_hash", "")
            if h:
                labels[h] = {col: int(row.get(col, 0)) for col in LABEL_COLS}
    return labels


def save_labels(labels: Dict[str, Dict[str, int]]) -> None:
    """Write all labels to labels.csv (full rewrite)."""
    with open(LABELS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["apk_hash"] + LABEL_COLS)
        writer.writeheader()
        for h, row in labels.items():
            writer.writerow({"apk_hash": h, **row})


# ── SQLite resume check ───────────────────────────────────────────────────────

def already_processed(apk_hash: str) -> bool:
    """Check if this apk_hash already exists in feature_store.sqlite."""
    if not os.path.exists(DB_PATH):
        return False
    try:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT 1 FROM features WHERE apk_hash = ?", (apk_hash,)
            ).fetchone()
            return row is not None
    except sqlite3.Error:
        return False


# ── Main pipeline ─────────────────────────────────────────────────────────────

def run(limit: Optional[int], dry_run: bool) -> None:
    if not AUTH_KEY:
        LOG.error("MB_AUTH_KEY not set — add it to .env")
        sys.exit(1)

    # Initialize pipeline once — it holds the DB connection + MobSF client
    pipeline = FeatureStorePipeline()
    labels   = load_existing_labels()
    stats    = defaultdict(lambda: {
        "fetched": 0, "skipped": 0,
        "downloaded": 0, "success": 0, "failed": 0
    })

    LOG.info("Starting dataset build")
    LOG.info("Families: %d  |  limit/family: %s  |  dry_run: %s  |  auto-resume: ON",
             len(FAMILY_TYPE_MAP), limit or "all", dry_run)

    with tempfile.TemporaryDirectory(prefix="mb_apks_") as tmpdir:
        for signature in FAMILY_TYPE_MAP:
            LOG.info("\n=== %s ===", signature.upper())

            samples = mb_query_signature(signature, limit=limit or 1000)
            stats[signature]["fetched"] = len(samples)
            LOG.info("  Found %d APKs", len(samples))

            if not samples:
                time.sleep(RATE_SLEEP)
                continue

            if limit:
                samples = samples[:limit]

            for sample in samples:
                sha256   = sample.get("sha256_hash", "")
                filename = sample.get("file_name", sha256 + ".apk")

                if not sha256:
                    continue

                # Already in feature_store.sqlite — skip the (expensive) MobSF
                # re-run, but STILL reconcile labels. This covers two cases:
                #   * the sample is listed under several families (multi-label) —
                #     union this family's labels into the existing row;
                #   * a previous run crashed after the feature row was written but
                #     before its label was saved — backfill the missing label.
                # MalwareBazaar's sha256_hash equals the pipeline's apk_hash (both
                # hash the same decrypted APK bytes), so it is the correct key.
                if already_processed(sha256):
                    LOG.info("  SKIP (already in feature store): %s", sha256[:16])
                    stats[signature]["skipped"] += 1
                    merged = _merge_labels(labels.get(sha256),
                                           family_to_labels(signature))
                    if merged != labels.get(sha256):
                        labels[sha256] = merged
                        save_labels(labels)
                    continue

                if dry_run:
                    LOG.info("  [dry-run] %s  (%s)", sha256[:16], filename)
                    continue

                # Download from MalwareBazaar
                LOG.info("  Downloading %s ...", sha256[:16])
                apk_bytes = mb_download(sha256)
                if apk_bytes is None:
                    stats[signature]["failed"] += 1
                    time.sleep(RATE_SLEEP)
                    continue
                stats[signature]["downloaded"] += 1

                # Write to temp file
                apk_path = os.path.join(tmpdir, sha256 + ".apk")
                with open(apk_path, "wb") as f:
                    f.write(apk_bytes)

                # Run through pipeline — this handles MobSF upload/scan/report
                # + feature extraction + sqlite storage internally.
                # run_dynamic=False: we only do static analysis for dataset building.
                try:
                    fv = pipeline.analyze_apk(apk_path, run_dynamic=False,
                                              cleanup_scan=True)
                    # Discard rows where MobSF static analysis failed (upload 400,
                    # scan read-timeout, etc.): the feature vector is empty, so a
                    # labeled row would be pure noise. Delete the stored row too so
                    # a later run RETRIES the sample instead of skipping it as
                    # "already processed".
                    if int(fv.static_analysis_success) != 1:
                        LOG.warning("  ✗ static analysis failed for %s — discarding row",
                                    fv.apk_hash[:16])
                        with sqlite3.connect(DB_PATH) as c:
                            c.execute("DELETE FROM features WHERE apk_hash = ?",
                                      (fv.apk_hash,))
                        stats[signature]["failed"] += 1
                        continue
                    # Merge labels keyed by the pipeline's computed apk_hash; a
                    # sample listed under several families (multi-label) unions
                    # its types rather than overwriting an earlier family's row.
                    label_row = _merge_labels(labels.get(fv.apk_hash),
                                              family_to_labels(signature))
                    labels[fv.apk_hash] = label_row
                    save_labels(labels)
                    types = [c.replace("label_", "")
                             for c, v in label_row.items() if v == 1]
                    LOG.info("  ✓ %s  family=%-15s  types=%s",
                             fv.apk_hash[:16], signature, types)
                    stats[signature]["success"] += 1
                except Exception as exc:
                    LOG.warning("  ✗ Pipeline failed for %s: %s", sha256[:16], exc)
                    stats[signature]["failed"] += 1
                finally:
                    # Always delete — don't keep malware on disk
                    if os.path.exists(apk_path):
                        os.unlink(apk_path)

                time.sleep(RATE_SLEEP)

            # Save labels after each family completes
            save_labels(labels)
            time.sleep(RATE_SLEEP)

    # ── Summary ──────────────────────────────────────────────────────────────
    LOG.info("\n\n=== SUMMARY ===")
    total_success = 0
    for sig, s in stats.items():
        LOG.info(
            "  %-15s  fetched=%-4d  downloaded=%-4d  "
            "success=%-4d  failed=%-4d  skipped=%-4d",
            sig, s["fetched"], s["downloaded"],
            s["success"], s["failed"], s["skipped"]
        )
        total_success += s["success"]
    LOG.info("\n  TOTAL PROCESSED: %d APKs", total_success)
    LOG.info("  Features: %s", DB_PATH)
    LOG.info("  Labels:   %s", LABELS_CSV)

    # Label distribution
    LOG.info("\n=== LABEL DISTRIBUTION ===")
    for col in LABEL_COLS:
        count = sum(1 for r in labels.values() if r.get(col, 0) == 1)
        LOG.info("  %-30s  %d", col, count)


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    p = argparse.ArgumentParser(
        description="Build malware dataset from MalwareBazaar"
    )
    p.add_argument("--limit",   type=int, default=None,
                   help="Max APKs per family (default: all)")
    p.add_argument("--dry-run", action="store_true",
                   help="Query only, no downloads or MobSF")
    args = p.parse_args()
    run(limit=args.limit, dry_run=args.dry_run)
