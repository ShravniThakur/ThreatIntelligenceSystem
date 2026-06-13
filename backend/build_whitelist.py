"""
build_whitelist.py
==================

One-time helper that builds ``bank_whitelist.json`` — the identity reference the
Intent Spoofing Detector (``intent_spoof.py``) compares unknown APKs against.

For each genuine bank APK it: runs MobSF static analysis (via the existing
``FeatureStorePipeline`` so it inherits that code's upload/retry/error handling),
extracts the identity fields (package, app name, cert fingerprint + CN, icon
pHash), asks you to confirm the bank's display name, and appends an entry.

Run it ONCE, after MobSF is up and ``MOBSF_API_KEY`` is set in ``.env``:

    cd backend
    python build_whitelist.py                      # auto-detects the bank-APK folder
    python build_whitelist.py --apk-dir ../BankAPKS  # or point it explicitly

It is NOT part of the live request pipeline.

Note: the cert-parsing helpers live in ``intent_spoof.py`` (the old
``campaign_store`` module was removed), so they are imported from there — single
source of truth shared with the detector.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
from typing import Dict, List, Optional

try:
    from dotenv import load_dotenv
    _ENV = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    load_dotenv(_ENV if os.path.exists(_ENV) else None)
except ImportError:
    pass

from feature_store_pipeline import FeatureStorePipeline
from intent_spoof import extract_cert_fingerprint, extract_cert_cn

HERE = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(HERE, "reports")
WHITELIST_PATH = os.path.join(HERE, "bank_whitelist.json")

# Candidate folders to auto-detect the genuine bank APKs (repo layout puts them at
# the repo root as ``BankAPKS``). ``samples/`` is deliberately excluded — that is
# the benign test app, not a bank reference.
_CANDIDATE_DIRS = [
    os.path.join(HERE, "..", "BankAPKS"),
    os.path.join(HERE, "..", "BankAPKs"),
    os.path.join(HERE, "BankAPKS"),
    os.path.join(HERE, "BankAPKs"),
    os.path.join(HERE, "bank_apks"),
]


def _find_apk_dir(explicit: Optional[str]) -> Optional[str]:
    """Return the folder of bank APKs (explicit override, else auto-detect)."""
    if explicit:
        return explicit if _has_apks(explicit) else None
    for cand in _CANDIDATE_DIRS:
        if _has_apks(cand):
            return os.path.abspath(cand)
    return None


def _has_apks(path: str) -> bool:
    return os.path.isdir(path) and any(f.lower().endswith(".apk") for f in os.listdir(path))


def _list_apks(apk_dir: str) -> List[str]:
    return sorted(
        os.path.join(apk_dir, f) for f in os.listdir(apk_dir)
        if f.lower().endswith(".apk")
    )


def _load_existing() -> List[dict]:
    """Load any existing whitelist so re-runs append rather than clobber."""
    if not os.path.exists(WHITELIST_PATH):
        return []
    try:
        with open(WHITELIST_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        return [e for e in data if isinstance(e, dict)] if isinstance(data, list) else []
    except (ValueError, OSError):
        return []


def _save(whitelist: List[dict]) -> None:
    with open(WHITELIST_PATH, "w", encoding="utf-8") as fh:
        json.dump(whitelist, fh, indent=2, ensure_ascii=False)


def _read_static_json(base: str) -> Dict:
    path = os.path.join(REPORTS_DIR, f"{base}.static.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (ValueError, OSError):
        return {}


def _prompt_bank_name(app_name: str, package_name: str) -> str:
    """Ask the operator to confirm/label the bank name; default to app_name."""
    try:
        ans = input(f"Bank name for {app_name} ({package_name}): "
                    f"[press Enter to use '{app_name}'] ").strip()
    except EOFError:
        ans = ""
    return ans or app_name


def process_apk(pipeline: FeatureStorePipeline, apk_path: str) -> Optional[dict]:
    """Analyse one bank APK and return its whitelist entry, or None on failure."""
    base = os.path.splitext(os.path.basename(apk_path))[0]
    print(f"\n--- {os.path.basename(apk_path)} ---")
    try:
        fv = pipeline.analyze_apk(apk_path, run_dynamic=False, report_dir=REPORTS_DIR)
    except Exception as exc:  # noqa: BLE001
        print(f"  ✗ MobSF analysis failed: {exc} — skipping.")
        return None

    if not getattr(fv, "static_analysis_success", 0):
        print("  ✗ Static analysis did not succeed (MobSF unreachable or scan error)"
              " — skipping.")
        return None

    static_json = _read_static_json(base)
    if not static_json:
        print(f"  ✗ Could not load reports/{base}.static.json — skipping.")
        return None

    # App name (for display in the alert): MobSF's Play Store title (genuine bank
    # apps are on Play) -> MobSF app_name -> filename. The detector matches on
    # package + cert fingerprint, so the name is purely a human-readable label.
    ps = static_json.get("playstore_details") or {}
    ps_title = str(ps.get("title", "") or "").strip() if isinstance(ps, dict) else ""

    package_name = str(static_json.get("package_name", "") or "")
    app_name = ps_title or str(static_json.get("app_name", "") or base)
    cert = static_json.get("certificate_analysis") or {}
    cert_info = cert.get("certificate_info", "") if isinstance(cert, dict) else ""
    cert_fingerprint = extract_cert_fingerprint(cert_info)
    cert_cn = extract_cert_cn(cert_info)
    if not cert_fingerprint:
        print("  ⚠ no cert SHA-256 parsed — this entry can't drive the cert check.")

    print(f"  app_name     : {app_name}")
    print(f"  package_name : {package_name}")
    print(f"  cert sha256  : {cert_fingerprint or '(none parsed)'}")
    print(f"  cert CN      : {cert_cn or '(none)'}")

    bank = _prompt_bank_name(app_name, package_name)

    return {
        "bank": bank,
        "app_name": app_name,
        "package_name": package_name,
        "cert_fingerprint": cert_fingerprint,
        "cert_cn": cert_cn,
        "apk_file": os.path.basename(apk_path),
        "added_at": datetime.datetime.now().isoformat(timespec="seconds"),
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Build bank_whitelist.json from genuine bank APKs.")
    parser.add_argument("--apk-dir", default=None,
                        help="Folder containing the genuine bank .apk files "
                             "(auto-detected, e.g. ../BankAPKS, if omitted).")
    args = parser.parse_args(argv)

    apk_dir = _find_apk_dir(args.apk_dir)
    if not apk_dir:
        print("ERROR: no bank-APK folder found. Pass --apk-dir <path> to a folder "
              "containing .apk files (looked in: "
              + ", ".join(os.path.relpath(c, HERE) for c in _CANDIDATE_DIRS) + ").")
        return 1

    apks = _list_apks(apk_dir)
    print(f"Bank-APK folder: {apk_dir}")
    print(f"Found {len(apks)} APK(s):")
    for p in apks:
        print(f"  - {os.path.basename(p)}")
    if not apks:
        print("Nothing to do.")
        return 1

    os.makedirs(REPORTS_DIR, exist_ok=True)
    pipeline = FeatureStorePipeline()

    # Re-runs append to / refresh the existing whitelist, keyed by package_name.
    existing = _load_existing()
    by_pkg = {e.get("package_name", ""): e for e in existing}

    processed = 0
    for apk_path in apks:
        entry = process_apk(pipeline, apk_path)
        if entry is None:
            continue
        by_pkg[entry["package_name"]] = entry   # upsert by package
        processed += 1
        _save(list(by_pkg.values()))            # persist after each success

    _save(list(by_pkg.values()))
    print(f"\nProcessed {processed}/{len(apks)} APKs successfully. "
          f"Whitelist saved to {os.path.relpath(WHITELIST_PATH, HERE)}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
