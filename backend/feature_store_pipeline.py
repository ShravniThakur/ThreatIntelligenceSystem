"""
feature_store_pipeline.py
=========================

A feature-store pipeline for Android APK malware analysis, purpose-built for
*banking* malware detection (overlay/accessibility trojans, SMS stealers,
remote-access droppers, etc.).

The pipeline:

    1. Takes an APK file as input.
    2. Runs MobSF **static** analysis via the REST API and fetches the JSON report.
    3. Runs MobSF **dynamic** analysis via the REST API on a locally connected
       Android emulator (Pixel 6 / API 33 / arm64, reached over ADB by MobSF).
       Dynamic analysis is best-effort: if it fails or times out we log it and
       continue with static-only features rather than blocking the pipeline.
    4. Normalizes both reports into a consistent internal schema, tolerating
       MobSF version differences (permissions may be a dict or a list, field
       names drift between releases, etc.).
    5. Extracts a flat feature vector across permission / API / network /
       certificate / manifest / obfuscation / dynamic feature groups.
    6. Persists each APK's feature vector into a local SQLite feature store keyed
       by the APK SHA256.
    7. Exports the feature store to CSV on demand.

MobSF REST API endpoints used (all relative to MOBSF_URL, default
http://localhost:8000). Every request sends the API key in the `Authorization`
header (read from the MOBSF_API_KEY environment variable):

    Static analysis
    ---------------
    POST /api/v1/upload                 Upload an APK. Returns {hash, scan_type, file_name}.
    POST /api/v1/scan                   Trigger static scan for an uploaded hash.
    POST /api/v1/report_json            Fetch the full static JSON report for a hash.

    Dynamic analysis (Android only)
    -------------------------------
    POST /api/v1/dynamic/start_analysis Boot the instrumented app on the emulator.
    POST /api/v1/dynamic/stop_analysis  Stop instrumentation and finalize the run.
    POST /api/v1/dynamic/report_json    Fetch the dynamic JSON report for a hash.

    (Optional helpers MobSF also exposes, not strictly required here:
     GET  /api/v1/android/apks            list installed test apps
     POST /api/v1/dynamic/get_env         dynamic analyzer environment status)

Usage
-----
    export MOBSF_API_KEY="<your key from the MobSF web UI 'API' page>"
    # optional: export MOBSF_URL="http://localhost:8000"

    python feature_store_pipeline.py /path/to/sample.apk
    python feature_store_pipeline.py /path/to/sample.apk --static-only
    python feature_store_pipeline.py --export features.csv      # export only

The module is also importable:

    from feature_store_pipeline import FeatureStorePipeline
    pipe = FeatureStorePipeline()
    vector = pipe.analyze_apk("/path/to/sample.apk")
    pipe.export_csv("features.csv")
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import os
import re
import sqlite3
import time
from collections import Counter
from dataclasses import dataclass, fields, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

import requests

# Load configuration from a local .env file (MOBSF_API_KEY, MOBSF_URL, emulator
# settings, etc.) into the process environment before we read any os.environ
# values below. python-dotenv is optional — if it isn't installed we silently
# fall back to whatever is already exported in the shell.
try:
    from dotenv import load_dotenv

    # Look for a .env next to this script regardless of the current working dir.
    _ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    load_dotenv(_ENV_PATH if os.path.exists(_ENV_PATH) else None)
except ImportError:  # pragma: no cover - dotenv is a convenience, not required
    pass


# --------------------------------------------------------------------------- #
# Configuration & logging
# --------------------------------------------------------------------------- #

LOG = logging.getLogger("feature_store")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)

# Default MobSF server location; overridable via the MOBSF_URL env var.
MOBSF_URL = os.environ.get("MOBSF_URL", "http://localhost:8000").rstrip("/")

# SQLite feature store location (next to this file by default).
DB_PATH = os.environ.get(
    "FEATURE_STORE_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "feature_store.sqlite"),
)

# How long to let a dynamic-analysis run instrument the app before stopping it.
# Banking trojans frequently delay malicious behaviour, so we give it a real
# window. Tunable via env var for CI vs. interactive use.
DYNAMIC_RUN_SECONDS = int(os.environ.get("MOBSF_DYNAMIC_RUN_SECONDS", "90"))

# Network-level request timeout for individual MobSF API calls (seconds).
HTTP_TIMEOUT = int(os.environ.get("MOBSF_HTTP_TIMEOUT", "300"))


# --------------------------------------------------------------------------- #
# Feature-set domain knowledge
# --------------------------------------------------------------------------- #
#
# These constants encode *why* each signal matters. Keeping them in one place
# makes the heuristics auditable and easy to tune as the threat landscape shifts.

# High-risk permissions individually tracked as their own boolean/count columns.
# Each is a classic building block of a banking-trojan kill chain.
HIGH_RISK_PERMISSIONS = {
    # SMS = OTP / 2FA interception, the single strongest banking-malware signal.
    "android.permission.READ_SMS": "read_sms",
    "android.permission.SEND_SMS": "send_sms",
    "android.permission.RECEIVE_SMS": "receive_sms",
    # Camera abuse: capture documents/QR/PINs.
    "android.permission.CAMERA": "camera",
    # Accessibility: lets malware read the screen and auto-click — the engine
    # behind overlay/clickjacking banking trojans.
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "accessibility_service",
    # Draw-over-other-apps: fake login overlays on top of real banking apps.
    "android.permission.SYSTEM_ALERT_WINDOW": "overlay",
    # Device admin: resists uninstall, locks the device for ransom.
    "android.permission.BIND_DEVICE_ADMIN": "bind_device_admin",
    # Contacts: harvest victims for smishing propagation.
    "android.permission.READ_CONTACTS": "read_contacts",
}

# The Android "dangerous" protection-level permission groups. We count how many
# distinct dangerous permissions an app requests; over-privileged apps are a
# strong prior for malware.
DANGEROUS_PERMISSION_HINTS = {
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "RECEIVE_MMS", "READ_CALL_LOG",
    "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS", "CALL_PHONE", "READ_PHONE_STATE",
    "READ_PHONE_NUMBERS", "CAMERA", "RECORD_AUDIO", "READ_CONTACTS",
    "WRITE_CONTACTS", "GET_ACCOUNTS", "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "BODY_SENSORS",
    "READ_CALENDAR", "WRITE_CALENDAR", "ACTIVITY_RECOGNITION",
}

# Suspicious top-level domains favoured by malware C2 because they are cheap,
# disposable, and weakly policed.
SUSPICIOUS_TLDS = (".ru", ".cn", ".tk", ".xyz")

# Benign OS / CDN infrastructure that a clean Android emulator contacts on its
# own (connectivity checks, OS update/telemetry, Play/Firebase). Dynamic traffic
# to these is environmental noise, not app-initiated C2 — the same finding the
# old scorer made about connectivitycheck.gstatic.com. We subtract domains
# matching these suffixes from the dynamic-vs-static domain delta so a benign app
# running on the emulator does not look like it loaded "hidden" C2 domains. This
# is the anti-false-positive sibling of the geo fix.
_BENIGN_INFRA_SUFFIXES = (
    "google.com", "googleapis.com", "googlesource.com", "gstatic.com",
    "google-analytics.com", "googletagmanager.com", "goo.gl", "android.com",
    "googleusercontent.com", "crashlytics.com", "firebaseio.com",
    "firebase.com", "firebaseapp.com", "ggpht.com", "doubleclick.net",
)


def _is_benign_infra(domain: str) -> bool:
    """True if ``domain`` is a known benign OS/CDN endpoint (see above)."""
    d = (domain or "").lower().strip(".")
    return any(d == suf or d.endswith("." + suf) for suf in _BENIGN_INFRA_SUFFIXES)

# Regexes / substrings used to detect risky API usage in the static report's
# code-analysis section. We match defensively against several MobSF field shapes.
API_SIGNATURES = {
    # Reflection lets malware hide method calls from static analysis.
    "uses_reflection": ["java.lang.reflect", "getmethod", "getdeclaredmethod", "reflection"],
    # Dynamic class loading = downloading & running a second-stage payload.
    "uses_dexclassloader": ["dexclassloader", "pathclassloader", "loadclass", "load_dex"],
    # Native code (.so / JNI) hides logic from Java-level scanners.
    "uses_native_code": ["loadlibrary", "system.loadlibrary", "jni", "native"],
    # Crypto often used to encrypt C2 traffic or hide strings.
    "uses_crypto": ["javax.crypto", "cipher", "aes", "des", "messagedigest", "crypto"],
    # Runtime.exec / shell = privilege escalation, persistence, su attempts.
    "uses_runtime_exec": ["runtime.getruntime", "runtime.exec", "processbuilder", "exec("],
}

# A regex for IPv4 literals hardcoded in code/resources (C2 addresses).
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)

# A loose domain matcher used as a fallback when MobSF does not pre-extract URLs.
DOMAIN_RE = re.compile(r"https?://([a-zA-Z0-9.\-]+)")


# --------------------------------------------------------------------------- #
# Feature vector schema
# --------------------------------------------------------------------------- #


# Schema version. Bump whenever the FeatureVector field set changes so the
# feature store can detect the old layout and migrate (see FeatureStore._ensure_schema).
# v1 = the original 38-feature schema; v2 = the 85-feature set (this build).
SCHEMA_VERSION = 2


@dataclass
class FeatureVector:
    """Flat, ML-ready feature vector for a single APK (the 85-feature set).

    Every field maps 1:1 to a column in the SQLite feature store. Field order
    here defines column order in the CSV export, and the SQLite column type is
    derived from each field's type annotation (float -> REAL, str -> TEXT, else
    INTEGER) by :meth:`FeatureStore._column_sql_type`.

    Missing-vs-zero discipline (decided once, applied everywhere)
    ------------------------------------------------------------
    A feature that MobSF *did not report* — because its whole source section is
    absent (no dynamic run -> every ``dyn_*``; no ``certificate_analysis`` ->
    every ``cert_*``; etc.) — is stored as ``None`` (SQL NULL), NOT 0. A feature
    genuinely *measured as zero* (the section was scanned and the count came back
    empty) is stored as ``0``. That is why every raw field defaults to ``None``:
    an extractor only writes a concrete number once it has actually seen the
    section. The deterministic Feature-Store Score coerces ``None`` -> 0 for
    scoring (via ``_num``), but the stored ``None`` is preserved so a future ML
    model can tell "absent" apart from "zero". The interaction/``feat_*`` derived
    features are the exception: they are always computed at the end (coercing any
    ``None`` inputs to 0), so they are always a concrete 0/1.

    Layer tags (from the spec): fs = feeds the deterministic Feature-Store Score,
    ml = ML-only, both = both. Kept in comments for auditability.
    """

    # ---- Identity / bookkeeping -------------------------------------------- #
    apk_hash: str = ""                       # SHA256, primary key
    apk_filename: str = ""
    analysis_timestamp: str = ""             # ISO-8601 UTC
    static_analysis_success: int = 0         # stored as 0/1 in SQLite
    dynamic_analysis_success: int = 0
    confidence_level: str = "low"            # high / medium / low

    # ---- Permissions ------------------------------------------------------- #
    perm_internet: Optional[int] = None              # fs
    perm_send_sms: Optional[int] = None              # both
    perm_read_sms: Optional[int] = None              # both
    perm_receive_sms: Optional[int] = None           # both
    perm_camera: Optional[int] = None                # fs
    perm_accessibility: Optional[int] = None         # both
    perm_overlay: Optional[int] = None               # both
    perm_device_admin: Optional[int] = None          # both
    perm_read_contacts: Optional[int] = None         # fs
    perm_record_audio: Optional[int] = None          # both
    perm_read_call_log: Optional[int] = None         # both
    perm_receive_boot: Optional[int] = None          # both
    perm_read_phone_state: Optional[int] = None      # fs
    perm_write_settings: Optional[int] = None        # fs
    dangerous_perm_count: Optional[int] = None       # fs
    total_perm_count: Optional[int] = None           # ml
    malware_perm_count: Optional[int] = None         # fs

    # ---- API calls (static code scan) -------------------------------------- #
    api_file_io_count: Optional[int] = None          # both
    api_tcp_count: Optional[int] = None              # ml
    api_crypto_count: Optional[int] = None           # ml
    api_reflection_count: Optional[int] = None       # both
    api_base64_count: Optional[int] = None           # ml
    api_ipc_count: Optional[int] = None              # ml
    api_message_digest_count: Optional[int] = None   # ml

    # ---- Code findings ----------------------------------------------------- #
    code_ecb_mode: Optional[int] = None              # both
    code_logging_sensitive: Optional[int] = None     # ml
    code_total_findings: Optional[int] = None        # ml

    # ---- Manifest ---------------------------------------------------------- #
    manifest_debuggable: Optional[int] = None        # both
    manifest_allow_backup: Optional[int] = None      # fs
    manifest_unprotected_exported: Optional[int] = None  # both
    manifest_high_count: Optional[int] = None        # fs
    manifest_warning_count: Optional[int] = None     # fs
    manifest_min_sdk: Optional[int] = None           # ml
    manifest_target_sdk: Optional[int] = None        # ml

    # ---- Certificate ------------------------------------------------------- #
    cert_debug_signed: Optional[int] = None          # both
    cert_high_findings: Optional[int] = None         # fs
    cert_warning_findings: Optional[int] = None      # fs

    # ---- Network (static) -------------------------------------------------- #
    static_domain_count: Optional[int] = None        # both
    static_url_count: Optional[int] = None           # ml
    static_http_count: Optional[int] = None          # both
    static_http_ratio: Optional[float] = None        # ml
    static_bad_domains: Optional[int] = None         # both
    static_ofac_domains: Optional[int] = None        # both
    firebase_url_count: Optional[int] = None         # ml
    secrets_count: Optional[int] = None              # both

    # ---- APKiD (anti-analysis detection) ----------------------------------- #
    apkid_anti_vm_checks: Optional[int] = None       # both
    apkid_unknown_compiler: Optional[int] = None     # ml
    apkid_suspicious_compiler: Optional[int] = None  # both
    apkid_dex_count: Optional[int] = None            # ml

    # ---- Binary (native libs) ---------------------------------------------- #
    binary_total_libs: Optional[int] = None          # ml
    binary_unfortified_ratio: Optional[float] = None # ml
    binary_all_stripped: Optional[int] = None        # ml

    # ---- Exported components ----------------------------------------------- #
    exported_activities: Optional[int] = None        # both
    exported_services: Optional[int] = None          # both
    exported_receivers: Optional[int] = None         # both
    exported_total: Optional[int] = None             # fs

    # ---- Strings & obfuscation --------------------------------------------- #
    strings_code_count: Optional[int] = None         # ml
    avg_string_entropy: Optional[float] = None       # ml
    max_string_entropy: Optional[float] = None       # ml
    short_string_ratio: Optional[float] = None       # ml

    # ---- AppSec (MobSF composite) ------------------------------------------ #
    appsec_score: Optional[int] = None               # ml
    appsec_high_count: Optional[int] = None          # fs
    appsec_warning_count: Optional[int] = None       # fs
    static_tracker_count: Optional[int] = None       # ml
    sbom_package_count: Optional[int] = None          # ml

    # ---- Network (dynamic) ------------------------------------------------- #
    # NOTE: `dyn_non_us_domain_ratio` from the original spec is intentionally
    # NOT implemented (geo fix). For an Indian PMLA/FIU-IND deployment a "non-US
    # ratio" false-positives on exactly the legitimate apps we protect (which
    # contact Indian, i.e. non-US, infrastructure). `dyn_unique_countries` stays
    # as an ml-only breadth signal with no US bias.
    dyn_domain_count: Optional[int] = None           # both
    dyn_url_count: Optional[int] = None              # both
    dyn_bad_domains: Optional[int] = None            # both
    dyn_ofac_domains: Optional[int] = None           # both
    dyn_unique_countries: Optional[int] = None       # ml

    # ---- Domain delta (key obfuscation signal) ----------------------------- #
    # `dyn_static_domain_delta` counts dynamic-only domains that are NOT benign
    # OS/CDN infrastructure (Google/Android/Firebase connectivity checks the
    # emulator makes on its own). Filtering that infrastructure is the same
    # anti-false-positive principle as the geo fix: "talked to Google" is not
    # "hidden C2". See `_BENIGN_INFRA_SUFFIXES` and `_extract_derived`.
    dyn_static_domain_delta: Optional[int] = None    # both (derived)
    dyn_static_url_delta: Optional[int] = None       # ml (derived)

    # ---- Runtime behaviour (dynamic sandbox) ------------------------------- #
    dyn_apimon_call_count: Optional[int] = None      # both
    dyn_droidmon_call_count: Optional[int] = None    # both
    dyn_base64_strings: Optional[int] = None         # ml
    dyn_clipboard_access: Optional[int] = None       # both
    dyn_sqlite_access: Optional[int] = None          # both
    dyn_sandbox_complete: Optional[int] = None       # ml
    dyn_tracker_count: Optional[int] = None          # ml

    # ---- Interaction / derived features ------------------------------------ #
    # Always concrete 0/1: computed last from the raw fields above (None -> 0).
    feat_sms_trifecta: Optional[int] = None          # both
    feat_overlay_accessibility: Optional[int] = None # both
    feat_anti_vm_detected: Optional[int] = None      # both
    feat_hidden_network: Optional[int] = None        # both
    feat_obfuscated_suspicious: Optional[int] = None # both

    @classmethod
    def column_names(cls) -> List[str]:
        """Ordered column names — single source of truth for the DB + CSV."""
        return [f.name for f in fields(cls)]


# --------------------------------------------------------------------------- #
# MobSF REST client
# --------------------------------------------------------------------------- #


class MobSFClient:
    """Thin wrapper over the MobSF REST API.

    Centralizes auth header injection, base-URL handling and error logging so the
    pipeline code reads as a clean sequence of high-level steps.
    """

    def __init__(self, base_url: str = MOBSF_URL, api_key: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("MOBSF_API_KEY", "")
        if not self.api_key:
            raise RuntimeError(
                "MOBSF_API_KEY is not set. Copy the API key from the MobSF web UI "
                "(top-right 'API' link) and export it as MOBSF_API_KEY."
            )
        # MobSF expects the raw key in the Authorization header (no 'Bearer ').
        self._headers = {"Authorization": self.api_key}

    # -- low-level helpers --------------------------------------------------- #

    def _post(self, path: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}{path}"
        return requests.post(url, headers=self._headers, timeout=HTTP_TIMEOUT, **kwargs)

    # -- static analysis ----------------------------------------------------- #

    def upload(self, apk_path: str) -> Dict[str, Any]:
        """POST /api/v1/upload — upload an APK, returns {hash, scan_type, file_name}."""
        LOG.info("Uploading APK to MobSF: %s", apk_path)
        with open(apk_path, "rb") as fh:
            files = {"file": (os.path.basename(apk_path), fh, "application/vnd.android.package-archive")}
            resp = self._post("/api/v1/upload", files=files)
        resp.raise_for_status()
        data = resp.json()
        LOG.info("Upload OK, MobSF hash=%s", data.get("hash"))
        return data

    def scan(self, scan_hash: str, file_name: str, scan_type: str = "apk") -> Dict[str, Any]:
        """POST /api/v1/scan — trigger the static scan for an uploaded hash."""
        LOG.info("Starting static scan for hash=%s", scan_hash)
        payload = {"hash": scan_hash, "scan_type": scan_type, "file_name": file_name}
        resp = self._post("/api/v1/scan", data=payload)
        resp.raise_for_status()
        return resp.json()

    def static_report(self, scan_hash: str) -> Dict[str, Any]:
        """POST /api/v1/report_json — fetch the full static JSON report."""
        LOG.info("Fetching static JSON report for hash=%s", scan_hash)
        resp = self._post("/api/v1/report_json", data={"hash": scan_hash})
        resp.raise_for_status()
        return resp.json()

    # -- dynamic analysis ---------------------------------------------------- #

    def dynamic_start(self, scan_hash: str) -> Dict[str, Any]:
        """POST /api/v1/dynamic/start_analysis — boot the app on the emulator."""
        LOG.info("Starting dynamic analysis for hash=%s", scan_hash)
        resp = self._post("/api/v1/dynamic/start_analysis", data={"hash": scan_hash})
        resp.raise_for_status()
        return resp.json()

    def dynamic_stop(self, scan_hash: str) -> Dict[str, Any]:
        """POST /api/v1/dynamic/stop_analysis — finalize instrumentation."""
        LOG.info("Stopping dynamic analysis for hash=%s", scan_hash)
        resp = self._post("/api/v1/dynamic/stop_analysis", data={"hash": scan_hash})
        resp.raise_for_status()
        return resp.json()

    def dynamic_report(self, scan_hash: str) -> Dict[str, Any]:
        """POST /api/v1/dynamic/report_json — fetch the dynamic JSON report."""
        LOG.info("Fetching dynamic JSON report for hash=%s", scan_hash)
        resp = self._post("/api/v1/dynamic/report_json", data={"hash": scan_hash})
        resp.raise_for_status()
        return resp.json()


# --------------------------------------------------------------------------- #
# Normalization helpers — absorb MobSF version drift
# --------------------------------------------------------------------------- #


def _as_iterable_permissions(perms: Any) -> List[str]:
    """Return a flat list of permission name strings from MobSF's `permissions`.

    Across MobSF versions this field has been:
      * a dict: {"android.permission.READ_SMS": {"status": "dangerous", ...}}
      * a list of dicts: [{"name": "android.permission.READ_SMS", ...}, ...]
      * a plain list of strings.
    We normalize all three into a list of permission-name strings.
    """
    if not perms:
        return []
    if isinstance(perms, dict):
        return list(perms.keys())
    if isinstance(perms, list):
        out = []
        for item in perms:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                # try common name-bearing keys
                name = item.get("name") or item.get("permission") or item.get("key")
                if name:
                    out.append(name)
        return out
    return []


def _permission_status_map(perms: Any) -> Dict[str, str]:
    """Map permission name -> protection status ('dangerous'/'normal'/...).

    Used to count dangerous permissions when MobSF labels them explicitly. Falls
    back to an empty map when the structure does not carry status info.
    """
    out: Dict[str, str] = {}
    if isinstance(perms, dict):
        for name, meta in perms.items():
            if isinstance(meta, dict):
                status = meta.get("status") or meta.get("protectionLevel") or ""
                out[name] = str(status).lower()
            else:
                out[name] = str(meta).lower()
    elif isinstance(perms, list):
        for item in perms:
            if isinstance(item, dict):
                name = item.get("name") or item.get("permission")
                status = item.get("status") or item.get("protectionLevel") or ""
                if name:
                    out[name] = str(status).lower()
    return out


def _first_present(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Return d[k] for the first key present & truthy — tolerates field renames."""
    for k in keys:
        if k in d and d[k] not in (None, "", [], {}):
            return d[k]
    return default


def _coerce_int(val: Any) -> Optional[int]:
    """Coerce a MobSF value to int, returning None for unparseable/None input.

    MobSF occasionally renders numeric fields as strings; this keeps the stored
    feature an integer while preserving the None ("absent") sentinel.
    """
    if val is None or val == "":
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        try:
            return int(float(val))
        except (TypeError, ValueError):
            return None


def _call_count(section: Any) -> int:
    """Total observed calls in a dynamic apimon/droidmon-style section.

    These sections are dicts keyed by class/API whose values are lists (or dicts)
    of individual call records; we sum their sizes. An empty dict -> 0 (the
    sandbox ran but observed nothing), a non-empty list -> its length. Defensive
    so an unexpected shape never raises.
    """
    if isinstance(section, dict):
        total = 0
        for v in section.values():
            if isinstance(v, (list, dict)):
                total += len(v)
            else:
                total += 1
        return total
    if isinstance(section, list):
        return len(section)
    return 0


def _shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of a string.

    High entropy is a hallmark of obfuscation: encrypted strings, packed
    payloads, and base64/hex C2 blobs all push entropy toward ~4.5-6.0,
    whereas natural identifiers sit lower.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _deep_strings(obj: Any, _budget: List[int] = None) -> Iterable[str]:
    """Yield string leaves from an arbitrarily nested report (bounded).

    Used as a fallback corpus for IP/domain/entropy extraction when MobSF does
    not pre-aggregate these. Bounded to avoid pathological reports blowing up.
    """
    if _budget is None:
        _budget = [200_000]  # cap number of strings inspected
    if _budget[0] <= 0:
        return
    if isinstance(obj, str):
        _budget[0] -= 1
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _deep_strings(v, _budget)
    elif isinstance(obj, list):
        for v in obj:
            yield from _deep_strings(v, _budget)


# --------------------------------------------------------------------------- #
# Feature extraction
# --------------------------------------------------------------------------- #


class FeatureExtractor:
    """Turns normalized MobSF reports into a :class:`FeatureVector`.

    Each ``_extract_*`` method owns one feature group and is defensive about
    missing/renamed fields so a partial report never crashes the pipeline.
    """

    def __init__(self, static_report: Dict[str, Any], dynamic_report: Optional[Dict[str, Any]]):
        self.static = static_report or {}
        self.dynamic = dynamic_report or {}

    # -- permissions --------------------------------------------------------- #

    def _extract_permissions(self, fv: FeatureVector) -> None:
        """Permissions group: individual banking-trojan capability flags + counts.

        Section: ``permissions`` (dict: name -> {status, info, description}).
        Absent section -> every ``perm_*`` stays None (missing-vs-zero rule).
        ``malware_perm_count`` comes from the separate ``malware_permissions``
        section and is set independently.
        """
        perms = self.static.get("permissions")
        if isinstance(perms, dict):
            names = set(perms.keys())
            fv.perm_internet = int("android.permission.INTERNET" in names)
            fv.perm_send_sms = int("android.permission.SEND_SMS" in names)
            fv.perm_read_sms = int("android.permission.READ_SMS" in names)
            fv.perm_receive_sms = int("android.permission.RECEIVE_SMS" in names)
            fv.perm_camera = int("android.permission.CAMERA" in names)
            fv.perm_accessibility = int(
                "android.permission.BIND_ACCESSIBILITY_SERVICE" in names
            )
            fv.perm_overlay = int("android.permission.SYSTEM_ALERT_WINDOW" in names)
            fv.perm_device_admin = int("android.permission.BIND_DEVICE_ADMIN" in names)
            fv.perm_read_contacts = int("android.permission.READ_CONTACTS" in names)
            fv.perm_record_audio = int("android.permission.RECORD_AUDIO" in names)
            fv.perm_read_call_log = int("android.permission.READ_CALL_LOG" in names)
            fv.perm_receive_boot = int(
                "android.permission.RECEIVE_BOOT_COMPLETED" in names
            )
            fv.perm_read_phone_state = int(
                "android.permission.READ_PHONE_STATE" in names
            )
            fv.perm_write_settings = int("android.permission.WRITE_SETTINGS" in names)
            fv.dangerous_perm_count = sum(
                1 for v in perms.values()
                if isinstance(v, dict) and v.get("status") == "dangerous"
            )
            fv.total_perm_count = len(perms)

        mp = self.static.get("malware_permissions")
        if isinstance(mp, dict):
            fv.malware_perm_count = _coerce_int(mp.get("total_malware_permissions"))

    # -- API calls (static code scan) ---------------------------------------- #

    def _api_files(self, key: str) -> int:
        """Count the files that touch a given MobSF ``android_api`` category.

        Each ``android_api[<key>]`` is ``{"files": {...}, "metadata": {...}}`` —
        ``files`` is a path-keyed dict (older builds: a list). We count its size.
        """
        api = self.static.get("android_api")
        if not isinstance(api, dict):
            return 0
        entry = api.get(key)
        if not isinstance(entry, dict):
            return 0
        files = entry.get("files")
        return len(files) if isinstance(files, (list, dict)) else 0

    def _extract_api(self, fv: FeatureVector) -> None:
        """API group: file I/O, network, crypto, reflection, base64, IPC counts.

        Section: ``android_api``. Absent -> every ``api_*`` stays None.
        """
        if not isinstance(self.static.get("android_api"), dict):
            return
        fv.api_file_io_count = self._api_files("api_local_file_io")
        fv.api_tcp_count = self._api_files("api_tcp")
        fv.api_crypto_count = self._api_files("api_crypto")
        fv.api_reflection_count = self._api_files("api_java_reflection")
        fv.api_base64_count = (
            self._api_files("api_base64_encode") + self._api_files("api_base64_decode")
        )
        fv.api_ipc_count = self._api_files("api_ipc")
        fv.api_message_digest_count = self._api_files("api_message_digest")

    # -- code findings ------------------------------------------------------- #

    def _extract_code(self, fv: FeatureVector) -> None:
        """Code-analysis findings: weak crypto (ECB), sensitive logging, totals.

        Section: ``code_analysis.findings`` (dict keyed by rule id). Absent -> None.
        """
        ca = self.static.get("code_analysis")
        findings = ca.get("findings") if isinstance(ca, dict) else None
        if not isinstance(findings, dict):
            return
        fv.code_ecb_mode = int("android_aes_ecb" in findings)
        fv.code_logging_sensitive = int("android_logging" in findings)
        fv.code_total_findings = len(findings)

    # -- network (static) ---------------------------------------------------- #

    def _extract_network(self, fv: FeatureVector) -> None:
        """Static network group: domains, URLs, cleartext ratio, bad/OFAC C2.

        Sections: ``domains`` (dict: domain -> {bad, ofac, geolocation}),
        ``urls`` (list of {urls:[...], path}), ``firebase_urls``, ``secrets``.
        Each sub-feature stays None only when its own source section is absent.
        """
        domains = self.static.get("domains")
        if isinstance(domains, dict):
            fv.static_domain_count = len(domains)
            fv.static_bad_domains = sum(
                1 for v in domains.values()
                if isinstance(v, dict) and v.get("bad", "no") != "no"
            )
            fv.static_ofac_domains = sum(
                1 for v in domains.values()
                if isinstance(v, dict) and v.get("ofac")
            )

        urls = self.static.get("urls")
        if isinstance(urls, list):
            all_urls = [
                u for e in urls if isinstance(e, dict)
                for u in (e.get("urls", []) or [])
            ]
            fv.static_url_count = len(all_urls)
            http_count = sum(
                1 for u in all_urls if isinstance(u, str) and u.startswith("http://")
            )
            https_count = sum(
                1 for u in all_urls if isinstance(u, str) and u.startswith("https://")
            )
            fv.static_http_count = http_count
            fv.static_http_ratio = round(http_count / max(http_count + https_count, 1), 4)

        if "firebase_urls" in self.static:
            fb = self.static.get("firebase_urls")
            fv.firebase_url_count = len(fb) if isinstance(fb, list) else 0
        if "secrets" in self.static:
            sec = self.static.get("secrets")
            fv.secrets_count = len(sec) if isinstance(sec, list) else 0

    # -- APKiD (anti-analysis detection) ------------------------------------- #

    def _extract_apkid(self, fv: FeatureVector) -> None:
        """APKiD group: anti-VM checks, unknown/suspicious compilers, dex count.

        Section: ``apkid`` (dict: dex filename -> {anti_vm:[...], compiler:[...]}).
        Absent -> every ``apkid_*`` stays None.
        """
        apkid = self.static.get("apkid")
        if not isinstance(apkid, dict):
            return
        vals = [v for v in apkid.values() if isinstance(v, dict)]
        fv.apkid_anti_vm_checks = sum(len(v.get("anti_vm", []) or []) for v in vals)
        fv.apkid_unknown_compiler = sum(
            1 for v in vals for c in (v.get("compiler", []) or [])
            if "unknown" in str(c).lower()
        )
        fv.apkid_suspicious_compiler = sum(
            1 for v in vals for c in (v.get("compiler", []) or [])
            if "suspicious" in str(c).lower()
        )
        fv.apkid_dex_count = len(apkid)

    # -- binary (native libs) ------------------------------------------------ #

    def _extract_binary(self, fv: FeatureVector) -> None:
        """Binary-hardening group from ``binary_analysis`` (list of .so reports).

        Absent -> every ``binary_*`` stays None. A present-but-empty list means
        "no native libs": total 0, ratio 0.0, and not-all-stripped (0).
        """
        bins = self.static.get("binary_analysis")
        if not isinstance(bins, list):
            return
        entries = [b for b in bins if isinstance(b, dict)]
        fv.binary_total_libs = len(entries)
        if not entries:
            fv.binary_unfortified_ratio = 0.0
            fv.binary_all_stripped = 0
            return
        unfortified = sum(
            1 for b in entries if not (b.get("fortify", {}) or {}).get("is_fortified")
        )
        fv.binary_unfortified_ratio = round(unfortified / max(len(entries), 1), 4)
        fv.binary_all_stripped = int(
            all((b.get("symbol", {}) or {}).get("is_stripped") for b in entries)
        )

    # -- exported components ------------------------------------------------- #

    def _extract_exported(self, fv: FeatureVector) -> None:
        """Exported-component attack surface from ``exported_count`` (dict).

        Absent -> every ``exported_*`` stays None.
        """
        ec = self.static.get("exported_count")
        if not isinstance(ec, dict):
            return
        fv.exported_activities = _coerce_int(ec.get("exported_activities", 0))
        fv.exported_services = _coerce_int(ec.get("exported_services", 0))
        fv.exported_receivers = _coerce_int(ec.get("exported_receivers", 0))
        fv.exported_total = sum(v for v in ec.values() if isinstance(v, (int, float)))

    # -- strings & obfuscation ----------------------------------------------- #

    def _extract_strings(self, fv: FeatureVector) -> None:
        """String-obfuscation group from ``strings.strings_code`` (list).

        Entropy/short-ratio over code strings flags packing/encryption and
        aggressive ProGuard renaming. Absent -> every field stays None.
        """
        strings = self.static.get("strings")
        code_strings = strings.get("strings_code") if isinstance(strings, dict) else None
        if not isinstance(code_strings, list):
            return
        code_strings = [t for t in code_strings if isinstance(t, str)]
        fv.strings_code_count = len(code_strings)
        longs = [t for t in code_strings if len(t) > 3]
        entropies = [_shannon_entropy(t) for t in longs]
        fv.avg_string_entropy = round(sum(entropies) / len(entropies), 4) if entropies else 0.0
        fv.max_string_entropy = round(max(entropies), 4) if entropies else 0.0
        fv.short_string_ratio = round(
            sum(1 for t in code_strings if len(t) <= 3) / max(len(code_strings), 1), 4
        )

    # -- AppSec (MobSF composite) -------------------------------------------- #

    def _extract_appsec(self, fv: FeatureVector) -> None:
        """AppSec/tracker/SBOM composite signals.

        Sections: ``appsec`` (security_score + high/warning lists), ``trackers``,
        ``sbom``. Each sub-feature stays None only when its own section is absent.
        """
        appsec = self.static.get("appsec")
        if isinstance(appsec, dict):
            fv.appsec_score = _coerce_int(appsec.get("security_score"))
            fv.appsec_high_count = len(appsec.get("high", []) or [])
            fv.appsec_warning_count = len(appsec.get("warning", []) or [])
        trackers = self.static.get("trackers")
        if isinstance(trackers, dict):
            fv.static_tracker_count = _coerce_int(trackers.get("detected_trackers", 0))
        sbom = self.static.get("sbom")
        if isinstance(sbom, dict):
            pkgs = sbom.get("sbom_packages", []) or []
            fv.sbom_package_count = len(pkgs) if isinstance(pkgs, list) else 0

    # -- manifest ------------------------------------------------------------ #

    def _extract_manifest(self, fv: FeatureVector) -> None:
        """Manifest group: debuggable/backup, unprotected exports, sev counts, SDKs.

        Section: ``manifest_analysis`` (manifest_findings list + manifest_summary
        dict); ``min_sdk`` / ``target_sdk`` are top-level. The finding-derived and
        summary-derived features stay None when their structure is absent; the SDK
        features default to 0 (a present static report always carries them).
        """
        ma = self.static.get("manifest_analysis")
        findings = ma.get("manifest_findings") if isinstance(ma, dict) else None
        summary = ma.get("manifest_summary") if isinstance(ma, dict) else None

        if isinstance(findings, list):
            fv.manifest_debuggable = int(
                any("debuggable" in str(f) for f in findings)
            )
            fv.manifest_allow_backup = int(
                any("allowBackup" in str(f) for f in findings)
            )
            fv.manifest_unprotected_exported = sum(
                1 for f in findings
                if isinstance(f, dict) and "explicitly_exported" in str(f.get("rule", ""))
            )
        if isinstance(summary, dict):
            fv.manifest_high_count = _coerce_int(summary.get("high", 0))
            fv.manifest_warning_count = _coerce_int(summary.get("warning", 0))

        fv.manifest_min_sdk = int(self.static.get("min_sdk") or 0)
        fv.manifest_target_sdk = int(self.static.get("target_sdk") or 0)

    # -- certificate --------------------------------------------------------- #

    def _extract_certificate(self, fv: FeatureVector) -> None:
        """Certificate group: debug-signed flag + high/warning finding counts.

        Section: ``certificate_analysis`` (certificate_findings list +
        certificate_summary dict). Absent -> every ``cert_*`` stays None.
        """
        cert = self.static.get("certificate_analysis")
        if not isinstance(cert, dict):
            return
        findings = cert.get("certificate_findings")
        if isinstance(findings, list):
            fv.cert_debug_signed = int(
                any("debug certificate" in str(f) for f in findings)
            )
        summary = cert.get("certificate_summary")
        if isinstance(summary, dict):
            fv.cert_high_findings = _coerce_int(summary.get("high", 0))
            fv.cert_warning_findings = _coerce_int(summary.get("warning", 0))

    # -- dynamic (network + runtime behaviour) ------------------------------- #

    def _extract_dynamic(self, fv: FeatureVector) -> None:
        """Dynamic group: runtime network scope + observed sandbox behaviour.

        Source: the dynamic report (``self.dynamic``). When no dynamic run is
        available every ``dyn_*`` stays None (missing, not zero) — a future ML
        model must be able to tell "no sandbox run" from "ran, saw nothing".
        """
        d = self.dynamic
        if not d:
            return

        dyn_domains = d.get("domains")
        if isinstance(dyn_domains, dict):
            fv.dyn_domain_count = len(dyn_domains)
            fv.dyn_bad_domains = sum(
                1 for v in dyn_domains.values()
                if isinstance(v, dict) and v.get("bad", "no") != "no"
            )
            fv.dyn_ofac_domains = sum(
                1 for v in dyn_domains.values()
                if isinstance(v, dict) and v.get("ofac")
            )
            fv.dyn_unique_countries = len({
                (v.get("geolocation") or {}).get("country_short")
                for v in dyn_domains.values()
                if isinstance(v, dict) and v.get("geolocation")
            })

        if "urls" in d:
            urls = d.get("urls")
            fv.dyn_url_count = len(urls) if isinstance(urls, list) else 0

        # Runtime behaviour. apimon/droidmon are dicts of observed API calls;
        # count the total calls (sum of per-bucket lengths) defensively.
        fv.dyn_apimon_call_count = _call_count(d.get("apimon"))
        fv.dyn_droidmon_call_count = _call_count(d.get("droidmon"))
        fv.dyn_base64_strings = len(d.get("base64_strings", []) or [])
        fv.dyn_clipboard_access = len(d.get("clipboard", []) or [])
        fv.dyn_sqlite_access = len(d.get("sqlite", []) or [])
        fv.dyn_sandbox_complete = int(bool(d.get("apimon")) or bool(d.get("droidmon")))
        trackers = d.get("trackers")
        fv.dyn_tracker_count = (
            _coerce_int(trackers.get("detected_trackers", 0))
            if isinstance(trackers, dict) else 0
        )

    # -- derived (domain delta + interaction features) ----------------------- #

    def _extract_derived(self, fv: FeatureVector) -> None:
        """Cross-section derived features. MUST run after all raw extractors.

        The domain/URL deltas compare the dynamic and static reports (so they
        only exist when both are present). The ``feat_*`` interaction features are
        always computed (coercing any None input to 0) so they are concrete 0/1.
        """
        s_domains = self.static.get("domains")
        d_domains = self.dynamic.get("domains") if self.dynamic else None
        if isinstance(s_domains, dict) and isinstance(d_domains, dict):
            # Dynamic-only domains, MINUS benign OS/CDN infrastructure the emulator
            # contacts on its own (anti-false-positive: "talked to Google" is not
            # "hidden C2"). This keeps a benign app off the hidden-C2 capability.
            new_domains = set(d_domains.keys()) - set(s_domains.keys())
            fv.dyn_static_domain_delta = sum(
                1 for dom in new_domains if not _is_benign_infra(dom)
            )
            s_urls = self.static.get("urls") or []
            s_url_total = sum(
                len(e.get("urls", []) or []) for e in s_urls if isinstance(e, dict)
            )
            d_urls = self.dynamic.get("urls") or []
            fv.dyn_static_url_delta = (len(d_urls) if isinstance(d_urls, list) else 0) - s_url_total

        def g(name: str) -> float:
            v = getattr(fv, name)
            return float(v) if isinstance(v, (int, float)) else 0.0

        fv.feat_sms_trifecta = int(
            bool(g("perm_send_sms")) and bool(g("perm_read_sms")) and bool(g("perm_receive_sms"))
        )
        fv.feat_overlay_accessibility = int(
            bool(g("perm_overlay")) and bool(g("perm_accessibility"))
        )
        fv.feat_anti_vm_detected = int(g("apkid_anti_vm_checks") > 0)
        fv.feat_hidden_network = int(g("dyn_static_domain_delta") > 5)
        fv.feat_obfuscated_suspicious = int(
            g("apkid_suspicious_compiler") > 0 and g("avg_string_entropy") > 3.5
        )

    # -- orchestration ------------------------------------------------------- #

    def extract(self) -> FeatureVector:
        """Run every feature group and return the populated vector.

        Order matters: ``_extract_derived`` consumes the raw fields the other
        extractors populate, so it runs last.
        """
        fv = FeatureVector()
        self._extract_permissions(fv)
        self._extract_api(fv)
        self._extract_code(fv)
        self._extract_network(fv)
        self._extract_apkid(fv)
        self._extract_binary(fv)
        self._extract_exported(fv)
        self._extract_strings(fv)
        self._extract_appsec(fv)
        self._extract_manifest(fv)
        self._extract_certificate(fv)
        self._extract_dynamic(fv)
        self._extract_derived(fv)
        return fv


# --------------------------------------------------------------------------- #
# SQLite feature store
# --------------------------------------------------------------------------- #


class FeatureStore:
    """SQLite-backed feature store keyed by APK SHA256.

    One row per APK. Re-analysing the same APK upserts (replaces) the row so the
    store always holds the latest vector.
    """

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    # SQLite type derived from each dataclass field's type annotation. With
    # ``from __future__ import annotations`` the annotation is a string (e.g.
    # "Optional[float]"), so we match on substrings.
    @staticmethod
    def _column_sql_type(name: str) -> str:
        """Pick a SQLite type per column from the FeatureVector field annotation."""
        ann = {f.name: str(f.type) for f in fields(FeatureVector)}
        t = ann.get(name, "")
        if "str" in t:
            return "TEXT"
        if "float" in t:
            return "REAL"
        return "INTEGER"

    def _build_table_ddl(self) -> str:
        """DDL for the features table, deriving column types from the dataclass."""
        col_defs = []
        for c in FeatureVector.column_names():
            sql_type = self._column_sql_type(c)
            if c == "apk_hash":
                col_defs.append(f"{c} {sql_type} PRIMARY KEY")
            else:
                col_defs.append(f"{c} {sql_type}")
        return f"CREATE TABLE IF NOT EXISTS features (\n  {',\n  '.join(col_defs)}\n);"

    def _ensure_schema(self) -> None:
        """Create the features table, MIGRATING the old schema if columns differ.

        SQLite's ``CREATE TABLE IF NOT EXISTS`` is a no-op when the table already
        exists, so simply adding dataclass fields would NOT add columns to a
        pre-existing ``feature_store.sqlite`` (the v1 38-column store). To pick up
        the v2 85-feature set we compare the live columns (``PRAGMA table_info``)
        against the dataclass field set and, on any mismatch, DROP and recreate
        the table. The store holds derived features re-extractable from the raw
        MobSF reports, so dropping it is safe; we log it loudly.
        """
        wanted = FeatureVector.column_names()
        with self._connect() as conn:
            existing = [r[1] for r in conn.execute("PRAGMA table_info(features)").fetchall()]
            if existing and existing != wanted:
                LOG.warning(
                    "Feature-store schema mismatch (have %d cols, want %d, SCHEMA_VERSION=%d) "
                    "— recreating the `features` table. Re-run extraction to repopulate.",
                    len(existing), len(wanted), SCHEMA_VERSION,
                )
                conn.execute("DROP TABLE features")
            conn.execute(self._build_table_ddl())
            conn.commit()
        LOG.info("Feature store ready at %s (%d columns, v%d)",
                 self.db_path, len(wanted), SCHEMA_VERSION)

    def upsert(self, fv: FeatureVector) -> None:
        """Insert or replace the row for this APK hash."""
        cols = FeatureVector.column_names()
        placeholders = ", ".join("?" for _ in cols)
        data = asdict(fv)
        values = [data[c] for c in cols]
        sql = f"INSERT OR REPLACE INTO features ({', '.join(cols)}) VALUES ({placeholders})"
        with self._connect() as conn:
            conn.execute(sql, values)
            conn.commit()
        LOG.info("Stored feature vector for %s (%s)", fv.apk_filename, fv.apk_hash[:12])

    def export_csv(self, csv_path: str) -> int:
        """Dump the whole feature store to CSV. Returns the row count written."""
        import csv

        cols = FeatureVector.column_names()
        with self._connect() as conn:
            rows = conn.execute(f"SELECT {', '.join(cols)} FROM features").fetchall()
        with open(csv_path, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(cols)
            writer.writerows(rows)
        LOG.info("Exported %d rows to %s", len(rows), csv_path)
        return len(rows)


# --------------------------------------------------------------------------- #
# Pipeline orchestrator
# --------------------------------------------------------------------------- #


def sha256_of_file(path: str) -> str:
    """Stream-hash a file to SHA256 (the APK's stable identity / primary key)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class FeatureStorePipeline:
    """End-to-end driver: APK in -> normalized report -> features -> store."""

    def __init__(
        self,
        mobsf_url: str = MOBSF_URL,
        api_key: Optional[str] = None,
        db_path: str = DB_PATH,
    ):
        self.client = MobSFClient(mobsf_url, api_key)
        self.store = FeatureStore(db_path)

    # -- static -------------------------------------------------------------- #

    def _run_static(self, apk_path: str) -> Dict[str, Any]:
        """Upload + scan + fetch report. Raises on hard failure."""
        upload_info = self.client.upload(apk_path)
        scan_hash = upload_info["hash"]
        file_name = upload_info.get("file_name", os.path.basename(apk_path))
        scan_type = upload_info.get("scan_type", "apk")
        self.client.scan(scan_hash, file_name, scan_type)
        report = self.client.static_report(scan_hash)
        # Stash the MobSF scan hash so dynamic analysis can reuse it.
        report["_mobsf_hash"] = scan_hash
        return report

    # -- dynamic ------------------------------------------------------------- #

    def _run_dynamic(self, scan_hash: str) -> Optional[Dict[str, Any]]:
        """Best-effort dynamic analysis. Never raises — returns None on failure."""
        try:
            self.client.dynamic_start(scan_hash)
            # Let the app run & misbehave on the emulator before we snapshot it.
            LOG.info("Dynamic instrumentation running for %ds...", DYNAMIC_RUN_SECONDS)
            time.sleep(DYNAMIC_RUN_SECONDS)
            self.client.dynamic_stop(scan_hash)
            report = self.client.dynamic_report(scan_hash)
            return report
        except Exception as exc:  # noqa: BLE001 - dynamic is intentionally non-fatal
            LOG.warning("Dynamic analysis failed/timed out (continuing static-only): %s", exc)
            return None

    # -- confidence ---------------------------------------------------------- #

    @staticmethod
    def _confidence(static_ok: bool, dynamic_ok: bool) -> str:
        """high = both, medium = static only, low = partial/failed static."""
        if static_ok and dynamic_ok:
            return "high"
        if static_ok and not dynamic_ok:
            return "medium"
        return "low"

    # -- orchestrate --------------------------------------------------------- #

    def analyze_apk(
        self,
        apk_path: str,
        run_dynamic: bool = True,
        report_dir: Optional[str] = None,
    ) -> FeatureVector:
        """Analyse one APK and persist its feature vector. Returns the vector.

        If ``report_dir`` is given, the complete raw MobSF JSON reports (static
        and, when available, dynamic) are written there for inspection — exactly
        what the REST API returned, before any feature extraction.
        """
        if not os.path.isfile(apk_path):
            raise FileNotFoundError(apk_path)

        apk_hash = sha256_of_file(apk_path)
        LOG.info("Analyzing %s (sha256=%s)", apk_path, apk_hash)

        static_ok = False
        dynamic_ok = False
        static_report: Dict[str, Any] = {}
        dynamic_report: Optional[Dict[str, Any]] = None

        # --- static (required for a useful vector, but we still record on fail) #
        try:
            static_report = self._run_static(apk_path)
            static_ok = bool(static_report) and "error" not in static_report
        except Exception as exc:  # noqa: BLE001
            LOG.error("Static analysis failed for %s: %s", apk_path, exc)
            static_ok = False

        # --- dynamic (best effort) --------------------------------------- #
        if run_dynamic and static_ok:
            scan_hash = static_report.get("_mobsf_hash")
            if scan_hash:
                dynamic_report = self._run_dynamic(scan_hash)
                dynamic_ok = dynamic_report is not None
        elif run_dynamic and not static_ok:
            LOG.warning("Skipping dynamic analysis because static analysis failed.")

        # --- optionally dump the raw MobSF JSON for inspection ----------- #
        if report_dir:
            self._save_raw_reports(report_dir, apk_path, static_report, dynamic_report)

        # --- feature extraction ------------------------------------------ #
        extractor = FeatureExtractor(static_report, dynamic_report)
        fv = extractor.extract()

        # --- bookkeeping fields ------------------------------------------ #
        fv.apk_hash = apk_hash
        fv.apk_filename = os.path.basename(apk_path)
        fv.analysis_timestamp = datetime.now(timezone.utc).isoformat()
        fv.static_analysis_success = int(static_ok)
        fv.dynamic_analysis_success = int(dynamic_ok)
        fv.confidence_level = self._confidence(static_ok, dynamic_ok)

        # --- persist ------------------------------------------------------ #
        self.store.upsert(fv)
        return fv

    @staticmethod
    def _save_raw_reports(
        report_dir: str,
        apk_path: str,
        static_report: Dict[str, Any],
        dynamic_report: Optional[Dict[str, Any]],
    ) -> None:
        """Write the complete raw MobSF JSON reports to ``report_dir``."""
        os.makedirs(report_dir, exist_ok=True)
        base = os.path.splitext(os.path.basename(apk_path))[0]
        if static_report:
            # Drop our internal bookkeeping key so the file is pure MobSF output.
            clean = {k: v for k, v in static_report.items() if k != "_mobsf_hash"}
            path = os.path.join(report_dir, f"{base}.static.json")
            with open(path, "w") as fh:
                json.dump(clean, fh, indent=2, ensure_ascii=False)
            LOG.info("Saved raw static report -> %s", path)
        if dynamic_report:
            path = os.path.join(report_dir, f"{base}.dynamic.json")
            with open(path, "w") as fh:
                json.dump(dynamic_report, fh, indent=2, ensure_ascii=False)
            LOG.info("Saved raw dynamic report -> %s", path)

    def export_csv(self, csv_path: str) -> int:
        return self.store.export_csv(csv_path)


# --------------------------------------------------------------------------- #
# Offline replay — build a FeatureVector from bundled reports (no MobSF needed)
# --------------------------------------------------------------------------- #


def extract_from_reports(
    static_json: Dict[str, Any],
    dynamic_json: Optional[Dict[str, Any]] = None,
    apk_filename: str = "",
    apk_hash: str = "",
) -> FeatureVector:
    """Run the full extractor over already-fetched MobSF reports.

    This is the MobSF-free path used by the self-test and by ``--replay``: it
    feeds the saved ``reports/<name>.static.json`` (+ optional dynamic) straight
    into :class:`FeatureExtractor` so the 85-feature set can be regenerated and
    validated without a live server.
    """
    fv = FeatureExtractor(static_json or {}, dynamic_json or {}).extract()
    fv.apk_filename = apk_filename
    fv.apk_hash = apk_hash or (static_json or {}).get("sha256", "") or ""
    fv.analysis_timestamp = datetime.now(timezone.utc).isoformat()
    fv.static_analysis_success = int(bool(static_json))
    fv.dynamic_analysis_success = int(bool(dynamic_json))
    fv.confidence_level = (
        "high" if (static_json and dynamic_json)
        else "medium" if static_json else "low"
    )
    return fv


def replay_reports(
    static_path: str,
    db_path: str = DB_PATH,
    persist: bool = True,
) -> FeatureVector:
    """Replay a saved static report (+ sibling dynamic) into a FeatureVector.

    The dynamic report is looked up by the basename convention
    (``<base>.static.json`` -> ``<base>.dynamic.json``). When ``persist`` is set
    the vector is upserted into the feature store so the sqlite/CSV reflect the
    new 85-column schema.
    """
    with open(static_path) as fh:
        static_json = json.load(fh)
    base = os.path.basename(static_path)
    if base.endswith(".static.json"):
        base = base[: -len(".static.json")]
    dyn_path = os.path.join(os.path.dirname(static_path), f"{base}.dynamic.json")
    dynamic_json = None
    if os.path.exists(dyn_path):
        with open(dyn_path) as fh:
            dynamic_json = json.load(fh)

    fv = extract_from_reports(
        static_json, dynamic_json, apk_filename=f"{base}.apk",
    )
    if persist:
        FeatureStore(db_path).upsert(fv)
    return fv


# --------------------------------------------------------------------------- #
# Pretty-print helper for the CLI / test
# --------------------------------------------------------------------------- #


def print_feature_vector(fv: FeatureVector) -> None:
    """Human-readable dump of a feature vector, grouped for readability."""
    data = asdict(fv)
    print("\n" + "=" * 60)
    print(f" FEATURE VECTOR  —  {fv.apk_filename}")
    print("=" * 60)
    groups = {
        "Identity / status": [
            "apk_hash", "apk_filename", "analysis_timestamp",
            "static_analysis_success", "dynamic_analysis_success", "confidence_level",
        ],
        "Permissions": [
            "perm_internet", "perm_send_sms", "perm_read_sms", "perm_receive_sms",
            "perm_camera", "perm_accessibility", "perm_overlay", "perm_device_admin",
            "perm_read_contacts", "perm_record_audio", "perm_read_call_log",
            "perm_receive_boot", "perm_read_phone_state", "perm_write_settings",
            "dangerous_perm_count", "total_perm_count", "malware_perm_count",
        ],
        "API calls": [
            "api_file_io_count", "api_tcp_count", "api_crypto_count",
            "api_reflection_count", "api_base64_count", "api_ipc_count",
            "api_message_digest_count",
        ],
        "Code findings": [
            "code_ecb_mode", "code_logging_sensitive", "code_total_findings",
        ],
        "Manifest": [
            "manifest_debuggable", "manifest_allow_backup",
            "manifest_unprotected_exported", "manifest_high_count",
            "manifest_warning_count", "manifest_min_sdk", "manifest_target_sdk",
        ],
        "Certificate": [
            "cert_debug_signed", "cert_high_findings", "cert_warning_findings",
        ],
        "Network (static)": [
            "static_domain_count", "static_url_count", "static_http_count",
            "static_http_ratio", "static_bad_domains", "static_ofac_domains",
            "firebase_url_count", "secrets_count",
        ],
        "APKiD": [
            "apkid_anti_vm_checks", "apkid_unknown_compiler",
            "apkid_suspicious_compiler", "apkid_dex_count",
        ],
        "Binary": [
            "binary_total_libs", "binary_unfortified_ratio", "binary_all_stripped",
        ],
        "Exported": [
            "exported_activities", "exported_services", "exported_receivers",
            "exported_total",
        ],
        "Strings & obfuscation": [
            "strings_code_count", "avg_string_entropy", "max_string_entropy",
            "short_string_ratio",
        ],
        "AppSec": [
            "appsec_score", "appsec_high_count", "appsec_warning_count",
            "static_tracker_count", "sbom_package_count",
        ],
        "Network (dynamic)": [
            "dyn_domain_count", "dyn_url_count", "dyn_bad_domains",
            "dyn_ofac_domains", "dyn_unique_countries",
            "dyn_static_domain_delta", "dyn_static_url_delta",
        ],
        "Runtime behaviour": [
            "dyn_apimon_call_count", "dyn_droidmon_call_count", "dyn_base64_strings",
            "dyn_clipboard_access", "dyn_sqlite_access", "dyn_sandbox_complete",
            "dyn_tracker_count",
        ],
        "Interaction / derived": [
            "feat_sms_trifecta", "feat_overlay_accessibility",
            "feat_anti_vm_detected", "feat_hidden_network",
            "feat_obfuscated_suspicious",
        ],
    }
    for group, keys in groups.items():
        print(f"\n[{group}]")
        for k in keys:
            print(f"  {k:<32} {data[k]}")
    print("=" * 60 + "\n")


# --------------------------------------------------------------------------- #
# CLI / simple test
# --------------------------------------------------------------------------- #


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="MobSF-backed APK malware feature-store pipeline."
    )
    parser.add_argument("apk", nargs="?", help="Path to the APK to analyze.")
    parser.add_argument(
        "--static-only", action="store_true",
        help="Skip dynamic analysis (static features only).",
    )
    parser.add_argument(
        "--export", metavar="CSV_PATH",
        help="Export the whole feature store to CSV and exit (or after analysis).",
    )
    parser.add_argument("--mobsf-url", default=MOBSF_URL, help="MobSF base URL.")
    parser.add_argument("--db", default=DB_PATH, help="SQLite feature-store path.")
    parser.add_argument(
        "--save-report", metavar="DIR", nargs="?", const="reports", default=None,
        help="Save the complete raw MobSF JSON report(s) to DIR (default: ./reports).",
    )
    parser.add_argument(
        "--replay", metavar="STATIC_JSON",
        help="MobSF-free replay: re-extract the 85-feature set from a saved "
             "reports/<name>.static.json (and sibling .dynamic.json), upsert it "
             "into the store, and print it. No API key / server needed.",
    )
    args = parser.parse_args(argv)

    # Replay mode: re-extract from saved reports, no MobSF/API key needed.
    if args.replay:
        if not os.path.exists(args.replay):
            parser.error(f"Replay static report not found: {args.replay}")
        fv = replay_reports(args.replay, db_path=args.db, persist=True)
        print_feature_vector(fv)
        if args.export:
            store = FeatureStore(args.db)
            n = store.export_csv(args.export)
            print(f"Exported {n} rows to {args.export}")
        return 0

    # Export-only mode does not need an API key (no MobSF calls).
    if args.export and not args.apk:
        store = FeatureStore(args.db)
        n = store.export_csv(args.export)
        print(f"Exported {n} rows to {args.export}")
        return 0

    if not args.apk:
        parser.error("Provide an APK path, or use --export CSV_PATH to export only.")

    try:
        pipeline = FeatureStorePipeline(mobsf_url=args.mobsf_url, db_path=args.db)
    except RuntimeError as exc:
        LOG.error("%s", exc)
        return 2

    # --- the "simple test": run the pipeline and print the vector ---------- #
    fv = pipeline.analyze_apk(
        args.apk, run_dynamic=not args.static_only, report_dir=args.save_report
    )
    print_feature_vector(fv)

    if args.export:
        n = pipeline.export_csv(args.export)
        print(f"Exported {n} rows to {args.export}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
