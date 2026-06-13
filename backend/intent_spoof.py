"""
intent_spoof.py
===============

The **Intent Spoofing Detector** — flags an unknown APK that is impersonating a
genuine Indian bank app by carrying a look-alike package name but the WRONG
signing certificate. It compares the unknown APK's identity against a whitelist of
the real bank apps (``bank_whitelist.json``, built once by ``build_whitelist.py``).

This is a STANDALONE signal: ``main.py`` persists and displays the result, but it
does NOT feed the two-score fusion verdict.

Detection — a single, high-confidence signal
---------------------------------------------
    cert_mismatch -> "definitive": the unknown APK's package name fuzzy-matches a
    whitelisted bank (difflib ratio >= 0.75, OR one is a substring of the other)
    AND its signing-cert SHA-256 fingerprint differs from that bank's. In plain
    terms: *"claims to be <bank> but is NOT signed by <bank>"* — a near-irrefutable
    forgery. Anything else -> "clean".

Why only this tier: earlier drafts also had icon-similarity and app-name tiers,
but MobSF exposes neither a usable launcher icon (``icon_path`` is empty and its
``/download/`` route is session-auth, not API) nor a real app label for fakes that
aren't on the Play Store. Reviving those reliably needed an APK parser that just
duplicates what MobSF already runs internally, so they were dropped in favour of
this one dependable, zero-dependency, fully deterministic signal. The whitelist
fingerprints come from Google Play App Signing keys (per-app unique), which is
exactly what makes the cert check work.

Entry point
-----------
    detect_impersonation(static_json) -> ImpersonationResult   (never raises)
"""

from __future__ import annotations

import difflib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Fuzzy threshold for "this package looks like a bank's" (difflib ratio).
_PKG_FUZZY_THRESHOLD = 0.75


# --------------------------------------------------------------------------- #
# Certificate parsing (campaign_store.py was removed in a refactor, so these live
# here now and are imported by build_whitelist.py — single source of truth).
# --------------------------------------------------------------------------- #


def extract_cert_fingerprint(certificate_info: str) -> str:
    """Return the cert SHA-256 fingerprint from MobSF's ``certificate_info`` dump.

    The dump has a line like ``sha256: 018672...f9`` (64 hex). We target that
    specific line and NOT the separate ``Fingerprint:`` (public-key) line, which
    is a different value. Returns "" if no SHA-256 line is present.
    """
    if not certificate_info:
        return ""
    m = re.search(r"sha256:\s*([a-f0-9]{64})", certificate_info, re.IGNORECASE)
    return m.group(1).lower() if m else ""


def extract_cert_cn(certificate_info: str) -> str:
    """Return the subject Common Name (CN=...) from MobSF's ``certificate_info``.

    Prefers the ``X.509 Subject:`` line; falls back to the first CN found. For
    Play-App-Signed apps this is typically "Android" (informational only — the
    detector keys on the fingerprint, not the CN). Returns "" if no CN is present.
    """
    if not certificate_info:
        return ""
    for line in certificate_info.splitlines():
        if "subject" in line.lower():
            m = re.search(r"CN=([^,\n]+)", line)
            if m:
                return m.group(1).strip()
    m = re.search(r"CN=([^,\n]+)", certificate_info)
    return m.group(1).strip() if m else ""


# --------------------------------------------------------------------------- #
# Output dataclasses (every field defaulted so the graceful-degradation paths can
# build a valid result without spelling out every argument).
# --------------------------------------------------------------------------- #


@dataclass
class ImpersonationSignal:
    """One reason the unknown APK looks like a bank impersonation."""

    signal_type: str = ""       # "cert_mismatch"
    description: str = ""        # human-readable explanation
    matched_bank: str = ""       # which whitelist entry triggered this
    similarity: float = 0.0      # 0.0-1.0 package-name similarity to the bank


@dataclass
class ImpersonationResult:
    """The complete impersonation assessment for one unknown APK."""

    is_impersonation: bool = False
    confidence: str = "clean"               # "definitive" | "clean"
    target_bank: str = ""                   # e.g. "Bank of India" (empty if clean)
    target_app: str = ""                    # e.g. "BOI Mobile"
    genuine_package: str = ""               # the real package name
    actual_package: str = ""                # the APK being analysed
    signals: List[ImpersonationSignal] = field(default_factory=list)
    verdict: str = "No impersonation of any known bank app detected."
    error: Optional[str] = None


# --------------------------------------------------------------------------- #
# Whitelist loading (cached — it never changes at runtime)
# --------------------------------------------------------------------------- #

_WHITELIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bank_whitelist.json")
_WHITELIST_CACHE: Optional[List[dict]] = None


def _load_whitelist() -> List[dict]:
    """Load bank_whitelist.json once and cache it. Returns [] if missing/invalid."""
    global _WHITELIST_CACHE
    if _WHITELIST_CACHE is not None:
        return _WHITELIST_CACHE
    data: List[dict] = []
    try:
        if os.path.exists(_WHITELIST_PATH):
            with open(_WHITELIST_PATH, encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, list):
                data = [e for e in loaded if isinstance(e, dict)]
    except (ValueError, OSError):
        data = []
    _WHITELIST_CACHE = data
    return data


# --------------------------------------------------------------------------- #
# Matching helpers
# --------------------------------------------------------------------------- #


def _ratio(a: str, b: str) -> float:
    """Fuzzy string similarity in [0,1] via stdlib difflib (no new dependency)."""
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def _package_lookalike(pkg: str, bank_pkg: str) -> bool:
    """True if two package names are confusably similar (fuzzy OR substring)."""
    if not pkg or not bank_pkg:
        return False
    if _ratio(pkg, bank_pkg) >= _PKG_FUZZY_THRESHOLD:
        return True
    return pkg in bank_pkg or bank_pkg in pkg


def _bank_label(entry: dict) -> str:
    return entry.get("bank") or entry.get("app_name") or entry.get("package_name") or "unknown bank"


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def detect_impersonation(static_json: Dict[str, Any]) -> ImpersonationResult:
    """Compare an unknown APK's identity against the bank whitelist. Never raises.

    Fires only the deterministic cert-mismatch signal: a look-alike package whose
    signing certificate is NOT the genuine bank's. Degrades cleanly (error field)
    when the whitelist is missing.
    """
    try:
        whitelist = _load_whitelist()
        if not whitelist:
            return ImpersonationResult(
                error="Whitelist not found — run build_whitelist.py first")

        static_json = static_json or {}
        pkg = str(static_json.get("package_name", "") or "")
        cert = static_json.get("certificate_analysis") or {}
        cert_info = cert.get("certificate_info", "") if isinstance(cert, dict) else ""
        fp = extract_cert_fingerprint(cert_info)

        matches: List[tuple] = []   # (signal, entry)
        for e in whitelist:
            e_pkg = str(e.get("package_name", "") or "")
            e_fp = str(e.get("cert_fingerprint", "") or "").lower()
            bank = _bank_label(e)

            # Same signing cert => this IS the genuine app (or same-developer
            # family) — never an impersonation of this entry.
            if fp and e_fp and fp == e_fp:
                continue

            # cert_mismatch: package looks like the bank's, cert differs. Require a
            # readable unknown fingerprint so we assert a real mismatch, not merely
            # an unreadable certificate.
            if fp and e_fp and fp != e_fp and _package_lookalike(pkg, e_pkg):
                sim = _ratio(pkg, e_pkg)
                matches.append((ImpersonationSignal(
                    signal_type="cert_mismatch",
                    description=(f"Package '{pkg}' resembles {bank}'s '{e_pkg}' "
                                f"but is signed with a different certificate "
                                f"({fp[:16]}… vs genuine {e_fp[:16]}…)."),
                    matched_bank=bank, similarity=round(sim, 3)), e))

        if not matches:
            return ImpersonationResult(actual_package=pkg)

        # Strongest = closest package name to a genuine bank.
        matches.sort(key=lambda m: m[0].similarity, reverse=True)
        _, entry = matches[0]
        bank = _bank_label(entry)
        target_app = entry.get("app_name", "") or bank
        genuine_pkg = entry.get("package_name", "")
        verdict = (f"This APK is impersonating {target_app} ({bank}): its package "
                   f"'{pkg or '(unknown)'}' mimics the genuine '{genuine_pkg}' but it "
                   f"is signed with a DIFFERENT certificate — a definitive forgery.")

        return ImpersonationResult(
            is_impersonation=True,
            confidence="definitive",
            target_bank=bank,
            target_app=target_app,
            genuine_package=genuine_pkg,
            actual_package=pkg,
            signals=[s for s, _ in matches],
            verdict=verdict,
        )
    except Exception as exc:  # noqa: BLE001 - detector must never crash the job
        return ImpersonationResult(error=f"intent-spoof detector failed: {exc}")


# --------------------------------------------------------------------------- #
# __main__ self-test
# --------------------------------------------------------------------------- #


def _pretty(res: ImpersonationResult) -> None:
    print("\n" + "=" * 64)
    print(f" IMPERSONATION: {res.is_impersonation}   confidence: {res.confidence}")
    print("=" * 64)
    if res.error:
        print(f" error: {res.error}")
    if res.is_impersonation:
        print(f" target   : {res.target_app} ({res.target_bank})")
        print(f" genuine  : {res.genuine_package}")
        print(f" this apk : {res.actual_package}")
        for s in res.signals:
            print(f"   [{s.signal_type}] ({s.similarity}) {s.description}")
    print(f" verdict  : {res.verdict}")
    print("=" * 64 + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    import sys
    argv = argv if argv is not None else sys.argv[1:]
    here = os.path.dirname(os.path.abspath(__file__))
    if not argv:
        print("usage: python intent_spoof.py path/to/suspicious.apk")
        return 0
    base = os.path.splitext(os.path.basename(argv[0]))[0]
    static_path = os.path.join(here, "reports", f"{base}.static.json")
    if not os.path.exists(static_path):
        print("Run MobSF analysis first.")
        return 0
    with open(static_path, encoding="utf-8") as fh:
        static_json = json.load(fh)
    _pretty(detect_impersonation(static_json))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
