"""
capabilities.py
===============

The shared capability-weight table that makes the two scores comparable.

The whole two-score design rests on one idea: the Feature-Store Score and the
Code-Behaviour Score must measure the **same set of capabilities**, just through
two different lenses —

    * the Feature-Store Score asks "do the MobSF FEATURES *declare* this
      capability?" (a deterministic predicate over the feature row), and
    * the Code-Behaviour Score asks "did reverse-engineering *confirm* this
      capability in the actual code?" (a canonical behaviour tag the RE step
      emitted).

By scoring both sides against this one table, the fusion step can line them up
capability-by-capability and surface the interesting gaps (declared-but-not-
confirmed = over-permissioned; confirmed-but-not-declared = code does something
the features can't see).

Each capability carries:
    weight          int   points it contributes to whichever score it fires in
    tactic          str   MITRE ATT&CK Mobile tactic (for the MITRE map grouping)
    mitre           str   "<technique id> <name>", or "" for non-ATT&CK signals
    feature_rule    (feature_row) -> bool   does the FEATURE side declare it?
    feature_keys    tuple[str]              feature columns cited in the evidence
    behaviour_tags  tuple[str]              RE behaviour tags that CONFIRM it

# verify MITRE ids against the current ATT&CK Mobile matrix

Two capabilities are intentionally **RE-only** (`feature_rule` always False):
``dynamic_code_load`` and ``shell_exec``. The 85-feature set has no
``uses_dexclassloader`` / ``uses_runtime_exec`` column, so these cannot be seen
from features at all — they fire *only* when the code-behaviour side confirms
them. That is exactly the "code does something the features can't see" case the
two-score architecture exists to surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# Numeric coercion (mirrors risk_scorer._num: None/""/missing -> 0)
# --------------------------------------------------------------------------- #


def _num(row: Dict[str, Any], key: str, default: float = 0.0) -> float:
    """Coerce ``row[key]`` to float; None/""/missing/unparseable -> ``default``.

    The feature row may come straight from sqlite/CSV with string-typed values,
    and absent-section features are stored as None — both must compare as 0 here
    (the missing-vs-zero distinction is preserved in storage, not in scoring).
    """
    val = row.get(key, default)
    if val is None or val == "":
        return float(default)
    try:
        return float(val)
    except (TypeError, ValueError):
        return float(default)


# --------------------------------------------------------------------------- #
# Capability definition
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Capability:
    """One canonical capability, scored identically from features or behaviour."""

    weight: int
    tactic: str                       # MITRE ATT&CK Mobile tactic ("" if none)
    mitre: str                        # "<id> <name>" ("" for non-ATT&CK signals)
    feature_rule: Callable[[Dict[str, Any]], bool]
    feature_keys: Tuple[str, ...] = ()
    behaviour_tags: Tuple[str, ...] = ()


# --------------------------------------------------------------------------- #
# The capability table
# --------------------------------------------------------------------------- #
#
# Weights follow the project spec. The high-weight banking-trojan capabilities
# (otp_theft_combo, accessibility_abuse, device_admin) only fire on real
# capability constellations; the low-weight, MITRE-less signals (reflection,
# obfuscation, weak_crypto, debuggable, self_signed_cert) are weak priors that a
# benign debug build can trip — which is why score_capabilities() caps their
# *combined* contribution so a pile of benign-build artifacts cannot alone reach
# the High band (see _WEAK_SIGNAL_CAP).

CAPABILITIES: Dict[str, Capability] = {
    # ---- OTP / SMS interception (the banking-trojan core) ------------------ #
    "otp_theft_combo": Capability(
        weight=35, tactic="Credential Access", mitre="T1417.002 Input Capture: GUI Input Capture",
        feature_rule=lambda r: (
            (_num(r, "perm_read_sms") == 1 or _num(r, "perm_receive_sms") == 1)
            and _num(r, "perm_accessibility") == 1
        ),
        feature_keys=("perm_read_sms", "perm_receive_sms", "perm_accessibility"),
        behaviour_tags=("intercept_sms", "abuse_accessibility"),
    ),
    "sms_access": Capability(
        weight=14, tactic="Collection", mitre="T1636.004 Protected User Data: SMS Messages",
        feature_rule=lambda r: (
            _num(r, "perm_receive_sms") == 1 or _num(r, "perm_read_sms") == 1
            or _num(r, "feat_sms_trifecta") == 1
        ),
        feature_keys=("perm_read_sms", "perm_receive_sms", "feat_sms_trifecta"),
        behaviour_tags=("intercept_sms",),
    ),
    "sms_send": Capability(
        weight=12, tactic="Impact", mitre="T1582 SMS Control",
        feature_rule=lambda r: _num(r, "perm_send_sms") == 1,
        feature_keys=("perm_send_sms",),
        behaviour_tags=("send_sms",),
    ),
    # ---- Accessibility / overlay (clickjacking & fake login) -------------- #
    "accessibility_abuse": Capability(
        weight=20, tactic="Impact", mitre="T1516 Input Injection",
        feature_rule=lambda r: _num(r, "perm_accessibility") == 1,
        feature_keys=("perm_accessibility",),
        behaviour_tags=("abuse_accessibility",),
    ),
    "screen_overlay": Capability(
        weight=15, tactic="Credential Access", mitre="T1417.002 Input Capture: GUI Input Capture",
        feature_rule=lambda r: (
            _num(r, "perm_overlay") == 1 or _num(r, "feat_overlay_accessibility") == 1
        ),
        feature_keys=("perm_overlay", "feat_overlay_accessibility"),
        behaviour_tags=("screen_overlay",),
    ),
    # ---- Privilege / persistence ----------------------------------------- #
    "device_admin": Capability(
        weight=20, tactic="Privilege Escalation",
        mitre="T1626.001 Abuse Elevation Control Mechanism: Device Administrator Permissions",
        feature_rule=lambda r: _num(r, "perm_device_admin") == 1,
        feature_keys=("perm_device_admin",),
        behaviour_tags=("device_admin",),
    ),
    "persistence_boot": Capability(
        weight=6, tactic="Persistence",
        mitre="T1624.001 Event Triggered Execution: Broadcast Receivers",
        feature_rule=lambda r: _num(r, "perm_receive_boot") == 1,
        feature_keys=("perm_receive_boot",),
        behaviour_tags=("persistence_boot",),
    ),
    # ---- RE-only: no feature can see these (see module docstring) --------- #
    "dynamic_code_load": Capability(
        weight=15, tactic="Defense Evasion", mitre="T1407 Download New Code at Runtime",
        feature_rule=lambda r: False,
        feature_keys=(),
        behaviour_tags=("dynamic_code_load",),
    ),
    "shell_exec": Capability(
        weight=10, tactic="Execution",
        mitre="T1623.001 Command and Scripting Interpreter: Unix Shell",
        feature_rule=lambda r: False,
        feature_keys=(),
        behaviour_tags=("shell_exec",),
    ),
    # ---- Surveillance / data theft ---------------------------------------- #
    "contact_harvest": Capability(
        weight=8, tactic="Collection", mitre="T1636.003 Protected User Data: Contact List",
        feature_rule=lambda r: _num(r, "perm_read_contacts") == 1,
        feature_keys=("perm_read_contacts",),
        behaviour_tags=("read_contacts",),
    ),
    "camera_capture": Capability(
        weight=10, tactic="Collection", mitre="T1512 Video Capture",
        feature_rule=lambda r: _num(r, "perm_camera") == 1,
        feature_keys=("perm_camera",),
        behaviour_tags=("camera_capture",),
    ),
    "audio_capture": Capability(
        weight=10, tactic="Collection", mitre="T1429 Audio Capture",
        feature_rule=lambda r: _num(r, "perm_record_audio") == 1,
        feature_keys=("perm_record_audio",),
        behaviour_tags=("record_audio",),
    ),
    "call_log_theft": Capability(
        weight=8, tactic="Collection", mitre="T1636.002 Protected User Data: Call Log",
        feature_rule=lambda r: _num(r, "perm_read_call_log") == 1,
        feature_keys=("perm_read_call_log",),
        behaviour_tags=("read_call_log",),
    ),
    "device_fingerprint": Capability(
        weight=4, tactic="Discovery", mitre="T1426 System Information Discovery",
        feature_rule=lambda r: _num(r, "perm_read_phone_state") == 1,
        feature_keys=("perm_read_phone_state",),
        behaviour_tags=("device_fingerprint",),
    ),
    "clipboard_theft": Capability(
        weight=8, tactic="Collection", mitre="T1414 Clipboard Data",
        feature_rule=lambda r: _num(r, "dyn_clipboard_access") > 0,
        feature_keys=("dyn_clipboard_access",),
        behaviour_tags=("clipboard_theft",),
    ),
    "local_db_exfil": Capability(
        weight=6, tactic="Collection", mitre="T1409 Stored Application Data",
        feature_rule=lambda r: _num(r, "dyn_sqlite_access") > 0,
        feature_keys=("dyn_sqlite_access",),
        behaviour_tags=("sqlite_exfil",),
    ),
    # ---- Command & control ------------------------------------------------ #
    "c2_sanctioned_infra": Capability(
        weight=15, tactic="Command and Control",
        mitre="T1437.001 Application Layer Protocol: Web Protocols",
        feature_rule=lambda r: (
            _num(r, "static_ofac_domains") > 0 or _num(r, "dyn_ofac_domains") > 0
            or _num(r, "static_bad_domains") > 0 or _num(r, "dyn_bad_domains") > 0
        ),
        feature_keys=("static_ofac_domains", "dyn_ofac_domains",
                      "static_bad_domains", "dyn_bad_domains"),
        behaviour_tags=("c2_web",),
    ),
    "hidden_c2": Capability(
        weight=12, tactic="Command and Control",
        mitre="T1437.001 Application Layer Protocol: Web Protocols",
        feature_rule=lambda r: (
            _num(r, "feat_hidden_network") == 1 or _num(r, "dyn_static_domain_delta") > 5
        ),
        feature_keys=("feat_hidden_network", "dyn_static_domain_delta"),
        behaviour_tags=("c2_web",),
    ),
    "cleartext_traffic": Capability(
        weight=5, tactic="Command and Control",
        mitre="T1437 Application Layer Protocol",
        # Count-based / suspicious-excess: ordinary single-URL apps don't fire;
        # only an app whose traffic is meaningfully cleartext does.
        feature_rule=lambda r: (
            _num(r, "static_http_count") > 0 and _num(r, "static_http_ratio") > 0.3
        ),
        feature_keys=("static_http_count", "static_http_ratio"),
        behaviour_tags=("cleartext_http",),
    ),
    "weak_crypto": Capability(
        weight=6, tactic="Command and Control",
        mitre="T1521.001 Encrypted Channel: Symmetric Cryptography",
        feature_rule=lambda r: _num(r, "code_ecb_mode") == 1,
        feature_keys=("code_ecb_mode",),
        behaviour_tags=("weak_crypto_ecb",),
    ),
    # ---- Weak, MITRE-less priors (benign debug builds trip these) --------- #
    "anti_analysis": Capability(
        weight=12, tactic="Defense Evasion",
        mitre="T1633.001 Virtualization/Sandbox Evasion: System Checks",
        feature_rule=lambda r: (
            _num(r, "feat_anti_vm_detected") == 1 or _num(r, "apkid_anti_vm_checks") > 0
        ),
        feature_keys=("feat_anti_vm_detected", "apkid_anti_vm_checks"),
        behaviour_tags=("anti_emulation", "anti_debug"),
    ),
    "reflection": Capability(
        weight=7, tactic="", mitre="",
        feature_rule=lambda r: _num(r, "api_reflection_count") > 0,
        feature_keys=("api_reflection_count",),
        behaviour_tags=("reflection",),
    ),
    "obfuscation": Capability(
        weight=7, tactic="", mitre="",
        feature_rule=lambda r: (
            _num(r, "feat_obfuscated_suspicious") == 1
            or _num(r, "apkid_suspicious_compiler") > 0
        ),
        feature_keys=("feat_obfuscated_suspicious", "apkid_suspicious_compiler"),
        behaviour_tags=("obfuscation",),
    ),
    "self_signed_cert": Capability(
        weight=10, tactic="", mitre="",
        feature_rule=lambda r: _num(r, "cert_debug_signed") == 1,
        feature_keys=("cert_debug_signed",),
        behaviour_tags=(),
    ),
    "debuggable": Capability(
        weight=8, tactic="", mitre="",
        feature_rule=lambda r: _num(r, "manifest_debuggable") == 1,
        feature_keys=("manifest_debuggable",),
        behaviour_tags=(),
    ),
    "exported_surface": Capability(
        weight=4, tactic="", mitre="",
        # Threshold (>4) so an ordinary app's couple of exported components — the
        # benign app-debug has 3 — does not count as attack surface.
        feature_rule=lambda r: _num(r, "exported_total") > 4,
        feature_keys=("exported_total",),
        behaviour_tags=(),
    ),
}


# The canonical behaviour-tag vocabulary the reverse-engineering step must choose
# from when tagging code (the union of every capability's behaviour_tags). Kept
# sorted + deduped so the RE prompt and capabilities_from_behaviours() agree.
BEHAVIOUR_TAGS: Tuple[str, ...] = tuple(sorted({
    t for cap in CAPABILITIES.values() for t in cap.behaviour_tags
}))


# Weak, MITRE-less prior signals whose COMBINED contribution is capped so a
# benign debug build (which legitimately trips most of them: debug cert,
# debuggable, R8 optimisation, reflection, AES-ECB, anti-VM strings) cannot pile
# up into the High band on weak signals alone. This is the spec's "only count
# suspicious excess, not ordinary activity" principle applied to capabilities.
_WEAK_SIGNAL_CAPS = frozenset({
    "reflection", "obfuscation", "self_signed_cert", "debuggable",
    "exported_surface", "weak_crypto", "anti_analysis", "cleartext_traffic",
    "device_fingerprint",
})
_WEAK_SIGNAL_CAP = 40  # max combined points from the weak-signal group


# --------------------------------------------------------------------------- #
# Fired-capability evidence + helpers
# --------------------------------------------------------------------------- #


@dataclass
class FiredCapability:
    """A capability that fired, with the weight and evidence that justified it."""

    capability: str
    weight: int
    evidence: str
    mitre: str = ""


def _feature_evidence(cap_id: str, feature_row: Dict[str, Any]) -> str:
    """Evidence string citing the actual feature values behind a declared cap."""
    cap = CAPABILITIES[cap_id]
    parts = [f"{k}={_fmt(feature_row.get(k))}" for k in cap.feature_keys]
    return ", ".join(parts) if parts else "(declared by feature rule)"


def _fmt(v: Any) -> str:
    """Compact value formatter for evidence strings."""
    if isinstance(v, float):
        return f"{v:g}"
    return "None" if v is None else str(v)


def capabilities_from_features(feature_row: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Capabilities DECLARED by the feature row.

    Returns a list of ``(cap_id, evidence)`` for every capability whose
    ``feature_rule`` is satisfied. Deterministic: same row -> same list.
    """
    out: List[Tuple[str, str]] = []
    for cap_id, cap in CAPABILITIES.items():
        try:
            fired = bool(cap.feature_rule(feature_row))
        except Exception:  # noqa: BLE001 - a malformed row must never crash scoring
            fired = False
        if fired:
            out.append((cap_id, _feature_evidence(cap_id, feature_row)))
    return out


def capabilities_from_behaviours(behaviour_tags: List[str]) -> List[Tuple[str, str]]:
    """Capabilities CONFIRMED by a reverse-engineering behaviour catalog.

    A capability is confirmed when *all* of its ``behaviour_tags`` appear in the
    catalog (so ``otp_theft_combo`` needs both ``intercept_sms`` AND
    ``abuse_accessibility``). Capabilities with no behaviour_tags (pure feature
    signals like ``self_signed_cert``) are never confirmable from code and are
    skipped here. Returns ``(cap_id, evidence)`` pairs.
    """
    present = {t for t in (behaviour_tags or []) if t}
    out: List[Tuple[str, str]] = []
    for cap_id, cap in CAPABILITIES.items():
        if not cap.behaviour_tags:
            continue
        if all(t in present for t in cap.behaviour_tags):
            confirmed = ", ".join(cap.behaviour_tags)
            out.append((cap_id, f"code-confirmed behaviour tag(s): {confirmed}"))
    return out


def score_capabilities(
    fired_caps: List[Tuple[str, str]]
) -> Tuple[int, List[FiredCapability]]:
    """Sum the weights of fired capabilities into a 0-100 score.

    ``fired_caps`` is a list of ``(cap_id, evidence)`` (from either
    capabilities_from_features or capabilities_from_behaviours). Deduplicates by
    capability id, caps the combined weak-signal contribution (see
    ``_WEAK_SIGNAL_CAP``), sums, and clamps to 100. Returns
    ``(score, fired_rules)`` where each fired rule carries capability / weight /
    evidence / mitre for the audit trail.
    """
    seen: Dict[str, str] = {}
    for cap_id, evidence in fired_caps:
        if cap_id in CAPABILITIES and cap_id not in seen:
            seen[cap_id] = evidence

    fired_rules: List[FiredCapability] = []
    strong_total = 0
    weak_total = 0
    for cap_id, evidence in seen.items():
        cap = CAPABILITIES[cap_id]
        fired_rules.append(FiredCapability(
            capability=cap_id, weight=cap.weight, evidence=evidence, mitre=cap.mitre,
        ))
        if cap_id in _WEAK_SIGNAL_CAPS:
            weak_total += cap.weight
        else:
            strong_total += cap.weight

    raw = strong_total + min(weak_total, _WEAK_SIGNAL_CAP)
    score = min(100, raw)
    # Stable, readable order: highest-weight capability first.
    fired_rules.sort(key=lambda f: f.weight, reverse=True)
    return score, fired_rules


def mitre_for(cap_ids: List[str]) -> Dict[str, List[str]]:
    """Group the MITRE techniques of the given capabilities by ATT&CK tactic.

    Returns ``{tactic: [unique "<id> <name>" techniques]}``. Capabilities with no
    ATT&CK mapping (the weak MITRE-less priors) are skipped. Built ONLY from the
    capability ids passed in — the fusion/RE layers pass the code-confirmed
    capabilities so the MITRE map reflects what the code actually does.
    """
    out: Dict[str, List[str]] = {}
    for cap_id in cap_ids:
        cap = CAPABILITIES.get(cap_id)
        if not cap or not cap.mitre or not cap.tactic:
            continue
        bucket = out.setdefault(cap.tactic, [])
        if cap.mitre not in bucket:
            bucket.append(cap.mitre)
    return out


# --------------------------------------------------------------------------- #
# __main__ self-test (no MobSF, no LLM — pure logic over the bundled row)
# --------------------------------------------------------------------------- #


def _load_app_debug_row() -> Optional[Dict[str, Any]]:
    """Best-effort load of the benign app-debug feature row (sqlite, else None)."""
    import os
    import sqlite3
    here = os.path.dirname(os.path.abspath(__file__))
    db = os.path.join(here, "feature_store.sqlite")
    if not os.path.exists(db):
        return None
    try:
        with sqlite3.connect(db) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                "SELECT * FROM features WHERE apk_filename = ? LIMIT 1",
                ("app-debug.apk",),
            )
            r = cur.fetchone() or conn.execute("SELECT * FROM features LIMIT 1").fetchone()
            return dict(r) if r else None
    except sqlite3.Error:
        return None


def main() -> int:
    print(f"Behaviour-tag vocabulary ({len(BEHAVIOUR_TAGS)}): {', '.join(BEHAVIOUR_TAGS)}\n")

    # 1) Benign row (if available): must stay out of the High band.
    row = _load_app_debug_row()
    if row:
        declared = capabilities_from_features(row)
        score, fired = score_capabilities(declared)
        print(f"[app-debug] declared capabilities -> Feature-Store-style score {score}/100")
        for f in fired:
            print(f"   [{f.weight:>2}] {f.capability:<20} {f.evidence}")
        assert score < 50, f"benign app-debug must stay Low/Medium, got {score}"
        assert "otp_theft_combo" not in {c for c, _ in declared}
        print("   -> OK (Low/Medium, no OTP combo)\n")
    else:
        print("[app-debug] no feature_store.sqlite row — run "
              "`python feature_store_pipeline.py --replay reports/app-debug.static.json` first.\n")

    # 2) Synthetic banking-trojan behaviour catalog -> confirmed caps + MITRE.
    catalog = ["intercept_sms", "abuse_accessibility", "screen_overlay",
               "dynamic_code_load", "c2_web"]
    confirmed = capabilities_from_behaviours(catalog)
    score, fired = score_capabilities(confirmed)
    cap_ids = [c for c, _ in confirmed]
    print(f"[synthetic trojan] catalog={catalog}")
    print(f"   confirmed capabilities -> Code-Behaviour-style score {score}/100: {cap_ids}")
    mitre = mitre_for(cap_ids)
    print(f"   MITRE map: {mitre}")
    assert "otp_theft_combo" in cap_ids, "intercept_sms+abuse_accessibility must confirm OTP combo"
    assert "dynamic_code_load" in cap_ids, "RE-only capability must confirm from behaviour"
    assert score >= 50, f"a real trojan catalog should reach High, got {score}"
    print("   -> OK (High, OTP combo + RE-only dynamic_code_load confirmed)\n")

    print("capabilities.py self-test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
