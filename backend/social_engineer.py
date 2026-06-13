"""
social_engineer.py
==================

The **Social-Engineering Detector** — a standalone signal that runs alongside the
Code-Behaviour (reverse-engineering) step. Where reverse engineering asks "what
does the code *do*?", this asks "what does the app's *UI text* try to make the
user do?" — the human-layer attack that banking-fraud apps depend on (fake RBI
notices, urgent "your account will be blocked" prompts, fake OTP screens,
phishing instructions impersonating NPCI / a bank).

It is deliberately **independent of fusion**: it reads the MobSF static report and
(when available) the jadx-decompiled resources, sends a filtered set of UI strings
to the same local Ollama model the RE step uses, and persists its own verdict to
the result JSON. The two-score system (Feature-Store + Code-Behaviour) is untouched.

Entry point
-----------
    detect_social_engineering(static_json, resources_dir) -> SEResult

Never raises. Every failure path returns a structured ``SEResult`` whose
``se_error`` explains what went wrong, so the calling job can persist it and move
on rather than crashing.

String sources (highest signal first)
-------------------------------------
    A. resources_dir/res/values*/strings.xml + res/layout*  (real UI strings)
    B. static_json["strings"]["strings_apk_res"]            (MobSF APK-resource strings)
    B2. static_json["strings"]["strings_code"]              (DEX bytecode — mostly noise)
    C. static_json["urls"]                                  (WebView / phishing URLs)

All collection + filtering is pure (no I/O side effects beyond reading the
already-on-disk resource files), so it is easy to unit-test and to extend when new
string sources appear.
"""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# The Ollama plumbing lives in reverse_engineer.py — import, do NOT duplicate.
from reverse_engineer import _generate, _safe_json_loads, _ollama_available


# --------------------------------------------------------------------------- #
# Output dataclasses
# --------------------------------------------------------------------------- #


@dataclass
class SEFinding:
    """One UI string the LLM flagged as social engineering."""

    text: str          # the offending string or UI element
    source: str        # strings.xml | layout_xml | apk_res_strings | mobsf_strings | webview_url
    technique: str     # impersonation | urgency | fake_otp | phishing_url | authority_claim
    explanation: str   # one sentence: why this is social engineering
    confidence: str    # high | medium | low


@dataclass
class SEResult:
    """The complete social-engineering assessment for one APK.

    The first four fields carry defaults so the many graceful-degradation paths
    can construct a valid result without spelling out every field (e.g. an
    "Ollama unavailable" result only sets verdict/se_error). ``se_band`` is the
    primary downstream signal; ``se_score`` is advisory (LLM-derived).
    """

    verdict: str = "unknown"                  # clean | suspicious | social_engineering | unknown
    confidence: str = "low"                   # high | medium | low
    se_score: int = 0                         # 0-100
    se_band: str = "Low"                      # Low | Medium | High | Critical
    findings: List[SEFinding] = field(default_factory=list)
    strings_analysed: int = 0                 # how many strings were sent to the LLM
    sources_used: List[str] = field(default_factory=list)   # which sources contributed
    summary: str = ""
    se_error: Optional[str] = None


# --------------------------------------------------------------------------- #
# Banding (same cuts as the Feature-Store / Code-Behaviour sides)
# --------------------------------------------------------------------------- #


def _se_band(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


# --------------------------------------------------------------------------- #
# Source A — jadx-decompiled resources (strings.xml + layouts)
# --------------------------------------------------------------------------- #

# android:* attributes whose VALUES are user-visible text worth analysing.
_LAYOUT_TEXT_ATTRS = (
    "{http://schemas.android.com/apk/res/android}text",
    "{http://schemas.android.com/apk/res/android}hint",
    "{http://schemas.android.com/apk/res/android}contentDescription",
)


def _strings_from_values_xml(path: str) -> List[str]:
    """Extract <string name="...">value</string> values from a strings.xml file."""
    out: List[str] = []
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return out
    for el in root.iter("string"):
        text = "".join(el.itertext()).strip()
        if text:
            out.append(text)
    return out


def _strings_from_layout_xml(path: str) -> List[str]:
    """Extract android:text/hint/contentDescription + <string> text from a layout."""
    out: List[str] = []
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return out
    for el in root.iter():
        # Attribute-borne UI text. Skip @string/@id references — those resolve via
        # strings.xml (already collected) and are not literal text themselves.
        for attr in _LAYOUT_TEXT_ATTRS:
            val = el.get(attr)
            if val and not val.startswith("@"):
                val = val.strip()
                if val:
                    out.append(val)
        # Literal <string> element text content, if any.
        if el.tag == "string":
            text = "".join(el.itertext()).strip()
            if text:
                out.append(text)
    return out


def _collect_from_resources(resources_dir: str) -> List[Dict[str, str]]:
    """Source A: strings.xml (+ localised variants) and layout XMLs from jadx."""
    items: List[Dict[str, str]] = []
    res_root = os.path.join(resources_dir, "res")
    if not os.path.isdir(res_root):
        return items

    # values/ + values-*/  ->  strings.xml
    try:
        entries = os.listdir(res_root)
    except OSError:
        return items
    for entry in entries:
        if entry == "values" or entry.startswith("values-"):
            sx = os.path.join(res_root, entry, "strings.xml")
            if os.path.isfile(sx):
                for text in _strings_from_values_xml(sx):
                    items.append({"text": text, "source": "strings.xml"})

    # layout/ + layout-*/  ->  every .xml, walked recursively
    for entry in entries:
        if entry == "layout" or entry.startswith("layout"):
            layout_dir = os.path.join(res_root, entry)
            if not os.path.isdir(layout_dir):
                continue
            for dirpath, _dirs, files in os.walk(layout_dir):
                for fn in files:
                    if fn.endswith(".xml"):
                        for text in _strings_from_layout_xml(os.path.join(dirpath, fn)):
                            items.append({"text": text, "source": "layout_xml"})
    return items


# --------------------------------------------------------------------------- #
# Source B — MobSF strings_apk_res  ('"key" : "value"' formatted)
# --------------------------------------------------------------------------- #


def _parse_apk_res_value(entry: str) -> str:
    """MobSF formats APK-resource strings as '"key" : "value"' (strings.py:90).

    Return just the value (everything after the first ``" : "``, de-quoted). If the
    entry does not match that pattern, return it unchanged.
    """
    sep = '" : "'
    idx = entry.find(sep)
    if idx == -1:
        return entry.strip()
    value = entry[idx + len(sep):]
    return value.strip().strip('"').strip()


# --------------------------------------------------------------------------- #
# String collection
# --------------------------------------------------------------------------- #


def _collect_strings(static_json: Dict[str, Any],
                     resources_dir: Optional[str]) -> List[Dict[str, str]]:
    """Collect candidate UI strings from all sources. PURE (reads files only).

    Returns a list of ``{"text": str, "source": str}`` in priority order:
    resources (A) -> apk_res_strings (B) -> mobsf_strings (B2) -> webview_url (C).
    """
    static_json = static_json or {}
    items: List[Dict[str, str]] = []

    # --- Source A: jadx resources (highest signal) ----------------------- #
    if resources_dir:
        items.extend(_collect_from_resources(resources_dir))

    strings = static_json.get("strings")
    if isinstance(strings, dict):
        # --- Source B: MobSF APK-resource strings ('"key" : "value"') ---- #
        apk_res = strings.get("strings_apk_res")
        if isinstance(apk_res, list):
            for entry in apk_res:
                if isinstance(entry, str):
                    value = _parse_apk_res_value(entry)
                    if value:
                        items.append({"text": value, "source": "apk_res_strings"})

        # --- Source B2: DEX bytecode strings (mostly noise) -------------- #
        code = strings.get("strings_code")
        if isinstance(code, list):
            for entry in code:
                if isinstance(entry, str) and entry.strip():
                    items.append({"text": entry.strip(), "source": "mobsf_strings"})

    # --- Source C: WebView / phishing URLs ------------------------------- #
    urls = static_json.get("urls")
    if isinstance(urls, list):
        for e in urls:
            if isinstance(e, dict):
                for u in (e.get("urls", []) or []):
                    if isinstance(u, str) and u.strip():
                        items.append({"text": u.strip(), "source": "webview_url"})

    return items


# --------------------------------------------------------------------------- #
# String filtering — keep the LLM input small and high-signal
# --------------------------------------------------------------------------- #

_MAX_TOTAL = 80
_MAX_UI = 40                 # strings.xml + layout_xml
_MAX_APK_RES = 30            # apk_res_strings
_MAX_DEX = 20                # mobsf_strings (DEX noise) — only if room remains
_MAX_LEN = 300
_MIN_LEN = 6

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")

# Scoring keyword tiers (case-insensitive) — banking/SE relevance.
_KW_TIER3 = ["OTP", "UPI", "BHIM", "NEFT", "RTGS", "IMPS", "RBI", "Reserve Bank",
             "SBI", "HDFC", "ICICI", "Axis", "BOI", "PNB", "account", "CVV", "IFSC",
             "PIN", "netbanking", "net banking", "debit card", "credit card",
             "card number", "खाता", "बैंक", "ओटीपी", "पासवर्ड"]
_KW_TIER2 = ["verify", "confirm", "urgent", "suspend", "block", "official",
             "authorised", "authorized", "KYC", "aadhaar", "PAN", "expire", "expiry",
             "deactivat", "unauthoris", "unauthoriz", "penalty", "refund", "reward",
             "cashback", "winner", "lottery", "prize", "claim", "validate", "frozen"]
_KW_TIER1 = ["click", "tap", "enter", "fill", "submit", "login", "log in", "sign in",
             "password", "credential", "pay", "transfer", "transaction", "balance",
             "update your", "scan", "download", "install"]


def _kw_hit(low: str, keywords: List[str]) -> bool:
    """True if any keyword occurs as a whole word/token in ``low`` (already
    lower-cased). Word-boundary matching avoids false hits like 'PAN' inside
    'expand'/'panel' or 'pin' inside 'shopping'."""
    for k in keywords:
        kl = k.lower()
        if re.search(r"(?<![a-z0-9])" + re.escape(kl) + r"(?![a-z0-9])", low):
            return True
    return False


def _relevance_score(text: str) -> int:
    """Score a string by banking/social-engineering relevance (higher = keep first)."""
    low = text.lower()
    score = 0
    if _kw_hit(low, _KW_TIER3):
        score += 3
    if _kw_hit(low, _KW_TIER2):
        score += 2
    if _kw_hit(low, _KW_TIER1):
        score += 1
    return score


def _is_noise(text: str, source: str) -> bool:
    """Drop clearly non-UI strings (class names, tokens, hashes, code URLs)."""
    n = len(text)
    if n < _MIN_LEN or n > _MAX_LEN:
        return True
    # Purely alphanumeric with no spaces -> likely a class name / token / id.
    if " " not in text and text.isalnum():
        return True
    if _BASE64_RE.match(text):
        return True
    # URLs from code strings are noise here — real URLs arrive via source C.
    if text.startswith("http") and source != "webview_url":
        return True
    return False


def _filter_strings(raw_strings: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Dedup, drop noise, prioritise by relevance, and cap — PURE.

    Cap policy (so genuine UI text always beats DEX noise):
        * all UI strings (strings.xml + layout_xml), up to 40
        * top-scored apk_res_strings, up to 30
        * at most 20 mobsf_strings, ONLY if the 80-total cap is not yet reached
        * ALL webview_url entries, regardless of the cap (few, high signal)

    Every returned string is guaranteed length <= 300 (enforced via _is_noise).
    """
    # 1) Deduplicate exact text matches, keeping the first (highest-priority) source.
    seen: set = set()
    deduped: List[Dict[str, str]] = []
    for item in raw_strings:
        text = item.get("text", "")
        if text in seen:
            continue
        seen.add(text)
        deduped.append(item)

    # Split by source class.
    ui, apk_res, dex, urls = [], [], [], []
    for item in deduped:
        src = item.get("source", "")
        text = item.get("text", "")
        if src == "webview_url":
            # URLs bypass the noise filter (length only) — always kept below.
            if len(text) <= _MAX_LEN:
                urls.append(item)
            continue
        if _is_noise(text, src):
            continue
        # Only forward strings with some banking/SE relevance. Bundled framework
        # resources (date-picker / calendar / accessibility text, in dozens of
        # languages) score 0 here, so they no longer flood the model and produce
        # nonsense findings. Genuine fraud lures hit a keyword. WebView URLs are
        # exempt (handled above) — they are high-signal regardless of wording.
        if _relevance_score(text) < 1:
            continue
        if src in ("strings.xml", "layout_xml"):
            ui.append(item)
        elif src == "apk_res_strings":
            apk_res.append(item)
        elif src == "mobsf_strings":
            dex.append(item)

    # 2/3) Sort each tier by relevance desc, then length desc as a tiebreaker.
    keyer = lambda it: (_relevance_score(it["text"]), len(it["text"]))
    ui.sort(key=keyer, reverse=True)
    apk_res.sort(key=keyer, reverse=True)
    dex.sort(key=keyer, reverse=True)

    # 4) Apply the cap in priority order.
    out: List[Dict[str, str]] = []
    out.extend(ui[:_MAX_UI])
    remaining = _MAX_TOTAL - len(out)
    out.extend(apk_res[:min(_MAX_APK_RES, max(0, remaining))])
    remaining = _MAX_TOTAL - len(out)
    if remaining > 0:
        out.extend(dex[:min(_MAX_DEX, remaining)])

    # 5) Always include all WebView URLs (added after the cap; deduped already).
    out.extend(urls)
    return out


# --------------------------------------------------------------------------- #
# LLM interpretation
# --------------------------------------------------------------------------- #

_SE_SYSTEM = (
    "You are a social engineering analyst detecting fraud UI in Android APKs targeting\n"
    "Indian bank customers (UPI, netbanking, OTP fraud). You are given a list of strings\n"
    "extracted from an APK's UI layouts, string resources, and code.\n\n"
    "Identify strings that are social engineering: impersonation of RBI or bank officials,\n"
    "fake urgency (\"your account will be blocked\"), fake OTP screens, phishing instructions,\n"
    "or authority claims. Ignore strings that are clearly UI boilerplate (OK, Cancel,\n"
    "Loading...) or technical strings (class names, error codes).\n\n"
    "For Indian banking context: RBI never asks for OTP over phone/app; banks never ask\n"
    "customers to \"verify\" credentials via a third-party app; any string claiming to be\n"
    "from RBI/NPCI/government that requests account details is social engineering.\n\n"
    "Return ONLY a JSON object with exactly these keys:\n"
    "- verdict: \"clean\" | \"suspicious\" | \"social_engineering\"\n"
    "- confidence: \"high\" | \"medium\" | \"low\"\n"
    "- se_score: integer 0-100 (0=clean, 100=definite social engineering)\n"
    "- findings: array of objects, each with:\n"
    "    - text: the exact offending string\n"
    "    - technique: one of \"impersonation\" | \"urgency\" | \"fake_otp\" | \"phishing_url\" | \"authority_claim\"\n"
    "    - explanation: one sentence explaining why this is social engineering\n"
    "    - confidence: \"high\" | \"medium\" | \"low\"\n"
    "- summary: 2-3 sentences describing the overall social engineering assessment\n\n"
    "findings should be empty array if verdict is \"clean\".\n\n"
    "BE CONSERVATIVE — most apps are clean. ONLY flag a string when it EXPLICITLY does one "
    "of: asks for an OTP/PIN/CVV/password/card or account number; threatens that the account "
    "is blocked/suspended/expired unless the user acts; claims to be RBI/NPCI/a bank/government "
    "and requests details; or gives phishing instructions (open a link, install/scan to verify, "
    "pay to release funds).\n"
    "DO NOT flag, and DO NOT invent urgency or authority for: generic UI navigation, buttons, "
    "scrolling, swiping, date/time pickers, calendars, AM/PM, accessibility labels, or any "
    "ordinary app text — including such strings in other languages. If a string is just a "
    "normal UI label, it is NOT social engineering. When in doubt, do not flag.\n"
    "Use ONLY strings that appear verbatim in the provided list — never invent text. Output "
    "each distinct string at most ONCE (no duplicate findings) and at most 25 findings total."
)

_VERDICTS = ("clean", "suspicious", "social_engineering")
_CONFIDENCES = ("high", "medium", "low")
_TECHNIQUES = ("impersonation", "urgency", "fake_otp", "phishing_url", "authority_claim")


def _analyse_strings(filtered_strings: List[Dict[str, str]]) -> SEResult:
    """Single Ollama call over the filtered strings -> SEResult. Never raises."""
    import json

    user = json.dumps(
        [{"text": s["text"], "source": s["source"]} for s in filtered_strings],
        ensure_ascii=False,
    )
    # Wide context: the input can be ~80 strings; without a big enough window the
    # model's JSON reply gets truncated and fails to parse.
    text, err = _generate(user, _SE_SYSTEM, max_output_tokens=4096, json_mode=True,
                          num_ctx=8192)
    if err:
        return SEResult(verdict="unknown", se_error=err,
                        strings_analysed=len(filtered_strings),
                        sources_used=sorted({s["source"] for s in filtered_strings}))

    obj, perr = _safe_json_loads(text)
    if perr or not isinstance(obj, dict):
        return SEResult(verdict="unknown",
                        se_error=f"social-engineering response was not valid JSON "
                                 f"({perr or 'not a JSON object'})",
                        strings_analysed=len(filtered_strings),
                        sources_used=sorted({s["source"] for s in filtered_strings}))

    # Validate the verdict / confidence enums exactly like reverse_engineer.py.
    verdict = str(obj.get("verdict", "")).strip().lower()
    if verdict not in _VERDICTS:
        verdict = "unknown"
    confidence = str(obj.get("confidence", "low")).strip().lower()
    if confidence not in _CONFIDENCES:
        confidence = "low"

    try:
        se_score = int(obj.get("se_score", 0))
    except (TypeError, ValueError):
        se_score = 0
    se_score = max(0, min(100, se_score))

    # Map each LLM finding's text back to the source it came from (the LLM does
    # not echo source). Match on exact text first, then substring containment.
    by_text = {s["text"]: s["source"] for s in filtered_strings}

    def _backfill_source(ftext: str) -> Optional[str]:
        """Source of the analysed string this finding refers to, or None if the
        finding's text doesn't correspond to any string we sent (hallucinated)."""
        if ftext in by_text:
            return by_text[ftext]
        for s in filtered_strings:
            if ftext and (ftext in s["text"] or s["text"] in ftext):
                return s["source"]
        return None

    _MAX_FINDINGS = 25
    findings: List[SEFinding] = []
    seen_texts: set = set()
    for f in (obj.get("findings") or []):
        if not isinstance(f, dict):
            continue
        ftext = str(f.get("text", "")).strip()
        if not ftext:
            continue
        key = ftext.lower()
        if key in seen_texts:            # collapse the model's repetition loops
            continue
        source = _backfill_source(ftext)
        if source is None:               # drop hallucinated text not in our input
            continue
        seen_texts.add(key)
        technique = str(f.get("technique", "")).strip().lower()
        if technique not in _TECHNIQUES:
            technique = "authority_claim"
        fconf = str(f.get("confidence", "low")).strip().lower()
        if fconf not in _CONFIDENCES:
            fconf = "low"
        findings.append(SEFinding(
            text=ftext,
            source=source,
            technique=technique,
            explanation=str(f.get("explanation", "")).strip() or "(not provided)",
            confidence=fconf,
        ))
        if len(findings) >= _MAX_FINDINGS:
            break

    # A "clean" verdict must not carry findings; conversely if the model returned
    # findings but called it clean, trust the findings and treat as suspicious.
    if verdict == "clean" and findings:
        verdict = "suspicious"

    summary = str(obj.get("summary", "")).strip()
    return SEResult(
        verdict=verdict,
        confidence=confidence,
        se_score=se_score,
        se_band=_se_band(se_score),
        findings=findings,
        strings_analysed=len(filtered_strings),
        sources_used=sorted({s["source"] for s in filtered_strings}),
        summary=summary or "Social-engineering analysis completed.",
        se_error=None,
    )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def detect_social_engineering(
    static_json: Dict[str, Any],
    resources_dir: Optional[str],
) -> SEResult:
    """Detect social-engineering UI in an APK. Never raises.

    Degrades gracefully:
        * Ollama unreachable           -> verdict "unknown", se_error set.
        * 0 strings after filtering    -> verdict "clean", empty assessment.
        * LLM returns unparseable JSON -> verdict "unknown", se_error set.
    """
    try:
        if not _ollama_available():
            return SEResult(verdict="unknown", se_score=0, se_band="Low",
                            se_error="Ollama unavailable")

        raw = _collect_strings(static_json, resources_dir)
        filtered = _filter_strings(raw)
        if not filtered:
            return SEResult(verdict="clean", se_score=0, se_band="Low",
                            summary="No UI strings found for analysis.",
                            strings_analysed=0)

        return _analyse_strings(filtered)
    except Exception as exc:  # noqa: BLE001 - SE must never crash the job
        return SEResult(verdict="unknown", se_error=f"social-engineering step failed: {exc}")


# --------------------------------------------------------------------------- #
# __main__ self-test — pure functions, no Ollama / MobSF / jadx needed
# --------------------------------------------------------------------------- #


def _selftest() -> int:
    ok = True

    # 1) APK-resource value parsing ('"key" : "value"' -> value).
    assert _parse_apk_res_value('"login_title" : "Login to your account"') == "Login to your account"
    assert _parse_apk_res_value('plain string with no sep') == "plain string with no sep"
    print("  [OK] _parse_apk_res_value")

    # 2) Collection from MobSF strings + urls (Source B/B2/C), resources_dir=None.
    static = {
        "strings": {
            "strings_apk_res": ['"otp_msg" : "Enter the OTP sent by RBI to verify your account"',
                                '"ok_btn" : "OK"'],
            "strings_code": ["Lcom/evil/Foo;", "this is a human readable sentence about login"],
        },
        "urls": [{"urls": ["http://phish.example/login", "https://legit.example"], "path": "x"}],
    }
    raw = _collect_strings(static, None)
    srcs = {i["source"] for i in raw}
    assert "apk_res_strings" in srcs and "mobsf_strings" in srcs and "webview_url" in srcs, srcs
    assert any(i["text"] == "Enter the OTP sent by RBI to verify your account" for i in raw)
    print(f"  [OK] _collect_strings (None resources): {len(raw)} strings, sources={sorted(srcs)}")

    # 3) Filtering: noise dropped, 300-char cap enforced, URLs always kept.
    noisy = [
        {"text": "AbCdEf0123456789xy", "source": "mobsf_strings"},            # alnum, no space
        {"text": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", "source": "mobsf_strings"},  # base64
        {"text": "x" * 400, "source": "apk_res_strings"},                     # too long
        {"text": "Verify your UPI account now or it will be blocked", "source": "strings.xml"},
        {"text": "OK", "source": "strings.xml"},                              # too short
        {"text": "http://code.example/api", "source": "mobsf_strings"},        # code URL (not source C)
        {"text": "http://phish.example/steal", "source": "webview_url"},       # real WebView URL
    ]
    filt = _filter_strings(noisy)
    texts = [f["text"] for f in filt]
    assert all(len(t) <= _MAX_LEN for t in texts), "300-char cap not enforced"
    assert "Verify your UPI account now or it will be blocked" in texts
    assert "http://phish.example/steal" in texts, "WebView URL must always be kept"
    # Dropped by the spec's filters: too-short, alnum-no-space, base64, over-long, code URL.
    for dropped in ("OK", "AbCdEf0123456789xy", "x" * 400, "http://code.example/api"):
        assert dropped not in texts, f"should have been filtered: {dropped!r}"
    assert not any(_BASE64_RE.match(t) for t in texts)
    print(f"  [OK] _filter_strings: {len(noisy)} -> {len(filt)} kept; noise dropped, cap enforced")

    # 4) Cap policy: UI beats DEX noise; total never exceeds 80 (+ urls).
    many = ([{"text": f"UI string number {i} about your bank account verify", "source": "strings.xml"}
             for i in range(100)]
            + [{"text": f"dex noise blob sentence number {i} here", "source": "mobsf_strings"}
               for i in range(100)])
    filt2 = _filter_strings(many)
    non_url = [f for f in filt2 if f["source"] != "webview_url"]
    assert len(non_url) <= _MAX_TOTAL, len(non_url)
    ui_kept = sum(1 for f in filt2 if f["source"] == "strings.xml")
    assert ui_kept == _MAX_UI, ui_kept
    print(f"  [OK] cap policy: {len(non_url)} non-url kept (<=80), {ui_kept} UI strings (==40)")

    # 5) Graceful degradation: empty input -> clean; (Ollama path not exercised here).
    res = _analyse_strings([]) if _ollama_available() else SEResult(verdict="clean")
    assert isinstance(res, SEResult)
    print("  [OK] SEResult construction / partial-field defaults")

    print("\nsocial_engineer.py self-test:", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
