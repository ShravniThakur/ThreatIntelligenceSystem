"""
reverse_engineer.py
====================

The **Code-Behaviour** side of the two-score engine: decompile the APK, slice out
the code MobSF already pointed at, ask a local LLM (Ollama) what each slice
actually *does*, and fold the confirmed behaviours into a Code-Behaviour Score +
a MITRE map.

Where the Feature-Store Score asks "what does the app *declare*?", this asks
"what does the code *do*?" — the two are deliberately kept separate (see
``fusion.py``). The Code-Behaviour Score is **LLM-derived and may vary**, so it is
always surfaced as a BAND; the exact integer is soft.

Pipeline (``reverse_engineer(apk_path, static_json) -> ReverseEngineeringResult``):

    1. Decompile everything with ``jadx -d <tmp> <apk>`` (needs ``jadx`` on PATH;
       ``brew install jadx``). Missing/failed jadx -> graceful degrade.
    2. Triage deterministically using the ``file:line`` pointers MobSF already
       computed (``code_analysis.findings``, ``android_api``, ``permission_mapping``,
       ``behaviour``) plus exported components / entry points. Slice at the
       METHOD level (using the line numbers) and pull 1 call-graph hop of helper
       methods, skipping framework noise (androidx/kotlin/okio/...).
    3. Interpret each slice with ``_generate(..., json_mode=True)`` (direct Ollama call),
       constraining the model to the canonical behaviour-tag vocabulary from
       ``capabilities.BEHAVIOUR_TAGS``.
    4. Code-Behaviour Score = ``capabilities.score_capabilities(
       capabilities_from_behaviours(catalog))`` -> int + band.
    5. MITRE map = ``capabilities.mitre_for(confirmed_caps)`` (behaviour catalog
       ONLY; empty if RE failed).

Graceful degradation is mandatory: any jadx or LLM failure returns a structured
fallback with an ``llm_error`` / coverage note — it never crashes the pipeline.
If RE cannot run at all, ``code_score``/``code_band`` are None and ``mitre_map``
is ``{}``; the fusion step then falls back to the deterministic Feature-Store
Score alone.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import requests

import capabilities

try:
    from dotenv import load_dotenv
    _ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    load_dotenv(_ENV_PATH if os.path.exists(_ENV_PATH) else None)
except ImportError:
    pass

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gemma3")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "600"))


def _ollama_available() -> bool:
    """Best-effort reachability probe. Never raises."""
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        return r.status_code == 200
    except requests.RequestException:
        return False


def _generate(user_msg: str, system_prompt: str, max_output_tokens: int,
              json_mode: bool, num_ctx: Optional[int] = None) -> tuple[str, Optional[str]]:
    """POST one chat completion to Ollama. Returns (text, error); never raises.

    ``num_ctx`` (when set) widens the model context window so a long prompt plus a
    long ``num_predict`` output isn't truncated — the report generator needs this.
    """
    options: Dict[str, Any] = {"temperature": 0, "num_predict": max_output_tokens}
    if num_ctx:
        options["num_ctx"] = num_ctx
    payload: Dict[str, Any] = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_msg},
        ],
        "stream": False,
        "options": options,
    }
    if json_mode:
        payload["format"] = "json"
    try:
        resp = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=OLLAMA_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        text = (data.get("message") or {}).get("content", "") or data.get("response", "")
        if not text or not text.strip():
            return "", "empty response from Ollama"
        return text, None
    except requests.exceptions.ConnectionError as exc:
        return "", (f"Ollama unreachable at {OLLAMA_URL} "
                    f"(is `ollama serve` running and `{OLLAMA_MODEL}` pulled?): {exc}")
    except requests.exceptions.Timeout:
        return "", f"Ollama request timed out after {OLLAMA_TIMEOUT}s (model={OLLAMA_MODEL})"
    except requests.exceptions.HTTPError as exc:
        return "", f"Ollama HTTP error: {exc}"
    except Exception as exc:  # noqa: BLE001
        return "", f"Ollama error: {exc}"


def _safe_json_loads(text: str) -> tuple[Any, Optional[str]]:
    """json.loads with fence/prefix stripping; returns (obj, error)."""
    if not text:
        return None, "empty text"
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:]
        cleaned = cleaned.strip()
    try:
        return json.loads(cleaned), None
    except (ValueError, TypeError):
        pass
    # The model's JSON was likely truncated at the token limit — salvage every
    # complete value and close the brackets still open at that point.
    repaired = _repair_truncated_json(cleaned)
    if repaired is not None:
        return repaired, None
    # Loose fallback: first opener to last closer (handles prose-wrapped JSON).
    for open_ch, close_ch in ("{", "}"), ("[", "]"):
        start = cleaned.find(open_ch)
        end = cleaned.rfind(close_ch)
        if 0 <= start < end:
            try:
                return json.loads(cleaned[start:end + 1]), None
            except (ValueError, TypeError):
                continue
    return None, "JSON parse error"


def _repair_truncated_json(text: str) -> Any:
    """Best-effort recovery of a truncated JSON object/array. Returns the parsed
    value, or None. Cuts back to the last COMPLETE value (a closing bracket, or
    the position before a separating comma) and appends closers for the brackets
    still open there — so a reply cut off mid-element still yields the rest."""
    start = text.find("{")
    sb = text.find("[")
    if sb != -1 and (start == -1 or sb < start):
        start = sb
    if start < 0:
        return None
    s = text[start:]

    stack: List[str] = []        # expected closing chars, innermost last
    in_str = esc = False
    last_safe = -1               # cut index in `s` (exclusive) at a value boundary
    safe_stack: List[str] = []   # snapshot of `stack` at last_safe
    for i, ch in enumerate(s):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            stack.append("}")
        elif ch == "[":
            stack.append("]")
        elif ch in "}]":
            if stack:
                stack.pop()
            last_safe, safe_stack = i + 1, list(stack)   # value just closed
        elif ch == ",":
            last_safe, safe_stack = i, list(stack)       # value before comma done

    if last_safe <= 0:
        return None
    candidate = s[:last_safe].rstrip().rstrip(",").rstrip()
    candidate += "".join(reversed(safe_stack))
    try:
        return json.loads(candidate)
    except (ValueError, TypeError):
        return None

# Decompiled paths we never want to spend an LLM call on — framework / vendor
# code, not the app's own logic. Matched as path prefixes (forward-slashed).
_FRAMEWORK_PREFIXES = (
    "androidx/", "android/", "kotlin/", "kotlinx/", "okio/", "okhttp3/",
    "retrofit2/", "com/google/", "com/android/", "org/", "java/", "javax/",
    "dagger/", "javax/", "io/reactivex/", "io/grpc/", "junit/", "j$/",
    "_COROUTINE/", "kotlinx/coroutines/",
)

# How many sliced methods to actually send to the LLM (the spec's top-N ~6-10).
MAX_METHODS = int(os.getenv("RE_MAX_METHODS", "8"))
# jadx decompilation timeout (seconds).
JADX_TIMEOUT = int(os.getenv("RE_JADX_TIMEOUT", "300"))


# --------------------------------------------------------------------------- #
# Output dataclasses
# --------------------------------------------------------------------------- #


@dataclass
class REFinding:
    """One LLM-interpreted code slice."""

    class_name: str
    method: str
    location: str                 # "path/Foo.java:40"
    what_it_does: str
    data_accessed: str
    verdict: str                  # benign | suspicious | malicious
    confidence: str               # high | medium | low
    behaviour_tags: List[str] = field(default_factory=list)
    mitre_technique: str = ""
    evidence: str = ""            # why we triaged this slice (the MobSF pointer)


@dataclass
class ReverseEngineeringResult:
    """The complete Code-Behaviour assessment for one APK."""

    findings: List[REFinding] = field(default_factory=list)
    behaviour_catalog: List[str] = field(default_factory=list)  # confirmed canonical tags
    code_score: Optional[int] = None        # None when RE could not run
    code_band: Optional[str] = None         # the band is what downstream uses
    mitre_map: Dict[str, List[str]] = field(default_factory=dict)
    summary: str = ""
    verdict: str = "unknown"                # benign | sms_fraud | banking_trojan | suspicious | unknown
    capability_constellation: List[str] = field(default_factory=list)  # confirmed cap ids
    re_coverage: Dict[str, Any] = field(default_factory=dict)
    llm_error: Optional[str] = None
    # Stable path to the persisted jadx resources subset (strings.xml + layouts),
    # consumed by the social-engineering detector. None when RE/jadx did not run,
    # no resources were produced, or no report_dir was supplied.
    resources_dir: Optional[str] = None


# --------------------------------------------------------------------------- #
# Bands (LLM-derived score -> Low/Medium/High/Critical; same cuts as the FS side)
# --------------------------------------------------------------------------- #


def _band(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


# --------------------------------------------------------------------------- #
# Step 1 — decompile
# --------------------------------------------------------------------------- #


def _decompile(apk_path: str, out_dir: str) -> Tuple[Optional[str], Optional[str], str]:
    """Run jadx into ``out_dir``. Returns (sources_dir, resources_dir, quality).

    ``quality`` is "ok" | "partial" | "failed". jadx commonly exits non-zero with
    warnings while still producing usable sources, so we key success on the
    ``sources/`` directory being non-empty rather than on the exit code.

    We deliberately DO NOT pass ``--no-res`` any more: jadx then also emits a
    ``resources/`` directory (decompiled ``strings.xml`` + layouts) that the
    social-engineering detector reads. Resources are reported INDEPENDENTLY of
    sources — they can be absent even when sources succeeded — so each is the
    directory path if present and non-empty, else ``None``.
    """
    if not shutil.which("jadx"):
        return None, None, "failed"

    def _present(name: str) -> Optional[str]:
        path = os.path.join(out_dir, name)
        return path if os.path.isdir(path) and os.listdir(path) else None

    try:
        proc = subprocess.run(
            ["jadx", "-d", out_dir, apk_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=JADX_TIMEOUT, text=True,
        )
    except subprocess.TimeoutExpired:
        # A timeout can still leave partial sources on disk — use what we have.
        sources = _present("sources")
        if sources:
            return sources, _present("resources"), "partial"
        return None, None, "failed"
    except Exception:  # noqa: BLE001 - decompilation must never crash the pipeline
        return None, None, "failed"

    sources = _present("sources")
    if sources:
        return sources, _present("resources"), ("ok" if proc.returncode == 0 else "partial")
    return None, None, "failed"


def _persist_resources(resources_dir: Optional[str], report_dir: Optional[str],
                       apk_path: str) -> Optional[str]:
    """Copy the SE-relevant subset of jadx resources to a STABLE location.

    ``resources_dir`` lives inside the ``TemporaryDirectory`` that
    :func:`reverse_engineer` deletes on exit, so anything the downstream
    social-engineering step needs must be copied out first. We copy only
    ``res/values*/strings.xml`` (default + localised variants) and ``res/layout*``
    directories — never the full resources tree, which can be large. Returns the
    stable destination root (``<report_dir>/<apk_basename>_resources``) or ``None``
    if there was nothing to persist / the copy failed. Never raises.
    """
    if not resources_dir or not report_dir:
        return None
    try:
        src_res = os.path.join(resources_dir, "res")
        if not os.path.isdir(src_res):
            return None
        base = os.path.splitext(os.path.basename(apk_path))[0]
        dest_root = os.path.join(report_dir, f"{base}_resources")
        dest_res = os.path.join(dest_root, "res")
        copied = False
        for entry in os.listdir(src_res):
            src_entry = os.path.join(src_res, entry)
            # values, values-hi, values-en, ... -> copy strings.xml only.
            if entry == "values" or entry.startswith("values-"):
                strings_xml = os.path.join(src_entry, "strings.xml")
                if os.path.isfile(strings_xml):
                    os.makedirs(os.path.join(dest_res, entry), exist_ok=True)
                    shutil.copy2(strings_xml, os.path.join(dest_res, entry, "strings.xml"))
                    copied = True
            # layout, layout-land, layout-v21, ... -> copy the whole layout dir.
            elif entry == "layout" or entry.startswith("layout"):
                if os.path.isdir(src_entry):
                    shutil.copytree(src_entry, os.path.join(dest_res, entry), dirs_exist_ok=True)
                    copied = True
        return dest_root if copied else None
    except Exception:  # noqa: BLE001 - persistence is best-effort, never fatal
        return None


# --------------------------------------------------------------------------- #
# Step 2 — deterministic triage from the static-report pointers
# --------------------------------------------------------------------------- #


@dataclass
class _Candidate:
    """A (file, lines, reason) triage target, before slicing/LLM."""

    path: str                 # "com/example/.../Foo.java"
    lines: List[int]
    reason: str               # why MobSF pointed here (the evidence)
    priority: int             # higher = analysed first


def _is_framework(path: str) -> bool:
    p = path.replace("\\", "/")
    return any(p.startswith(pre) for pre in _FRAMEWORK_PREFIXES)


def _parse_lines(val: Any) -> List[int]:
    """MobSF stores line pointers as a comma-joined string like "40,23,7"."""
    out: List[int] = []
    for tok in str(val or "").split(","):
        tok = tok.strip()
        if tok.isdigit():
            out.append(int(tok))
    return out


def _merge(cands: Dict[str, _Candidate], path: str, lines: List[int],
           reason: str, priority: int) -> None:
    """Accumulate candidates per file, keeping the highest priority + all lines."""
    if _is_framework(path) or not path.endswith(".java"):
        return
    cur = cands.get(path)
    if cur is None:
        cands[path] = _Candidate(path, sorted(set(lines)), reason, priority)
    else:
        cur.lines = sorted(set(cur.lines) | set(lines))
        if priority > cur.priority:
            cur.priority, cur.reason = priority, reason


# Permissions whose code is worth reading first (banking-trojan capabilities).
_SENSITIVE_PERMS = (
    "SMS", "ACCESSIBILITY", "SYSTEM_ALERT_WINDOW", "DEVICE_ADMIN", "CONTACTS",
    "CALL_LOG", "RECORD_AUDIO", "CAMERA", "PHONE_STATE", "BOOT_COMPLETED",
)
# android_api categories worth reading (skip pure noise like get_system_service).
_SENSITIVE_API = (
    "api_crypto", "api_tcp", "api_java_reflection", "api_ipc",
    "api_base64_decode", "api_local_file_io", "api_message_digest",
)


def _collect_candidates(static_json: Dict[str, Any]) -> List[_Candidate]:
    """Build the prioritised triage list from MobSF's file:line pointers."""
    cands: Dict[str, _Candidate] = {}

    # 1) code_analysis.findings — MobSF already flagged these (highest signal).
    findings = (static_json.get("code_analysis") or {}).get("findings") or {}
    if isinstance(findings, dict):
        for rule, body in findings.items():
            files = (body or {}).get("files") or {}
            if isinstance(files, dict):
                for path, lines in files.items():
                    _merge(cands, path, _parse_lines(lines),
                           f"code_analysis finding: {rule}", 100)

    # 2) permission_mapping — code that actually uses sensitive permissions.
    pmap = static_json.get("permission_mapping") or {}
    if isinstance(pmap, dict):
        for perm, files in pmap.items():
            sensitive = any(s in perm.upper() for s in _SENSITIVE_PERMS)
            if not isinstance(files, dict):
                continue
            for path, lines in files.items():
                _merge(cands, path, _parse_lines(lines),
                       f"uses permission {perm}", 90 if sensitive else 40)

    # 3) android_api — sensitive API usage sites.
    api = static_json.get("android_api") or {}
    if isinstance(api, dict):
        for cat, body in api.items():
            if cat not in _SENSITIVE_API:
                continue
            files = (body or {}).get("files") or {}
            if isinstance(files, dict):
                for path, lines in files.items():
                    _merge(cands, path, _parse_lines(lines),
                           f"android_api: {cat}", 70)

    # 4) behaviour — MobSF's behaviour engine pointers.
    behaviour = static_json.get("behaviour") or {}
    if isinstance(behaviour, dict):
        for bid, body in behaviour.items():
            meta = (body or {}).get("metadata") or {}
            label = ", ".join(meta.get("label", []) or []) or bid
            files = (body or {}).get("files") or {}
            if isinstance(files, dict):
                for path, lines in files.items():
                    _merge(cands, path, _parse_lines(lines),
                           f"behaviour: {label}", 60)

    ranked = sorted(cands.values(), key=lambda c: (c.priority, len(c.lines)), reverse=True)
    return ranked


# --------------------------------------------------------------------------- #
# Method-level slicing + 1 call-graph hop
# --------------------------------------------------------------------------- #

# Loose Java method-signature matcher (modifiers + return type + name + params).
_METHOD_RE = re.compile(
    r"^\s*(?:@\w+\s*)*"
    r"(?:public|private|protected|static|final|synchronized|native|abstract|default|\s)*"
    r"[\w$<>\[\].]+\s+([\w$]+)\s*\([^;{]*\)\s*(?:throws [\w$.,\s]+)?\{?\s*$"
)
_CALL_RE = re.compile(r"\b([a-z][\w$]*)\s*\(")
_NON_METHOD_NAMES = {"if", "for", "while", "switch", "catch", "return", "new"}


def _find_methods(source: str) -> Tuple[List[str], List[Tuple[int, int, str]]]:
    """Find top-level (class-member) method spans in a decompiled Java file.

    Returns ``(lines, [(start, end, name)])`` with 1-indexed inclusive spans.
    Brace counting is naive (good enough for clean decompiled code); a span is a
    block opened while at class-body depth 1 by a line matching a method
    signature, closed when depth returns to <=1.
    """
    lines = source.split("\n")
    methods: List[Tuple[int, int, str]] = []
    depth = 0
    cur_start: Optional[int] = None
    cur_name = ""
    seen_open = False
    for n, line in enumerate(lines, start=1):
        if cur_start is None and depth == 1:
            m = _METHOD_RE.match(line)
            if m and m.group(1) not in _NON_METHOD_NAMES:
                cur_start, cur_name, seen_open = n, m.group(1), False
        depth += line.count("{") - line.count("}")
        if cur_start is not None:
            if depth > 1:
                seen_open = True
            if seen_open and depth <= 1:
                methods.append((cur_start, n, cur_name))
                cur_start = None
    return lines, methods


def _method_for_line(methods: List[Tuple[int, int, str]], lineno: int
                     ) -> Optional[Tuple[int, int, str]]:
    for start, end, name in methods:
        if start <= lineno <= end:
            return (start, end, name)
    return None


def _slice_text(lines: List[str], span: Tuple[int, int, str], max_lines: int = 120) -> str:
    start, end, _ = span
    end = min(end, start + max_lines - 1)
    return "\n".join(lines[start - 1:end])


def _slice_for_candidate(source: str, cand: _Candidate
                         ) -> Tuple[str, str, str]:
    """Slice the enclosing method(s) for a candidate, plus 1 call-graph hop.

    Returns (method_name, location, code_text). Falls back to a line window when
    no enclosing method can be identified (obfuscated / unusual layout).
    """
    lines, methods = _find_methods(source)
    primary_line = cand.lines[0] if cand.lines else 1

    span = _method_for_line(methods, primary_line)
    if span is None:
        lo = max(1, primary_line - 12)
        hi = min(len(lines), primary_line + 25)
        window = "\n".join(lines[lo - 1:hi])
        return ("<unknown>", f"{cand.path}:{primary_line}", window)

    blocks: List[str] = [_slice_text(lines, span)]
    method_name = span[2]

    # One call-graph hop: pull bodies of helper methods this method calls that
    # are defined in the same file (so the model sees what decrypt()/send() do).
    primary_text = blocks[0]
    called = {m for m in _CALL_RE.findall(primary_text) if m not in _NON_METHOD_NAMES}
    by_name = {name: (s, e, name) for (s, e, name) in methods}
    hops = 0
    for name in called:
        if name == method_name or name not in by_name:
            continue
        blocks.append(f"// --- helper: {name}() ---\n" + _slice_text(lines, by_name[name], 60))
        hops += 1
        if hops >= 2:
            break

    location = f"{cand.path}:{primary_line}"
    return (method_name, location, "\n\n".join(blocks))


# --------------------------------------------------------------------------- #
# Step 3 — LLM interpretation of each slice
# --------------------------------------------------------------------------- #

_RE_SYSTEM = (
    "You are a senior Android reverse-engineer triaging DECOMPILED code for a "
    "bank's mobile-malware team. You are given one method (plus a couple of helper "
    "methods it calls) that a static scanner flagged. Explain what the code "
    "actually does, what sensitive data or APIs it touches, and whether it is "
    "benign, suspicious, or malicious. Be conservative: ordinary networking, "
    "logging, file I/O, Compose UI and standard crypto in a normal app are BENIGN. "
    "Only call something malicious when the code itself shows abuse (e.g. reading "
    "incoming SMS and forwarding it, driving an accessibility service to auto-click, "
    "drawing an overlay over another app, loading a downloaded DEX, running shell "
    "commands).\n"
    "Tag the behaviour using ONLY these canonical tags (choose the ones the code "
    "actually demonstrates, or an empty list): {tags}.\n"
    "Return ONLY a JSON object with exactly these keys: what_it_does, data_accessed, "
    "verdict, confidence, behaviour_tags, mitre_technique. "
    "'verdict' is one of benign|suspicious|malicious. 'confidence' is high|medium|low. "
    "'behaviour_tags' is an array drawn ONLY from the allowed tags above. "
    "'what_it_does' and 'data_accessed' are one sentence each. 'mitre_technique' is a "
    "MITRE ATT&CK Mobile technique id+name if one clearly applies, else an empty string."
)


def _interpret_slice(cand: _Candidate, method_name: str, location: str, code: str
                     ) -> Tuple[Optional[REFinding], Optional[str]]:
    """Send one slice to the LLM and parse a REFinding. Returns (finding, error)."""
    system = _RE_SYSTEM.format(tags=", ".join(capabilities.BEHAVIOUR_TAGS))
    class_name = cand.path[:-5].replace("/", ".") if cand.path.endswith(".java") else cand.path
    user = (
        f"Class: {class_name}\nMethod: {method_name}\n"
        f"Why flagged: {cand.reason}\n\n```java\n{code}\n```"
    )
    text, err = _generate(user, system, max_output_tokens=1024, json_mode=True)
    if err:
        return None, err
    obj, perr = _safe_json_loads(text)
    if perr or not isinstance(obj, dict):
        return None, (perr or "RE interpretation did not return a JSON object")

    allowed = set(capabilities.BEHAVIOUR_TAGS)
    raw_tags = obj.get("behaviour_tags") or []
    if isinstance(raw_tags, str):
        raw_tags = [raw_tags]
    tags = [t for t in raw_tags if isinstance(t, str) and t in allowed]

    verdict = str(obj.get("verdict", "benign")).strip().lower()
    if verdict not in ("benign", "suspicious", "malicious"):
        verdict = "suspicious"
    confidence = str(obj.get("confidence", "low")).strip().lower()
    if confidence not in ("high", "medium", "low"):
        confidence = "low"

    finding = REFinding(
        class_name=class_name,
        method=method_name,
        location=location,
        what_it_does=str(obj.get("what_it_does", "")).strip() or "(not provided)",
        data_accessed=str(obj.get("data_accessed", "")).strip() or "(not provided)",
        verdict=verdict,
        confidence=confidence,
        behaviour_tags=tags,
        mitre_technique=str(obj.get("mitre_technique", "")).strip(),
        evidence=cand.reason,
    )
    return finding, None


# --------------------------------------------------------------------------- #
# Verdict synthesis
# --------------------------------------------------------------------------- #


def _overall_verdict(constellation: List[str], code_band: Optional[str]) -> str:
    """Coarse family label from the CONFIRMED capabilities + code band."""
    cset = set(constellation)
    if {"otp_theft_combo"} & cset or ({"accessibility_abuse", "screen_overlay"} & cset
                                      and {"sms_access", "sms_send"} & cset):
        return "banking_trojan"
    if {"accessibility_abuse", "screen_overlay", "device_admin"} & cset:
        return "banking_trojan"
    if {"sms_access", "sms_send"} & cset:
        return "sms_fraud"
    if code_band in ("High", "Critical"):
        return "suspicious"
    return "benign"


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def reverse_engineer(
    apk_path: str,
    static_json: Dict[str, Any],
    report_dir: Optional[str] = None,
) -> ReverseEngineeringResult:
    """Decompile, triage, interpret, and score the Code-Behaviour side.

    Never raises: any failure degrades to a structured result whose
    ``re_coverage`` / ``llm_error`` explain what did not run. When RE cannot run
    at all (no jadx, decompilation failed, or the LLM produced no usable
    interpretation), ``code_score`` / ``code_band`` are None and ``mitre_map`` is
    ``{}`` so the fusion step falls back to the Feature-Store Score alone.
    """
    static_json = static_json or {}
    coverage: Dict[str, Any] = {
        "jadx_available": bool(shutil.which("jadx")),
        "ollama_available": _ollama_available(),
        "decompilation_quality": "failed",
        "candidates_triaged": 0,
        "methods_analyzed": 0,
        "llm_calls": 0,
        "notes": "",
    }

    if not os.path.isfile(apk_path):
        coverage["notes"] = f"APK not found: {apk_path}"
        return ReverseEngineeringResult(
            summary="Reverse engineering did not run (APK file missing).",
            re_coverage=coverage, llm_error=coverage["notes"],
        )

    if not coverage["jadx_available"]:
        coverage["notes"] = ("jadx not found on PATH — install it (`brew install jadx`) "
                             "to enable code-behaviour analysis.")
        return ReverseEngineeringResult(
            summary="Reverse engineering unavailable (jadx not installed); "
                    "verdict falls back to the Feature-Store Score.",
            re_coverage=coverage, llm_error=coverage["notes"],
        )

    # Persisted (stable) copy of the jadx resources subset for the SE detector.
    # Populated inside the temp-dir block below, BEFORE the temp dir is deleted.
    stable_resources: Optional[str] = None
    with tempfile.TemporaryDirectory(prefix="re_jadx_") as tmp:
        sources, resources, quality = _decompile(apk_path, tmp)
        coverage["decompilation_quality"] = quality
        # Copy strings.xml + layouts out of the temp dir before it is cleaned up.
        stable_resources = _persist_resources(resources, report_dir, apk_path)
        if sources is None:
            coverage["notes"] = "jadx produced no sources (decompilation failed)."
            return ReverseEngineeringResult(
                summary="Decompilation failed; verdict falls back to the "
                        "Feature-Store Score.",
                re_coverage=coverage, llm_error=coverage["notes"],
                resources_dir=stable_resources,
            )

        candidates = _collect_candidates(static_json)
        coverage["candidates_triaged"] = len(candidates)

        findings: List[REFinding] = []
        errors: List[str] = []
        analysed = 0
        for cand in candidates:
            if analysed >= MAX_METHODS:
                break
            src_path = os.path.join(sources, cand.path)
            if not os.path.isfile(src_path):
                continue
            try:
                with open(src_path, encoding="utf-8", errors="replace") as fh:
                    source = fh.read()
            except OSError:
                continue
            method_name, location, code = _slice_for_candidate(source, cand)
            if not code.strip():
                continue
            coverage["llm_calls"] += 1
            finding, err = _interpret_slice(cand, method_name, location, code)
            if err:
                errors.append(err)
                # If the very first calls all fail the LLM is likely down — stop.
                if coverage["llm_calls"] >= 2 and not findings:
                    break
                continue
            if finding is not None:
                findings.append(finding)
                analysed += 1

        coverage["methods_analyzed"] = analysed

    # Behaviour catalog = deduped canonical tags actually confirmed in code.
    catalog = sorted({t for f in findings for t in f.behaviour_tags})

    # No usable interpretation -> treat as "RE did not run" for scoring purposes.
    llm_error = "; ".join(dict.fromkeys(errors)) if errors else None
    if not findings and (llm_error or not coverage["ollama_available"]):
        coverage["notes"] = (coverage["notes"]
                             or "No code slices could be interpreted (LLM unavailable).")
        return ReverseEngineeringResult(
            findings=[], behaviour_catalog=[], code_score=None, code_band=None,
            mitre_map={}, verdict="unknown",
            summary="Code-behaviour analysis could not be completed; verdict "
                    "falls back to the Feature-Store Score.",
            re_coverage=coverage, llm_error=llm_error,
            resources_dir=stable_resources,
        )

    confirmed = capabilities.capabilities_from_behaviours(catalog)
    constellation = [cap_id for cap_id, _ in confirmed]
    code_score, _fired = capabilities.score_capabilities(confirmed)
    code_band = _band(code_score)
    mitre_map = capabilities.mitre_for(constellation)
    verdict = _overall_verdict(constellation, code_band)

    mal = sum(1 for f in findings if f.verdict == "malicious")
    susp = sum(1 for f in findings if f.verdict == "suspicious")
    summary = (
        f"Analysed {len(findings)} flagged method(s): {mal} malicious, {susp} "
        f"suspicious. Confirmed behaviours: {', '.join(catalog) or 'none'}. "
        f"Code-Behaviour band: {code_band} (score {code_score}, LLM-derived/indicative). "
        f"Verdict: {verdict}."
    )

    return ReverseEngineeringResult(
        findings=findings,
        behaviour_catalog=catalog,
        code_score=code_score,
        code_band=code_band,
        mitre_map=mitre_map,
        summary=summary,
        verdict=verdict,
        capability_constellation=constellation,
        re_coverage=coverage,
        llm_error=llm_error,
        resources_dir=stable_resources,
    )


# --------------------------------------------------------------------------- #
# __main__ self-test
# --------------------------------------------------------------------------- #


def main(argv: Optional[List[str]] = None) -> int:
    import json
    argv = argv if argv is not None else sys.argv[1:]
    here = os.path.dirname(os.path.abspath(__file__))
    apk = argv[0] if argv else os.path.join(here, "samples", "app-debug.apk")
    static_path = os.path.join(here, "reports", "app-debug.static.json")

    if not os.path.exists(static_path):
        print(f"Static report not found at {static_path} — cannot triage. Exiting cleanly.")
        return 0
    with open(static_path) as fh:
        static_json = json.load(fh)

    if not shutil.which("jadx"):
        print("jadx not installed — skipping live RE self-test (this is the "
              "graceful-degradation path). `brew install jadx` to enable. Exit 0.")
        res = reverse_engineer(apk, static_json)
        assert res.code_score is None and res.mitre_map == {}
        print(f"  degraded result: verdict={res.verdict}, note={res.re_coverage.get('notes')}")
        return 0
    if not _ollama_available():
        print(f"Ollama not reachable at {OLLAMA_URL} — skipping live RE "
              "self-test (graceful-degradation path). Exit 0.")
        return 0
    if not os.path.exists(apk):
        print(f"Sample APK not found at {apk} — cannot run live RE. Exit 0.")
        return 0

    print(f"Running reverse engineering on {apk} (jadx + Ollama present)...")
    res = reverse_engineer(apk, static_json)
    print("\n" + "=" * 64)
    print(f" CODE-BEHAVIOUR  verdict={res.verdict}  band={res.code_band}  "
          f"score={res.code_score} (LLM-derived, indicative)")
    print("=" * 64)
    print(f" decompilation : {res.re_coverage.get('decompilation_quality')}")
    print(f" triaged/analysed/llm_calls : {res.re_coverage.get('candidates_triaged')}/"
          f"{res.re_coverage.get('methods_analyzed')}/{res.re_coverage.get('llm_calls')}")
    print(f" behaviour catalog : {res.behaviour_catalog or '(none)'}")
    print(f" MITRE map        : {res.mitre_map or '{}'}")
    print(f" llm_error        : {res.llm_error}")
    print("\n Findings:")
    for f in res.findings:
        print(f"   [{f.verdict}/{f.confidence}] {f.class_name}.{f.method}  ({f.location})")
        print(f"       {f.what_it_does}")
        if f.behaviour_tags:
            print(f"       tags: {', '.join(f.behaviour_tags)}")
    print("=" * 64)

    # Acceptance: the bundled app-debug is BENIGN — no banking-trojan behaviours.
    banking = {"intercept_sms", "abuse_accessibility", "screen_overlay", "send_sms"}
    leaked = banking & set(res.behaviour_catalog)
    if leaked:
        print(f"\nWARNING: benign sample produced banking-trojan tags {leaked} — "
              "the LLM over-called (the exact Code-Behaviour score is advisory).")
    else:
        print("\nOK: benign sample — no SMS/accessibility/overlay behaviours confirmed.")
    assert res.verdict != "banking_trojan", "benign app-debug must not be a banking_trojan"
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
