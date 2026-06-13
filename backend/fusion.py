"""
fusion.py
=========

The terminal step: ANALYSE the two scores against each other and emit the final
verdict. This is deterministic — it takes the (deterministic) Feature-Store Score
and the (LLM-derived) Code-Behaviour Score and reasons over them **by band, not by
exact value**, because the code band is advisory and may wobble between runs.

``analyse_scores(fs_result, re_result) -> FusionResult``

Quadrant logic (FS = what the app declares, CODE = what the code was confirmed to
do):

    CODE High  &  FS Low/Med   -> "declares little but does something in code":
                                   obfuscated / dynamically-loaded payload — the
                                   hardest case. action = block.
    FS High    &  CODE Low/Med  -> dangerous capability declared but RE did not
                                   confirm it exercised: over-permissioned.
                                   action = monitor.
    Both High                   -> genuine threat. action = block.
    Both Low                    -> benign. action = clear.
    Borderline / conflicting near a band boundary -> escalate_manual_review.
    Otherwise (low-grade, neither High) -> monitor.

If the Code-Behaviour side is unavailable (``re_result.code_band is None`` —
jadx/LLM missing or RE degraded), fall back to the **Feature-Store Score alone**:
Critical->block, High->escalate, Medium->monitor, Low->clear, and set
``re_unavailable=True`` with a note.

Also computes a ``capability_gap``: capabilities declared by features but not
confirmed by RE (``declared_only`` — over-permissioning), confirmed by RE but not
declared by features (``re_only`` — code does something no feature flagged, the
most interesting), and ``confirmed_both``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# Band -> ordinal rank, so "compare by band" is a simple integer comparison.
_RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
_HIGH_BOUNDARY = 50           # the Medium/High cut
_BOUNDARY_WINDOW = 5          # +/- points that count as "near a band boundary"


@dataclass
class FusionResult:
    """The terminal, human-readable verdict from analysing both scores."""

    fs_score: int
    fs_band: str
    code_score: Optional[int]
    code_band: Optional[str]
    quadrant: str
    recommended_action: str               # block | monitor | clear | escalate_manual_review
    reasoning: str
    capability_gap: Dict[str, List[str]] = field(default_factory=dict)
    re_unavailable: bool = False


def _rank(band: Optional[str]) -> int:
    return _RANK.get(band or "Low", 0)


def _near_boundary(score: Optional[int]) -> bool:
    """True if a score sits within the window straddling the Medium/High cut."""
    if score is None:
        return False
    return abs(int(score) - _HIGH_BOUNDARY) <= _BOUNDARY_WINDOW


def _capability_gap(fs_result: Any, re_result: Any) -> Dict[str, List[str]]:
    """Compare declared (feature) vs confirmed (RE) capabilities."""
    declared = set(getattr(fs_result, "capabilities", []) or [])
    confirmed = set(getattr(re_result, "capability_constellation", []) or [])
    return {
        # Declared by features, NOT confirmed in code -> over-permissioned / latent.
        "declared_only": sorted(declared - confirmed),
        # Confirmed in code, NOT declared by any feature -> the interesting gap.
        "re_only": sorted(confirmed - declared),
        # Agreed by both lenses -> high-confidence capabilities.
        "confirmed_both": sorted(declared & confirmed),
    }


def analyse_scores(fs_result: Any, re_result: Any) -> FusionResult:
    """Fuse the Feature-Store and Code-Behaviour scores into a terminal verdict.

    ``fs_result`` is a risk_scorer.ScoringResult (needs ``score``, ``risk_band``,
    ``capabilities``). ``re_result`` is a reverse_engineer.ReverseEngineeringResult
    (needs ``code_score``, ``code_band``, ``capability_constellation``); when
    ``code_band`` is None the Code-Behaviour side did not run.
    """
    fs_score = int(getattr(fs_result, "score", 0) or 0)
    fs_band = getattr(fs_result, "risk_band", "Low") or "Low"
    code_score = getattr(re_result, "code_score", None)
    code_band = getattr(re_result, "code_band", None)
    gap = _capability_gap(fs_result, re_result)

    # ---- RE unavailable: Feature-Store-Score-only fallback ----------------- #
    if code_band is None:
        action = {
            "Critical": "block",
            "High": "escalate_manual_review",
            "Medium": "monitor",
            "Low": "clear",
        }.get(fs_band, "escalate_manual_review")
        note = getattr(re_result, "re_coverage", {}) or {}
        why = note.get("notes") or "code-behaviour analysis did not run"
        reasoning = (
            f"Code-behaviour analysis is unavailable ({why}). Falling back to the "
            f"deterministic Feature-Store Score alone: {fs_score}/100 ({fs_band}) "
            f"-> {action}. The deterministic right-hand side carries the result, as "
            f"designed."
        )
        return FusionResult(
            fs_score=fs_score, fs_band=fs_band, code_score=None, code_band=None,
            quadrant="fs_only", recommended_action=action, reasoning=reasoning,
            capability_gap=gap, re_unavailable=True,
        )

    # ---- Both scores available: compare BY BAND ---------------------------- #
    fs_rank, code_rank = _rank(fs_band), _rank(code_band)
    fs_high, code_high = fs_rank >= 2, code_rank >= 2
    both_low = fs_rank == 0 and code_rank == 0
    re_only = gap["re_only"]
    # Conflicting AND fragile: the two lenses land in different bands and BOTH
    # scores hug the Medium/High cut, so the High classification itself is
    # marginal on both sides. Too ambiguous to action automatically.
    conflicting_boundary = (
        fs_rank != code_rank
        and _near_boundary(fs_score) and _near_boundary(code_score)
    )

    if conflicting_boundary:
        quadrant, action = "borderline", "escalate_manual_review"
        reasoning = (
            f"The two lenses conflict right at the Medium/High boundary "
            f"(Feature-Store {fs_score}/100 {fs_band}, Code-Behaviour {code_score} "
            f"{code_band}). The High call is marginal on both sides and they "
            f"disagree — escalate for manual review rather than auto-deciding."
        )
    elif fs_high and code_high:
        quadrant, action = "confirmed_threat", "block"
        reasoning = (
            f"Both lenses agree this is dangerous: features declare it "
            f"({fs_score}/100 {fs_band}) AND reverse-engineering confirmed the "
            f"behaviour in code ({code_band} band). Confirmed capabilities: "
            f"{', '.join(gap['confirmed_both']) or 'see catalog'}."
        )
    elif code_high and not fs_high:
        quadrant, action = "hidden_payload", "block"
        reasoning = (
            f"The app DECLARES little ({fs_score}/100 {fs_band}) but the code DOES "
            f"something: reverse-engineering reached the {code_band} band"
            + (f", finding capabilities no feature flagged: {', '.join(re_only)}"
               if re_only else "")
            + ". This is the obfuscated / dynamically-loaded-payload case the "
            "two-score design exists to catch — treat with high attention."
        )
    elif fs_high and not code_high:
        quadrant, action = "over_permissioned", "monitor"
        reasoning = (
            f"A dangerous capability is DECLARED ({fs_score}/100 {fs_band}) but "
            f"reverse-engineering did not confirm it exercised in code ({code_band} "
            f"band). Likely over-permissioned rather than actively malicious; "
            f"monitor. Declared-but-unconfirmed: "
            f"{', '.join(gap['declared_only']) or 'none'}."
        )
    elif both_low:
        quadrant, action = "benign", "clear"
        reasoning = (
            f"Both lenses are quiet: Feature-Store {fs_score}/100 ({fs_band}) and "
            f"Code-Behaviour {code_band} band. No dangerous capability declared or "
            f"confirmed — benign."
        )
    elif _near_boundary(fs_score) or _near_boundary(code_score):
        quadrant, action = "borderline", "escalate_manual_review"
        reasoning = (
            f"Scores sit near the Medium/High boundary (Feature-Store {fs_score}/100 "
            f"{fs_band}, Code-Behaviour {code_score} {code_band}). Too close to call "
            f"automatically — escalate for manual review."
        )
    else:
        # Neither High, not both Low, not near a boundary -> low-grade concern.
        quadrant, action = "low_grade", "monitor"
        reasoning = (
            f"Low-grade signals only: Feature-Store {fs_score}/100 ({fs_band}), "
            f"Code-Behaviour {code_band} band. No high-severity capability declared "
            f"or confirmed in code"
            + (f"; code-only behaviours noted: {', '.join(re_only)}" if re_only else "")
            + ". Monitor."
        )

    return FusionResult(
        fs_score=fs_score, fs_band=fs_band, code_score=code_score, code_band=code_band,
        quadrant=quadrant, recommended_action=action, reasoning=reasoning,
        capability_gap=gap, re_unavailable=False,
    )


# --------------------------------------------------------------------------- #
# __main__ self-test (pure logic; no MobSF / jadx / LLM needed)
# --------------------------------------------------------------------------- #


@dataclass
class _FS:                      # minimal stand-ins matching the real dataclasses
    score: int
    risk_band: str
    capabilities: List[str] = field(default_factory=list)


@dataclass
class _RE:
    code_score: Optional[int]
    code_band: Optional[str]
    capability_constellation: List[str] = field(default_factory=list)
    re_coverage: Dict[str, Any] = field(default_factory=dict)


def _check(name: str, fr: FusionResult, expect_action: str) -> bool:
    ok = fr.recommended_action == expect_action
    flag = "OK " if ok else "FAIL"
    print(f"  [{flag}] {name:<28} quadrant={fr.quadrant:<18} action={fr.recommended_action} "
          f"(expected {expect_action})")
    return ok


def main() -> int:
    import json
    here = os.path.dirname(os.path.abspath(__file__))
    ok = True

    # 1) Real benign app-debug FS + None RE -> FS-only fallback (Medium -> monitor).
    try:
        import risk_scorer
        static_path = os.path.join(here, "reports", "app-debug.static.json")
        with open(static_path) as fh:
            static_json = json.load(fh)
        row = risk_scorer._load_feature_row("app-debug.apk")
        fs_real = risk_scorer.score(row, static_json)
        fr = analyse_scores(fs_real, _RE(None, None, [], {"notes": "RE not run"}))
        ok &= _check("app-debug FS-only", fr, "monitor")
        assert fr.re_unavailable and fr.recommended_action != "block"
    except Exception as exc:  # noqa: BLE001
        print(f"  (skipped real app-debug check: {exc})")

    # 2) Truly-Low benign FS + benign Low RE -> clear.
    fr = analyse_scores(_FS(10, "Low", []), _RE(0, "Low", []))
    ok &= _check("both Low (benign)", fr, "clear")

    # 3) Benign FS + None RE where FS is Low -> clear (FS-only fallback).
    fr = analyse_scores(_FS(12, "Low", []), _RE(None, None, [], {"notes": "no jadx"}))
    ok &= _check("Low FS, RE unavailable", fr, "clear")
    assert fr.re_unavailable

    # 4) Hidden payload: FS Low/Med, CODE High -> block.
    fr = analyse_scores(_FS(20, "Low", []),
                        _RE(70, "High", ["dynamic_code_load", "shell_exec"]))
    ok &= _check("hidden payload (code High)", fr, "block")
    assert fr.capability_gap["re_only"] == ["dynamic_code_load", "shell_exec"]

    # 5) Over-permissioned: FS High, CODE Low -> monitor.
    fr = analyse_scores(_FS(60, "High", ["device_admin", "sms_access"]),
                        _RE(5, "Low", []))
    ok &= _check("over-permissioned (FS High)", fr, "monitor")

    # 6) Both High -> block.
    fr = analyse_scores(_FS(80, "Critical", ["otp_theft_combo"]),
                        _RE(85, "Critical", ["otp_theft_combo"]))
    ok &= _check("both High (confirmed)", fr, "block")

    # 7) Borderline near the 50 boundary -> escalate_manual_review.
    fr = analyse_scores(_FS(48, "Medium", []), _RE(52, "High", ["reflection"]))
    ok &= _check("borderline @ boundary", fr, "escalate_manual_review")

    print("\nfusion.py self-test:", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
