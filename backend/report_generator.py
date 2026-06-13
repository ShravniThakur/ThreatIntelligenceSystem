"""
report_generator.py — final GenAI incident report.
==================================================

The terminal step of the pipeline. It does NOT compute any new signal; it SYNTHESISES
the outputs of every component already in the assembled result dict — the two scores +
fusion verdict, reverse-engineering findings, social-engineering, intent-spoofing,
DNA family similarity, campaign links, and the (prototype) ML classifier — into a
single, well-structured incident report for a bank fraud-investigation team.

Uses the same local Ollama model the rest of the pipeline uses (via
``reverse_engineer._generate``). Never raises: if Ollama is unavailable the report
block comes back with ``markdown=None`` and an ``error``, and the pipeline finishes
normally (the deterministic scores and all component panels are unaffected).

Entry point
-----------
    generate_report(result: dict) -> dict
        {"markdown": str|None, "model": str, "generated_at": iso, "error": str|None}
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from reverse_engineer import _generate, _ollama_available, OLLAMA_MODEL


_SYSTEM = (
    "You are a senior mobile-threat analyst writing the FINAL, DETAILED incident report "
    "for an Indian bank's fraud-investigation team. You are given the distilled outputs of "
    "an automated APK analysis pipeline; synthesise them into a thorough, well-explained "
    "report in GitHub-flavoured Markdown.\n\n"
    "Ground rules:\n"
    "- The deterministic Feature-Store Score and the fusion verdict are AUTHORITATIVE — "
    "lead with them. The Code-Behaviour score is LLM-derived and advisory.\n"
    "- Be strictly evidence-based: cite only the concrete signals given; never invent "
    "capabilities, families, behaviours, package names, or numbers not present in the data. "
    "Explaining and interpreting the given evidence is encouraged; fabricating new evidence "
    "is not.\n"
    "- The ML classification is a PROTOTYPE trained on SYNTHETIC data — mention it only as "
    "an experimental cross-check, never as a basis for the verdict.\n"
    "- Do NOT invent or include a calendar date — the report timestamp is recorded "
    "separately.\n"
    "- Write for the Indian banking context (UPI / netbanking / OTP fraud, RBI/NPCI "
    "impersonation, credential and SMS-OTP theft).\n\n"
    "DEPTH — this is the most important instruction. Do not just list signals; EXPLAIN them. "
    "For every significant capability, behaviour, MITRE technique, and finding, write 1-3 "
    "sentences covering: (a) what it is in plain language, (b) the specific evidence that "
    "fired it (quote the evidence string / counts), and (c) why it matters to a bank's fraud "
    "team and how an attacker could abuse it against customers. Connect related signals into "
    "a coherent narrative of what this app appears designed to do. Where evidence is present, "
    "each major section should be several sentences to a few paragraphs — be comprehensive, "
    "but every sentence must be grounded in the brief (no filler).\n\n"
    "Use these sections (omit one only if there is genuinely no data for it; otherwise write "
    "it out, and if a section truly has no signal, say so AND briefly explain what its absence "
    "means):\n"
    "1. **Verdict & Recommended Action** — fused verdict, recommended action, and a full "
    "rationale paragraph tying together the scores and the strongest evidence.\n"
    "2. **Risk Scores** — Feature-Store Score/band, Code-Behaviour band, fusion quadrant, and "
    "what each means and why they landed where they did.\n"
    "3. **Key Evidence** — walk through the most important declared capabilities, "
    "code-confirmed behaviours, and MITRE techniques, EXPLAINING each (what / evidence / why "
    "it matters) rather than just listing them.\n"
    "4. **Capability Gap** — behaviours confirmed in code but not declared (and vice-versa), "
    "and why that mismatch is or isn't concerning.\n"
    "5. **Social Engineering** — fraud-UI findings and the techniques they use against users, "
    "if any.\n"
    "6. **Impersonation** — whether it forges a known bank app, with the certificate/package "
    "reasoning.\n"
    "7. **Malware DNA & Campaign** — family similarity (and what that family typically does) "
    "and links to other analysed APKs.\n"
    "8. **ML Classification (prototype)** — experimental label cross-check, clearly disclaimed.\n"
    "9. **Analyst Recommendation** — concrete, prioritised next steps for the fraud team "
    "(specific classes/methods to inspect, indicators to monitor, containment actions).\n\n"
    "Open with a short **Executive Summary** paragraph before section 1 so a busy investigator "
    "grasps the verdict immediately, then provide the full detailed analysis below. Do not echo "
    "these instructions."
)


# --------------------------------------------------------------------------- #
# Distil the assembled result into a compact, focused brief for the model
# --------------------------------------------------------------------------- #


def _distill(r: Dict[str, Any]) -> str:
    """Turn the (verbose) result dict into a compact text brief for the LLM."""
    L: List[str] = []
    g = r.get

    # Identity
    L.append("## APK")
    L.append(f"- file: {g('apk_filename') or g('apk_hash', '')}")
    L.append(f"- package: {g('package_name', '(unknown)')}")
    L.append(f"- sha256: {g('apk_hash', '')}")

    # Verdict + scores
    L.append("\n## Scores & verdict")
    L.append(f"- Feature-Store Score: {g('fs_score')}/100 ({g('fs_band')})  [deterministic, authoritative]")
    code_band = g('code_band')
    L.append(f"- Code-Behaviour band: {code_band if code_band else 'N/A (reverse engineering did not run)'}"
             f"  [LLM-derived, advisory]")
    L.append(f"- Fusion quadrant: {g('quadrant', '—')}")
    L.append(f"- Recommended action: {g('recommended_action', '—')}")
    if g('reasoning'):
        L.append(f"- Fusion reasoning: {g('reasoning')}")

    # Fired capabilities (top by weight)
    fired = g('fired_rules') or []
    if fired:
        top = sorted(fired, key=lambda x: x.get('weight', 0), reverse=True)[:10]
        L.append("\n## Declared capabilities (feature-store, top by weight)")
        for f in top:
            mitre = f" [{f.get('mitre')}]" if f.get('mitre') else ""
            L.append(f"- {f.get('capability')} (+{f.get('weight')}){mitre} — {f.get('evidence', '')}")

    # Reverse engineering
    if code_band is not None:
        L.append("\n## Code-behaviour (reverse engineering)")
        L.append(f"- RE verdict: {g('re_verdict', 'unknown')}")
        cat = g('behaviour_catalog') or []
        L.append(f"- Confirmed behaviours: {', '.join(cat) if cat else 'none'}")
        mitre_map = g('mitre_map') or {}
        if mitre_map:
            techs = "; ".join(f"{tac}: {', '.join(v)}" for tac, v in mitre_map.items())
            L.append(f"- MITRE (code-confirmed): {techs}")
        gap = g('capability_gap') or {}
        if gap.get('re_only'):
            L.append(f"- Found in code but NOT declared (interesting): {', '.join(gap['re_only'])}")
        if gap.get('declared_only'):
            L.append(f"- Declared by features but NOT confirmed in code (over-permissioned/latent): "
                     f"{', '.join(gap['declared_only'])}")
        findings = g('re_findings') or []
        flagged = [f for f in findings if f.get('verdict') in ('malicious', 'suspicious')][:10]
        for f in flagged:
            tags = ", ".join(f.get('behaviour_tags') or [])
            L.append(f"  - [{f.get('verdict')}/{f.get('confidence', '?')}] "
                     f"{f.get('class_name')}.{f.get('method')}: {f.get('what_it_does', '')}"
                     + (f" | data accessed: {f.get('data_accessed')}" if f.get('data_accessed') else "")
                     + (f" | tags: {tags}" if tags else ""))

    # Social engineering
    se_verdict = g('se_verdict')
    if se_verdict and se_verdict not in ('clean', 'unknown'):
        L.append("\n## Social engineering")
        L.append(f"- verdict: {se_verdict} ({g('se_band')}), {len(g('se_findings') or [])} finding(s)")
        for f in (g('se_findings') or [])[:6]:
            L.append(f"  - [{f.get('technique')}] \"{f.get('text', '')}\" — {f.get('explanation', '')}")
    elif se_verdict:
        L.append(f"\n## Social engineering\n- {se_verdict} (no fraud-UI strings flagged)")

    # Impersonation
    imp = g('impersonation') or {}
    if imp.get('is_impersonation'):
        L.append("\n## Impersonation (DEFINITIVE)")
        L.append(f"- Impersonates {imp.get('target_app')} ({imp.get('target_bank')}); "
                 f"genuine package {imp.get('genuine_package')} vs this {imp.get('actual_package')}; "
                 f"signing certificate MISMATCH.")
    else:
        L.append("\n## Impersonation\n- No impersonation of any known bank app detected.")

    # DNA + campaign
    dna = g('dna') or {}
    if dna.get('fingerprinted') and dna.get('reference_size'):
        L.append("\n## Malware DNA")
        L.append(f"- Closest family: {dna.get('top_family')} "
                 f"({round((dna.get('top_similarity') or 0) * 100)}% structural, {dna.get('band')})")
        if dna.get('tlsh_clone'):
            L.append(f"- DEX byte-clone of a known {dna.get('tlsh_nearest_family')} sample "
                     f"(TLSH distance {dna.get('tlsh_distance')}) — likely a repackage.")
    camp = g('campaign') or {}
    if camp.get('is_campaign'):
        L.append("\n## Campaign")
        L.append(f"- Linked to {camp.get('size', 1) - 1} other analysed APK(s) in cluster "
                 f"{camp.get('campaign_id')}.")
        for e in (camp.get('links') or [])[:5]:
            L.append(f"  - {e.get('other_package') or e.get('other_hash', '')[:16]}: "
                     f"{', '.join(e.get('reasons') or [])}")

    # ML classifier (prototype)
    ml = g('ml_classification') or {}
    if ml.get('available'):
        preds = ml.get('predicted') or []
        L.append("\n## ML classifier (PROTOTYPE — synthetic training data, experimental)")
        L.append(f"- Predicted: {', '.join(preds) if preds else 'none above threshold'} "
                 f"(top: {ml.get('top_label')} {round((ml.get('top_probability') or 0) * 100)}%)")

    return "\n".join(L)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def generate_report(result: Dict[str, Any]) -> Dict[str, Any]:
    """Synthesise the assembled result into a Markdown incident report. Never raises."""
    meta = {"markdown": None, "model": OLLAMA_MODEL,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "error": None}
    try:
        if not _ollama_available():
            meta["error"] = "Ollama unavailable — report not generated"
            return meta
        brief = _distill(result or {})
        # Wide context so the (long) detailed report isn't truncated by the brief.
        text, err = _generate(brief, _SYSTEM, max_output_tokens=4096, json_mode=False,
                              num_ctx=8192)
        if err:
            meta["error"] = err
            return meta
        meta["markdown"] = (text or "").strip() or None
        if meta["markdown"] is None:
            meta["error"] = "empty report from model"
        return meta
    except Exception as exc:  # noqa: BLE001 - report generation must never crash the job
        meta["error"] = f"report generation failed: {exc}"
        return meta


# --------------------------------------------------------------------------- #
# __main__ — render a report from a saved result.json
# --------------------------------------------------------------------------- #


def main() -> int:
    import json
    import os
    import sys
    argv = sys.argv[1:]
    if not argv:
        print("usage: python report_generator.py reports/<hash>.result.json")
        return 0
    if not os.path.exists(argv[0]):
        print(f"Not found: {argv[0]}")
        return 0
    with open(argv[0], encoding="utf-8") as fh:
        result = json.load(fh)
    rep = generate_report(result)
    if rep["error"]:
        print(f"[error] {rep['error']}")
        print("\n--- distilled brief that WOULD be sent ---\n")
        print(_distill(result))
        return 0
    print(rep["markdown"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
