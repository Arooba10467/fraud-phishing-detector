"""
Combines rule-based URL checks + LLM message analysis into one overall
risk score, and generates a ready-to-send fraud report draft.

Weighting philosophy (per the proposal): rule-based checks are treated as
hard, explainable signals and the LLM score is a softer, contextual signal.
Neither is allowed to silently cancel the other out: if EITHER signal is
confident this is a scam, the overall score reflects that. Rule-based
checks alone can't catch every scam domain (new shorteners, unlisted
brands), so a high-confidence LLM read (clear urgency/impersonation
language) must be able to drive the score to "High Risk" on its own,
not get capped at a fraction of its value just because no link-level
red flag happened to fire.
"""

from datetime import datetime, timezone

# Points added per flagged rule-based signal
RULE_WEIGHTS = {
    "typosquatting": 30,
    "domain_age": 20,
    "ssl": 20,
    "structure": 15,
}


def compute_overall_risk(url_check_results: list[dict], llm_result: dict) -> dict:
    """
    url_check_results: list of dicts from checks.run_all_url_checks() (one per URL)
    llm_result: dict from llm_analysis.analyze_message_with_llm()
    """
    rule_score = 0
    rule_reasons = []

    for result in url_check_results:
        for check_name, weight in RULE_WEIGHTS.items():
            check = result.get(check_name, {})
            if check.get("flagged"):
                rule_score += weight
                reason = check.get("reason") or "; ".join(check.get("reasons", []))
                rule_reasons.append(f"[{result['url']}] {reason}")

    rule_score = min(rule_score, 100)

    llm_score = llm_result.get("risk_score", 0) if llm_result.get("ok") else 0

    # Take the stronger of the two signals as the base, then add a smaller
    # bonus when both agree — this way a confident LLM read on its own can
    # still reach "High Risk" instead of being diluted by a quiet rule-based
    # score, while agreement between both signals still counts for something.
    overall = max(rule_score, llm_score)
    overall += round(0.2 * min(rule_score, llm_score))
    overall = min(100, overall)

    if overall >= 70:
        verdict = "High Risk"
    elif overall >= 35:
        verdict = "Suspicious"
    else:
        verdict = "Likely Safe"

    return {
        "overall_score": overall,
        "verdict": verdict,
        "rule_based_reasons": rule_reasons,
        "llm_red_flags": llm_result.get("red_flags", []),
        "llm_explanation": llm_result.get("explanation", ""),
        "language_detected": llm_result.get("language_detected", "Unknown"),
    }


def generate_fraud_report(message_text: str, urls: list[str], risk_summary: dict,
                           impersonated_org: str = "") -> str:
    """Produces a plain-text draft the user can copy/paste or download to send to PTA / the bank."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "SUSPECTED FRAUD / PHISHING REPORT",
        f"Generated: {timestamp}",
        "",
        f"Risk Assessment: {risk_summary['verdict']} ({risk_summary['overall_score']}/100)",
        f"Detected Language: {risk_summary.get('language_detected', 'Unknown')}",
        "",
        "Message Content (as received):",
        "-" * 40,
        message_text.strip(),
        "-" * 40,
        "",
    ]

    if impersonated_org:
        lines.append(f"Organization Impersonated (claimed): {impersonated_org}")
        lines.append("")

    if urls:
        lines.append("Suspicious Link(s):")
        for u in urls:
            lines.append(f"  - {u}")
        lines.append("")

    if risk_summary.get("rule_based_reasons"):
        lines.append("Technical Red Flags Detected:")
        for r in risk_summary["rule_based_reasons"]:
            lines.append(f"  - {r}")
        lines.append("")

    if risk_summary.get("llm_red_flags"):
        lines.append("Content/Language Red Flags Detected:")
        for r in risk_summary["llm_red_flags"]:
            lines.append(f"  - {r}")
        lines.append("")

    if risk_summary.get("llm_explanation"):
        lines.append("Summary:")
        lines.append(risk_summary["llm_explanation"])
        lines.append("")

    lines.append(
        "This report was generated with the assistance of an automated screening "
        "tool and should be treated as risk-screening, not a definitive verdict. "
        "Please forward this to PTA (via the PTA CMS complaint portal) and/or the "
        "impersonated organization's official fraud-reporting channel."
    )

    return "\n".join(lines)
