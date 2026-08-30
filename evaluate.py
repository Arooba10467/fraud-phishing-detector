"""
Evaluation script: runs the full detection pipeline (rule-based checks +
LLM analysis) against test_data/test_messages.py and reports accuracy.

Usage:
    export GROQ_API_KEY=your_key_here
    python evaluate.py

Requires network access (WHOIS/SSL checks + Groq API calls), so run this
somewhere with internet — Colab, your local machine, or after deployment.
"""

import sys
import time

from checks import extract_urls, run_all_url_checks
from llm_analysis import analyze_message_with_llm
from scoring import compute_overall_risk
from test_data.test_messages import TEST_MESSAGES


def classify(message_text: str, impersonated_org: str) -> tuple[bool, int]:
    """Returns (predicted_is_scam, risk_score) for one message."""
    urls = extract_urls(message_text)
    url_check_results = [run_all_url_checks(u) for u in urls]
    llm_result = analyze_message_with_llm(message_text)
    risk_summary = compute_overall_risk(url_check_results, llm_result)

    # Treat "Suspicious" and "High Risk" both as a positive (scam) prediction —
    # matches the app's own red/orange vs green banner split.
    predicted_scam = risk_summary["overall_score"] >= 35
    return predicted_scam, risk_summary["overall_score"]


def main():
    results = []
    print(f"Running evaluation on {len(TEST_MESSAGES)} test messages...\n")

    for i, (message, org, is_scam, category) in enumerate(TEST_MESSAGES, 1):
        predicted_scam, score = classify(message, org)
        correct = predicted_scam == is_scam
        results.append({
            "category": category,
            "actual": is_scam,
            "predicted": predicted_scam,
            "score": score,
            "correct": correct,
        })
        status = "✓" if correct else "✗ MISS"
        print(f"[{i}/{len(TEST_MESSAGES)}] {status}  "
              f"actual={'SCAM' if is_scam else 'safe':5s}  "
              f"predicted={'SCAM' if predicted_scam else 'safe':5s}  "
              f"score={score:3d}  ({category})")
        time.sleep(1)  # be gentle on the free-tier Groq rate limit

    # --- Overall metrics ---
    total = len(results)
    correct_count = sum(r["correct"] for r in results)
    accuracy = correct_count / total * 100

    true_positives = sum(1 for r in results if r["actual"] and r["predicted"])
    false_positives = sum(1 for r in results if not r["actual"] and r["predicted"])
    false_negatives = sum(1 for r in results if r["actual"] and not r["predicted"])
    true_negatives = sum(1 for r in results if not r["actual"] and not r["predicted"])

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) else 0

    print("\n" + "=" * 60)
    print(f"ACCURACY: {correct_count}/{total} ({accuracy:.1f}%)")
    print(f"PRECISION: {precision:.2f}  (of messages flagged as scam, how many really were)")
    print(f"RECALL: {recall:.2f}  (of actual scams, how many were caught)")
    print(f"\nConfusion matrix:")
    print(f"  True Positives (scam correctly caught):     {true_positives}")
    print(f"  False Positives (safe wrongly flagged):     {false_positives}")
    print(f"  False Negatives (scam missed):               {false_negatives}")
    print(f"  True Negatives (safe correctly passed):      {true_negatives}")

    # --- Per-category breakdown ---
    print(f"\nMisses by category:")
    misses = [r for r in results if not r["correct"]]
    if misses:
        for r in misses:
            print(f"  - {r['category']}: actual={r['actual']}, predicted={r['predicted']}, score={r['score']}")
    else:
        print("  None — all test messages classified correctly.")


if __name__ == "__main__":
    main()
