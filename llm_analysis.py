"""
LLM-powered analysis of message tone, urgency, and impersonation cues.

Uses the Groq API (fast inference for open models like Llama), which is
OpenAI-compatible — so we call it using the standard `openai` Python
client, just pointed at Groq's base URL.

On Hugging Face Spaces, set your key as a Secret named GROQ_API_KEY in the
Space settings (Settings -> Variables and secrets). Never hardcode it.
"""

import os
import json

SYSTEM_PROMPT = """You are a fraud/phishing detection assistant for messages sent to \
people in Pakistan. Messages may be in English, Urdu (Urdu script), or Roman Urdu \
(Urdu written in Latin letters, e.g. "aap ka account block ho jaye ga"). You will be \
given a raw SMS or WhatsApp message. Analyze it for social-engineering and phishing \
patterns such as:
- urgency / threats ("account will be blocked", "act within 1 hour")
- impersonation of a bank, telecom, or government body (JazzCash, Easypaisa, HBL, \
UBL, PTA, FBR, NADRA, etc.)
- requests for OTP, PIN, CNIC, or account credentials
- promises of prizes, lottery wins, or unrealistic rewards
- suspicious sender claims (e.g. "official" numbers that don't match real short codes)

Respond ONLY with a single JSON object, no preamble, no markdown fences, in exactly \
this shape:

{
  "risk_score": <integer 0-100, your estimate of how likely this is a scam>,
  "language_detected": "<English | Urdu | Roman Urdu | Mixed>",
  "red_flags": ["<short phrase>", ...],
  "explanation": "<2-3 sentence plain-language explanation for a non-technical user>"
}

If the message shows no scam indicators, return a low risk_score and an empty \
red_flags list. Never invent red flags that aren't actually present in the text."""


def analyze_message_with_llm(message_text: str) -> dict:
    """
    Calls the Groq API to analyze message tone/context.
    Returns a dict matching the JSON contract above, or an error dict.
    """
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return {
            "ok": False,
            "reason": "No GROQ_API_KEY set. Add it as a Secret in your "
                      "Hugging Face Space settings (or a local env var for testing).",
        }

    raw_text = ""
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")

        response = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            max_tokens=500,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": message_text},
            ],
        )

        raw_text = response.choices[0].message.content.strip()

        # Strip accidental markdown fences just in case
        raw_text = raw_text.replace("```json", "").replace("```", "").strip()

        parsed = json.loads(raw_text)
        parsed["ok"] = True
        return parsed

    except json.JSONDecodeError:
        return {"ok": False, "reason": "LLM did not return valid JSON.", "raw": raw_text}
    except Exception as e:
        return {"ok": False, "reason": f"LLM call failed: {e}"}
