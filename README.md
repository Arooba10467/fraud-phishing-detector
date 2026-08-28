# SMS/WhatsApp Fraud & Phishing Detector

AI-augmented fraud/phishing message detector for Pakistan. Paste a suspicious
SMS/WhatsApp message and get a risk score combining rule-based security checks
(typosquatting, WHOIS domain age, SSL validity, URL structure) with LLM-based
tone/language analysis (English, Urdu, Roman Urdu).

## Setup (local or Colab)

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=your_key_here
streamlit run app.py
```

## Files
- `app.py` — Streamlit UI, main entry point
- `checks.py` — rule-based security checks (typosquatting, WHOIS, SSL, URL structure)
- `brand_domains.py` — seed list of legitimate Pakistani brand domains
- `llm_analysis.py` — LLM call for tone/language/impersonation analysis
- `scoring.py` — combines rule-based + LLM signals into one risk score; generates fraud report draft

## Deploying to Hugging Face Spaces
1. Create a new Space -> SDK: **Streamlit**
2. Push these files (or upload via the web UI)
3. In Space Settings -> "Variables and secrets", add `ANTHROPIC_API_KEY` as a secret
4. Space builds automatically from `requirements.txt`
