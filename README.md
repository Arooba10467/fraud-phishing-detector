# SMS/WhatsApp Fraud & Phishing Detector

AI-augmented fraud/phishing message detector for Pakistan. Paste a suspicious
SMS/WhatsApp message and get a risk score combining rule-based security checks
(typosquatting, WHOIS domain age, SSL validity, URL structure) with LLM-based
tone/language analysis (English, Urdu, Roman Urdu).

## Setup (local or Colab)

```bash
pip install -r requirements.txt
export GROQ_API_KEY=your_key_here
streamlit run app.py
```

## Files
- `app.py` — Streamlit UI, main entry point
- `checks.py` — rule-based security checks (typosquatting, WHOIS, SSL, URL structure)
- `brand_domains.py` — seed list of legitimate Pakistani brand domains
- `llm_analysis.py` — LLM call (Groq) for tone/language/impersonation analysis
- `scoring.py` — combines rule-based + LLM signals into one risk score; generates fraud report draft

## Deploying to Streamlit Community Cloud
1. Push these files to a public GitHub repo (app.py at the repo root)
2. Go to share.streamlit.io -> sign in with GitHub -> "Create app"
3. Select the repo, branch, and set main file to `app.py`
4. Under "Advanced settings", add secret: `GROQ_API_KEY = your_key_here`
5. Click Deploy

