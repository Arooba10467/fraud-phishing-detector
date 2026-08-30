import streamlit as st

from checks import extract_urls, run_all_url_checks
from llm_analysis import analyze_message_with_llm
from scoring import compute_overall_risk, generate_fraud_report

st.set_page_config(page_title="SMS/WhatsApp Fraud Detector", page_icon="🛡️", layout="centered")

# --- Background + custom styling ---
# Uses a free Unsplash cybersecurity-themed image as a fixed background with
# a dark overlay so text stays readable. Swap the URL for any image you like.
st.markdown(
    """
    <style>
    .stApp {
        background:
            linear-gradient(rgba(10, 12, 20, 0.88), rgba(10, 12, 20, 0.92)),
            url("https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&w=1600&q=80");
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
    }
    .verdict-banner {
        padding: 1.2rem 1.5rem;
        border-radius: 12px;
        font-size: 1.4rem;
        font-weight: 700;
        text-align: center;
        margin-bottom: 1rem;
        border: 2px solid;
    }
    .verdict-high-risk {
        background-color: rgba(220, 38, 38, 0.18);
        border-color: #dc2626;
        color: #ff6b6b;
    }
    .verdict-suspicious {
        background-color: rgba(217, 119, 6, 0.18);
        border-color: #d97706;
        color: #fbbf24;
    }
    .verdict-safe {
        background-color: rgba(22, 163, 74, 0.18);
        border-color: #16a34a;
        color: #4ade80;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🛡️ SMS/WhatsApp Fraud & Phishing Detector")
st.caption(
    "Paste a suspicious SMS or WhatsApp message (English, Urdu, or Roman Urdu) "
    "and get an instant risk assessment. This is a screening tool, not a "
    "definitive verdict — always verify independently before acting."
)

EXAMPLE_MESSAGES = {
    "🚨 Example: Bank scam": (
        "Dear customer, your JazzCash account will be BLOCKED in 24 hours due to "
        "incomplete KYC. Update immediately: http://jazzcash-kyc-update.com",
        "JazzCash",
    ),
    "🚨 Example: Roman Urdu scam": (
        "PakPost: Aap ka parcel address ghalat hai. Update na kiya to wapis bhej diya "
        "jaye ga: https://qrco.de/bf56c0",
        "PakPost",
    ),
    "✅ Example: Legitimate message": (
        "Your OTP for JazzCash transaction is 483920. Do not share this code with "
        "anyone. Valid for 5 minutes.",
        "JazzCash",
    ),
}

if "message_input" not in st.session_state:
    st.session_state["message_input"] = ""
if "org_input" not in st.session_state:
    st.session_state["org_input"] = ""

st.caption("Try an example, or paste your own message below:")
example_cols = st.columns(len(EXAMPLE_MESSAGES))
for col, (label, (msg, org)) in zip(example_cols, EXAMPLE_MESSAGES.items()):
    if col.button(label, use_container_width=True):
        st.session_state["message_input"] = msg
        st.session_state["org_input"] = org
        st.rerun()
        
message_text = st.text_area(
    "Paste the suspicious message here",
    height=150,
    placeholder="e.g. Dear customer aap ka JazzCash account 24 hours main block ho jaye ga. "
                "Verify karnay k liye is link per click karein: http://jazzcash-verify-pk.com",
    key="message_input",
)

impersonated_org = st.text_input(
    "Which organization does it claim to be from? (optional)",
    placeholder="e.g. JazzCash, HBL, PTA",
    key="org_input",
)

analyze_clicked = st.button("Analyze Message", type="primary")

if analyze_clicked:
    if not message_text.strip():
        st.warning("Please paste a message first.")
        st.stop()

    with st.spinner("Extracting links and running security checks..."):
        urls = extract_urls(message_text)
        url_check_results = [run_all_url_checks(u) for u in urls]

    with st.spinner("Analyzing message tone and language..."):
        llm_result = analyze_message_with_llm(message_text)

    risk_summary = compute_overall_risk(url_check_results, llm_result)

    st.divider()

    # --- Verdict banner ---
    score = risk_summary["overall_score"]
    verdict = risk_summary["verdict"]
    if verdict == "High Risk":
        banner_class, banner_label = "verdict-high-risk", f"🚨 NOT SAFE — {score}/100"
    elif verdict == "Suspicious":
        banner_class, banner_label = "verdict-suspicious", f"⚠️ Suspicious — {score}/100"
    else:
        banner_class, banner_label = "verdict-safe", f"✅ Likely Safe — {score}/100"

    st.markdown(
        f'<div class="verdict-banner {banner_class}">{banner_label}</div>',
        unsafe_allow_html=True,
    )

    if not llm_result.get("ok"):
        st.info(f"Note: AI language analysis unavailable — {llm_result.get('reason')}. "
                "Score is based on link checks only.")

    # --- Explanation ---
    if risk_summary.get("llm_explanation"):
        st.write(risk_summary["llm_explanation"])

    # --- Red flags ---
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("🔎 Technical Red Flags")
        if risk_summary["rule_based_reasons"]:
            for r in risk_summary["rule_based_reasons"]:
                st.write(f"- {r}")
        elif urls:
            st.write(f"{len(urls)} link(s) found, but no technical red flags detected.")
        else:
            st.write("No links found in this message.")

    with col2:
        st.subheader("💬 Language Red Flags")
        if risk_summary["llm_red_flags"]:
            for r in risk_summary["llm_red_flags"]:
                st.write(f"- {r}")
        else:
            st.write("None detected.")

    # --- Per-URL detail (expandable) ---
    if url_check_results:
        st.subheader(f"🔗 Link(s) Found ({len(url_check_results)})")
        st.caption("Full technical breakdown per link — expand to see raw check results.")
        for result in url_check_results:
            with st.expander(result["url"]):
                st.json(result)

    # --- Fraud report ---
    st.divider()
    st.subheader("📝 Auto-Drafted Fraud Report")
    report_text = generate_fraud_report(message_text, urls, risk_summary, impersonated_org)
    st.text_area("Report draft (copy or download below)", report_text, height=300)
    st.download_button(
        "Download Report as .txt",
        data=report_text,
        file_name="fraud_report_draft.txt",
        mime="text/plain",
    )

st.divider()
st.caption(
    "⚠️ This tool provides automated risk screening only and is not a substitute "
    "for official verification. If in doubt, contact your bank/telecom directly "
    "using the number on your card or official website — never a number from the message."
    "Made by Arooba Internee at The ARZENS"

)
