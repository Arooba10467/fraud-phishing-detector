"""
Test dataset for measuring detector accuracy.

Each entry: (message_text, org_claimed, is_scam, category)
- is_scam: True/False ground truth label
- category: for breaking down accuracy by scam type / language

IMPORTANT: These are synthetic/illustrative examples written to resemble
real scam patterns reported in Pakistan. For your actual project
submission, supplement/replace these with real messages you or people
around you have received (screenshot the SMS, transcribe the text here).
Real samples will make your accuracy numbers meaningful for the writeup;
synthetic ones are just a starting point to get the eval script running.
"""

TEST_MESSAGES = [
    # ---- SCAMS: English ----
    (
        "Dear customer, your JazzCash account will be BLOCKED in 24 hours due to "
        "incomplete KYC. Update immediately: http://jazzcash-kyc-update.com",
        "JazzCash", True, "bank_wallet_english",
    ),
    (
        "CONGRATULATIONS! Your number has WON PKR 500,000 in the Telenor lucky draw. "
        "Claim now: http://telenor-prize-pk.net/claim",
        "Telenor", True, "prize_scam_english",
    ),
    (
        "HBL Alert: Unusual activity detected on your account. Verify your identity now "
        "to avoid suspension: http://hbl-verify-secure.com",
        "HBL", True, "bank_wallet_english",
    ),
    (
        "Your parcel is on hold due to unpaid customs fee of Rs. 250. Pay now to release: "
        "https://tcs-express-pay.info/track",
        "TCS", True, "courier_scam_english",
    ),

    # ---- SCAMS: Roman Urdu ----
    (
        "Aap ka Easypaisa account 12 ghante mein band ho jaye ga kyun k aap ne verify "
        "nahi kiya. Is link per click karein: http://easypaisa-verify-pk.com",
        "Easypaisa", True, "bank_wallet_roman_urdu",
    ),
    (
        "Mubarak ho! Aap ne PTCL ki taraf se free mobile jeeta hai. Abhi claim karen: "
        "http://ptcl-inaam.net",
        "PTCL", True, "prize_scam_roman_urdu",
    ),
    (
        "NADRA: Aap ka CNIC block hone wala hai. Fori update ke liye yahan click karein: "
        "http://nadra-cnic-update.com warna account suspend ho jaye ga.",
        "NADRA", True, "govt_impersonation_roman_urdu",
    ),
    (
        "Zong se aap ko last warning di ja rahi hai, aap ka number 2 ghante mein band "
        "ho jaye ga. Verify karein: https://zong-verify.info",
        "Zong", True, "telecom_scam_roman_urdu",
    ),

    # ---- SCAMS: Urdu script ----
    (
        "پیارے کسٹمر، آپ کا اکاؤنٹ 24 گھنٹوں میں بند ہو جائے گا۔ ابھی تصدیق کریں: "
        "http://jazzcash-tasdeeq.com",
        "JazzCash", True, "bank_wallet_urdu_script",
    ),

    # ---- SCAMS: shortener / structural tricks ----
    (
        "PakPost: Aap ka parcel address ghalat hai. Update na kiya to wapis bhej diya "
        "jaye ga: https://qrco.de/bf56c0",
        "PakPost", True, "courier_scam_shortener",
    ),
    (
        "Your bank account needs verification. Click here: http://192.168.45.12/verify-hbl",
        "HBL", True, "ip_based_url",
    ),

    # ---- LEGITIMATE: English ----
    (
        "Your OTP for JazzCash transaction is 483920. Do not share this code with anyone. "
        "Valid for 5 minutes.",
        "JazzCash", False, "legit_otp_english",
    ),
    (
        "Hi! Just checking if we're still on for lunch tomorrow at 1pm?",
        "", False, "legit_personal_english",
    ),
    (
        "Your Daraz order #DR3928102 has been shipped and will arrive within 3-5 "
        "business days. Track at daraz.pk/track",
        "Daraz", False, "legit_order_english",
    ),
    (
        "Reminder: Your electricity bill of Rs. 4,500 is due on the 15th. Pay via "
        "1LINK, easypaisa or your bank app.",
        "", False, "legit_bill_reminder",
    ),

    # ---- LEGITIMATE: Roman Urdu ----
    (
        "Assalam o alaikum, kal meeting 3 baje hai office mein, please time per aa jayen.",
        "", False, "legit_personal_roman_urdu",
    ),
    (
        "Aap ka Careem ride 5 minute mein pohanch jaye ga. Driver: Ahmed, car number "
        "LEA-1234.",
        "Careem", False, "legit_ride_roman_urdu",
    ),

    # ---- LEGITIMATE: Urdu script ----
    (
        "السلام علیکم، آپ کا آرڈر موصول ہو گیا ہے، جلد ڈسپیچ کر دیا جائے گا۔",
        "", False, "legit_order_urdu_script",
    ),

    # ---- EDGE CASES: legitimate but urgent-sounding (tests false positive rate) ----
    (
        "URGENT: Your flight PK-301 to Karachi has been rescheduled to 6:45 PM today. "
        "Please check in 2 hours before departure.",
        "PIA", False, "legit_urgent_english",
    ),
    (
        "Meeting has been moved up — please join in 10 minutes, link: "
        "https://meet.google.com/abc-defg-hij",
        "", False, "legit_urgent_link_english",
    ),
]
