import re
from urllib.parse import urlparse
SHORTENER_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd"
]

FINANCIAL_KEYWORDS = [
    "bank account",
    "credit card",
    "debit card",
    "payment",
    "transaction",
    "money",
    "refund"
]

THREAT_KEYWORDS = [
    "account will be closed",
    "account will be suspended",
    "legal action",
    "you will be blocked",
    "immediately"
]

SUSPICIOUS_SENDER_WORDS = [
    "support",
    "security",
    "verify",
    "account",
    "billing"
]

URL_PATTERN = r'https?://[^\s]+'

IP_PATTERN = r'^\d{1,3}(\.\d{1,3}){3}$'
def add_indicator(risk_score, indicators, score, message):
    risk_score += score
    indicators.append(message)
    return risk_score

def analyze_content(subject, email_body):
    risk_score = 0
    indicators = []

    email_text = subject + " " + email_body
    email_text_lower = email_text.lower()

    if "urgent" in email_text_lower:
        risk_score = add_indicator(
            risk_score,
            indicators,
            15,
            "Urgent language detected"
        )

    if "password" in email_text_lower:
        risk_score = add_indicator(
            risk_score,
            indicators,
            20,
            "Password request detected"
        )

    if "suspended" in email_text_lower or "suspension" in email_text_lower:
        risk_score = add_indicator(
            risk_score,
            indicators,
            20,
            "Account suspension language detected"
        )

    if "verify" in email_text_lower or "verification" in email_text_lower:
        risk_score = add_indicator(
            risk_score,
            indicators,
            15,
            "Verification request detected"
        )

    if "click" in email_text_lower:
        risk_score = add_indicator(
            risk_score,
            indicators,
            15,
            "Instruction to click a link detected"
        )

    for keyword in FINANCIAL_KEYWORDS:
        if keyword in email_text_lower:
            risk_score = add_indicator(
                risk_score,
                indicators,
                20,
                f"Financial-related request detected: {keyword}"
            )

    for keyword in THREAT_KEYWORDS:
        if keyword in email_text_lower:
            risk_score = add_indicator(
                risk_score,
                indicators,
                15,
                f"Threat or pressure language detected: {keyword}"
            )

    return risk_score, indicators, email_text
def extract_urls(email_text):
    urls = re.findall(URL_PATTERN, email_text)
    return urls
def analyze_urls(urls):
    risk_score = 0
    indicators = []

    if urls:
        risk_score = add_indicator(
            risk_score,
            indicators,
            5,
            f"{len(urls)} URL(s) detected in email"
        )

    for url in urls:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()

        if parsed_url.scheme == "http":
            risk_score = add_indicator(
                risk_score,
                indicators,
                10,
                f"URL does not use HTTPS: {url}"
            )

        if re.match(IP_PATTERN, domain):
            risk_score = add_indicator(
                risk_score,
                indicators,
                20,
                f"URL uses an IP address instead of a domain: {url}"
            )

        if domain in SHORTENER_DOMAINS:
            risk_score = add_indicator(
                risk_score,
                indicators,
                15,
                f"URL shortener detected: {domain}"
            )

        if "@" in url:
            risk_score = add_indicator(
                risk_score,
                indicators,
                20,
                f"URL contains '@' character: {url}"
            )

    return risk_score, indicators
def analyze_sender(sender):
    risk_score = 0
    indicators = []

    if "@" not in sender:
        risk_score = add_indicator(
            risk_score,
            indicators,
            25,
            "Sender email address appears invalid"
        )

    if "@" in sender:
        sender_domain = sender.split("@")[-1].lower()
    else:
        sender_domain = ""

    for word in SUSPICIOUS_SENDER_WORDS:
        if word in sender.lower():
            risk_score = add_indicator(
                risk_score,
                indicators,
                5,
                f"Sender contains security-related keyword: {word}"
            )

    return risk_score, indicators, sender_domain
def classify_risk(risk_score):
    if risk_score >= 60:
        return "PHISHING"
    elif risk_score >= 30:
        return "SUSPICIOUS"
    else:
        return "LEGITIMATE"

def analyze_email(sender, subject, email_body):
    content_score, content_indicators, email_text = analyze_content(
        subject,
        email_body
    )

    urls = extract_urls(email_text)

    url_score, url_indicators = analyze_urls(urls)

    sender_score, sender_indicators, sender_domain = analyze_sender(sender)

    total_score = content_score + url_score + sender_score

    total_score = min(total_score, 100)

    classification = classify_risk(total_score)

    indicators = (
        content_indicators
        + url_indicators
        + sender_indicators
    )

    return {
        "sender": sender,
        "sender_domain": sender_domain,
        "subject": subject,
        "risk_score": total_score,
        "classification": classification,
        "indicators": indicators,
        "urls": urls
    }
sender = "security@example.com"

subject = "URGENT! Your account will be suspended"

email_body = """
Your account has been detected for suspicious activity.
Please verify your password immediately.
Click the link below to secure your account.

https://example.com/verify
"""

result = analyze_email(
    sender,
    subject,
    email_body
)

print("PHISHING EMAIL DETECTION RESULT")
print("--------------------------------")
print("Sender:", result["sender"])
print("Sender Domain:", result["sender_domain"])
print("Subject:", result["subject"])
print("Risk Score:", result["risk_score"])
print("Classification:", result["classification"])

print("\nDetected Indicators:")

if result["indicators"]:
    for indicator in result["indicators"]:
        print("-", indicator)
else:
    print("- No suspicious indicators detected")

print("\nDetected URLs:")

if result["urls"]:
    for url in result["urls"]:
        print("-", url)
else:
    print("- No URLs detected")