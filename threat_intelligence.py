import re


def analyze_threats(subject, sender, body):
    """
    Analyze an email for common phishing threat indicators.
    """

    text = f"{subject} {sender} {body}".lower()

    indicators = []

    # 1. Suspicious URL
    url_pattern = r"https?://[^\s]+"

    if re.search(url_pattern, text):
        indicators.append("Suspicious URL detected")

    # 2. IP address used in URL
    ip_url_pattern = r"https?://(?:\d{1,3}\.){3}\d{1,3}"

    if re.search(ip_url_pattern, text):
        indicators.append("IP address used instead of domain name")

    # 3. Urgent language
    urgent_words = [
        "urgent",
        "immediately",
        "act now",
        "verify now",
        "account suspended",
        "account will be closed",
        "last warning"
    ]

    for word in urgent_words:
        if word in text:
            indicators.append("Urgent or threatening language detected")
            break

    # 4. Credential request
    credential_words = [
        "password",
        "username",
        "login",
        "credentials",
        "verify your account",
        "confirm your account",
        "security code",
        "otp"
    ]

    for word in credential_words:
        if word in text:
            indicators.append("Possible credential request detected")
            break

    # 5. Suspicious sender
    suspicious_sender_words = [
        "noreply",
        "support",
        "security",
        "admin",
        "verify"
    ]

    if "@" in sender:
        sender_name = sender.split("@")[0].lower()

        for word in suspicious_sender_words:
            if word in sender_name:
                indicators.append("Sender identity requires verification")
                break

    # 6. Financial information request
    financial_words = [
        "bank account",
        "credit card",
        "debit card",
        "card number",
        "bank details",
        "payment",
        "wire transfer"
    ]

    for word in financial_words:
        if word in text:
            indicators.append("Financial information request detected")
            break

    # Remove duplicates
    indicators = list(dict.fromkeys(indicators))

    # Determine risk
    if len(indicators) >= 3:
        risk = "HIGH"
    elif len(indicators) >= 1:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "risk": risk,
        "indicators": indicators
    }