def calculate_risk_score(signals):
    score = 0
    reasons = []

    if signals.get("long_url"):
        score += 8
        reasons.append("Unusually long URL")

    if signals.get("at_symbol"):
        score += 25
        reasons.append("URL contains @ symbol")
        
    if signals.get("deceptive_at_pattern"):
        score += 20
        reasons.append("Deceptive @ URL pattern detected")    

    if signals.get("encoded_characters"):
        score += 4
        reasons.append("Encoded characters detected")

    if signals.get("excessive_numbers"):
        score += 8
        reasons.append("Excessive numbers in URL")

    if signals.get("excessive_hyphens"):
        score += 8
        reasons.append("Excessive hyphens in URL")

    if signals.get("suspicious_keywords"):
        score += 10
        reasons.append("Suspicious keywords detected")

    if signals.get("not_https"):
        score += 5
        reasons.append("Connection is not HTTPS")

    if signals.get("ip_address"):
        score += 20
        reasons.append("IP address used instead of domain")

    if signals.get("impersonation"):
        score += 30
        reasons.append("Possible brand impersonation detected")

    if signals.get("known_malicious"):
        score += 40
        reasons.append("URL found in reputation database")
    if signals.get("downgrade"):
        score += 15
        reasons.append("HTTPS connection downgraded to HTTP")    

    strong_signals = sum([
        bool(signals.get("ip_address")),
        bool(signals.get("impersonation")),
        bool(signals.get("suspicious_keywords"))
    ])

    if strong_signals >= 2:
        score += 10
        reasons.append("Multiple strong risk indicators detected")

    score = min(score, 100)

    if score >= 70:
        risk_level = "HIGH"
    elif score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }


if __name__ == "__main__":

    print("\n========== RISK ENGINE TEST ==========\n")

    test_cases = [
        {
            "name": "Clean URL",
            "signals": {}
        },
        {
            "name": "URL with @ symbol",
            "signals": {
                "at_symbol": True
            }
        },
        {
            "name": "Multiple suspicious signals",
            "signals": {
                "long_url": True,
                "suspicious_keywords": True,
                "not_https": True,
                "ip_address": True,
                "impersonation": True
            }
        },
        {
            "name": "Known malicious reputation",
            "signals": {
                "known_malicious": True
            }
        },
        {
    "name": "HTTPS downgrade",
    "signals": {
        "downgrade": True
    }
}
    ]

    for test in test_cases:

        result = calculate_risk_score(test["signals"])

        print("Test:", test["name"])
        print("Risk Score:", result["risk_score"])
        print("Risk Level:", result["risk_level"])
        print("Reasons:")

        for reason in result["reasons"]:
            print("-", reason)

        print("\n" + "-" * 50 + "\n")