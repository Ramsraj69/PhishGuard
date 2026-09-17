def calculate_risk_score(signals):
    score = 0
    reasons = []

    # Weak signals
    if signals.get("long_url"):
        score += 8
        reasons.append("Unusually long URL")
    if signals.get("at_symbol"):
        score += 15
        reasons.append("URL contains @ symbol")

    if signals.get("encoded_characters"):
        score += 4
        reasons.append("Encoded characters detected")

    if signals.get("excessive_numbers"):
        score += 8
        reasons.append("Excessive numbers in URL")

    if signals.get("excessive_hyphens"):
        score += 8
        reasons.append("Excessive hyphens in URL")

    # Medium signals
    if signals.get("suspicious_keywords"):
        score += 10
        reasons.append("Suspicious keywords detected")

    if signals.get("not_https"):
        score += 5
        reasons.append("Connection is not HTTPS")

    if signals.get("ip_address"):
        score += 20
        reasons.append("IP address used instead of domain")

    # Strong signal
    if signals.get("impersonation"):
        score += 30
        reasons.append("Possible brand impersonation detected")

    # Combination bonus
    strong_signals = sum([
        bool(signals.get("ip_address")),
        bool(signals.get("impersonation")),
        bool(signals.get("suspicious_keywords"))
    ])

    if strong_signals >= 2:
        score += 10
        reasons.append("Multiple strong risk indicators detected")

    # Keep score between 0 and 100
    score = min(score, 100)

    # Risk level
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

# ==============================
# A9 BASIC TEST
# ==============================

test_signals = {
    "long_url": False,
    "at_symbol": True,
    "excessive_numbers": False,
    "excessive_hyphens": False,
    "encoded_characters": False,
    "suspicious_keywords": False,
    "ip_address": False,
    "not_https": False,
    "impersonation": False
}
result = calculate_risk_score(test_signals)

print("\n========== A9 LEGITIMATE URL TEST ==========\n")
print("Risk Score:", result["risk_score"])
print("Risk Level:", result["risk_level"])
print("Reasons:")

for reason in result["reasons"]:
    print("-", reason)