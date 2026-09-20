# =========================
# PHISHGUARD RISK ENGINE
# =========================


def calculate_risk_score(signals):

    score = 0
    reasons = []

    # =========================
    # BASIC URL SIGNALS
    # =========================

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

    # =========================
    # DOMAIN SIGNALS
    # =========================

    if signals.get("long_domain"):
        score += 5
        reasons.append("Unusually long domain")

    if signals.get("excessive_numbers"):
        score += 8
        reasons.append("Excessive numbers in URL")

    if signals.get("excessive_hyphens"):
        score += 8
        reasons.append("Excessive hyphens in URL")

    if signals.get("suspicious_domain_pattern"):
        score += 15
        reasons.append("Suspicious domain pattern detected")

    if signals.get("lookalike_characters"):
        score += 10
        reasons.append("Lookalike characters detected in domain")

    if signals.get("deep_subdomain"):
        score += 10
        reasons.append("Unusually deep subdomain structure detected")

    # =========================
    # KEYWORD ANALYSIS
    # =========================

    if signals.get("suspicious_keywords"):
        score += 5
        reasons.append("Suspicious keywords detected")

    # =========================
    # HTTPS
    # =========================

    if signals.get("not_https"):
        score += 5
        reasons.append("Connection is not HTTPS")

    # =========================
    # IP ADDRESS
    # =========================

    if signals.get("ip_address"):
        score += 20
        reasons.append("IP address used instead of domain")

    # =========================
    # BRAND IMPERSONATION
    # =========================

    if signals.get("impersonation"):
        score += 30
        reasons.append("Possible brand impersonation detected")

    if signals.get("brand_hidden"):
        score += 10
        reasons.append("Trusted brand name hidden in subdomain")

    # =========================
    # DOMAIN SIMILARITY
    # =========================

    similarity = signals.get("domain_similarity")

    if similarity is not None:

        if similarity >= 0.90:
            score += 15
            reasons.append(
                "Domain is highly similar to a trusted domain"
            )

        elif similarity >= 0.75:
            score += 8
            reasons.append(
                "Domain is similar to a trusted domain"
            )

    # =========================
    # PUNYCODE / UNICODE
    # =========================

    if signals.get("punycode") and signals.get("impersonation"):
        score += 15
        reasons.append(
            "Punycode domain associated with possible impersonation"
        )

    if signals.get("unicode_confusable"):
        score += 20
        reasons.append(
            "Unicode confusable characters detected"
        )

    # =========================
    # REPUTATION
    # =========================

    if signals.get("known_malicious"):
        score += 40
        reasons.append(
            "URL found in reputation database"
        )

    # =========================
    # REDIRECT / DESTINATION ANALYSIS
    # =========================

    # A redirect was detected
    if signals.get("redirect_detected"):
        score += 5
        reasons.append(
            "URL redirects to another destination"
        )

    # Final destination belongs to another registered domain
    if signals.get("domain_changed"):
        score += 15
        reasons.append(
            "Redirect destination uses a different domain"
        )

    # Too many redirects can indicate suspicious redirect chains
    if signals.get("too_many_redirects"):
        score += 10
        reasons.append(
            "Too many redirects detected"
        )

    # =========================
    # HTTPS DOWNGRADE
    # =========================

    if signals.get("downgrade"):
        score += 15
        reasons.append(
            "HTTPS connection downgraded to HTTP"
        )

    # =========================
    # PORT
    # =========================

    if signals.get("unusual_port"):
        score += 5
        reasons.append(
            "Unusual port detected"
        )

    # =========================
    # MULTIPLE STRONG SIGNALS
    # =========================

    strong_signals = sum([
        bool(signals.get("ip_address")),
        bool(signals.get("impersonation")),
        bool(signals.get("suspicious_keywords")),
        bool(signals.get("suspicious_domain_pattern")),
        bool(signals.get("known_malicious")),
        bool(signals.get("domain_changed"))
    ])

    if strong_signals >= 2:
        score += 10
        reasons.append(
            "Multiple strong risk indicators detected"
        )

    # =========================
    # LIMIT SCORE
    # =========================

    score = min(score, 100)

    # =========================
    # RISK LEVEL
    # =========================

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


# =========================
# TEST
# =========================

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
            "name": "Suspicious domain",
            "signals": {
                "suspicious_domain_pattern": True,
                "suspicious_keywords": True
            }
        },

        {
            "name": "Brand impersonation",
            "signals": {
                "impersonation": True,
                "suspicious_keywords": True,
                "suspicious_domain_pattern": True
            }
        },

        {
            "name": "Multiple suspicious signals",
            "signals": {
                "long_url": True,
                "suspicious_keywords": True,
                "not_https": True,
                "ip_address": True,
                "impersonation": True,
                "suspicious_domain_pattern": True
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
        },

        {
            "name": "Redirect to different domain",
            "signals": {
                "redirect_detected": True,
                "domain_changed": True
            }
        },

        {
            "name": "Too many redirects",
            "signals": {
                "too_many_redirects": True
            }
        }
    ]

    for test in test_cases:

        result = calculate_risk_score(
            test["signals"]
        )

        print("Test:", test["name"])
        print("Risk Score:", result["risk_score"])
        print("Risk Level:", result["risk_level"])

        print("Reasons:")

        for reason in result["reasons"]:
            print("-", reason)

        print("\n" + "-" * 50 + "\n")