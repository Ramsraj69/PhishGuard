def format_result(risk_result):
    score = risk_result.get("risk_score", 0)
    level = risk_result.get("risk_level", "LOW")
    reasons = risk_result.get("reasons", [])

    return {
        "risk_score": score,
        "risk_level": level,
        "reasons": reasons,
        "message": get_message(level)
    }


def get_message(risk_level):

    if risk_level == "HIGH":
        return "This URL appears highly suspicious. Avoid opening it."

    elif risk_level == "MEDIUM":
        return "This URL has some suspicious characteristics. Proceed with caution."

    else:
        return "No major suspicious indicators were detected."


# ==============================
# A10 TEST
# ==============================

test_result = {
    "risk_score": 83,
    "risk_level": "HIGH",
    "reasons": [
        "Unusually long URL",
        "Suspicious keywords detected",
        "IP address used instead of domain",
        "Possible brand impersonation detected",
        "Multiple strong risk indicators detected"
    ]
}

formatted = format_result(test_result)

print("\n========== A10 EXPLAINABLE RESULT ==========\n")
print("Risk Score:", formatted["risk_score"])
print("Risk Level:", formatted["risk_level"])
print("Message:", formatted["message"])
print("Reasons:")

for reason in formatted["reasons"]:
    print("-", reason)