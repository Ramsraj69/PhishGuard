"""
PhishGuard Protection Decision Engine

Converts the existing risk classification into
a clear protection action.

LOW    -> ALLOW
MEDIUM -> WARN
HIGH   -> BLOCK
"""


def get_protection_action(risk_level):
    """
    Convert risk level into a protection action.
    """

    if not risk_level:
        return {
            "action": "WARN",
            "severity": "UNKNOWN",
            "message": "Risk level is unavailable. Proceed with caution."
        }

    level = str(risk_level).upper()


    # LOW risk
    if level == "LOW":

        return {
            "action": "ALLOW",
            "severity": "LOW",
            "message": "No major threat indicators were detected."
        }


    # MEDIUM risk
    if level == "MEDIUM":

        return {
            "action": "WARN",
            "severity": "MEDIUM",
            "message": "Suspicious characteristics were detected. Verify the destination before continuing."
        }


    # HIGH risk
    if level == "HIGH":

        return {
            "action": "BLOCK",
            "severity": "HIGH",
            "message": "Strong threat indicators were detected. Avoid opening this URL."
        }


    # Unknown risk level
    return {
        "action": "WARN",
        "severity": "UNKNOWN",
        "message": "The risk level could not be determined. Proceed with caution."
    }