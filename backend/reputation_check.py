from urllib.parse import urlparse
from threat_database import is_known_malicious_domain
from risk_engine import calculate_risk_score


def get_hostname(url):
    parsed = urlparse(url)
    return parsed.hostname


def check_reputation(url):
    """
    Checks the URL hostname against the local threat database.

    Returns:
        reputation_status
        source
        reason
    """

    hostname = get_hostname(url)

    if hostname is None:
        return {
            "reputation_status": "unknown",
            "source": "Local Threat Database",
            "reason": "Invalid URL hostname"
        }

    hostname = hostname.lower().rstrip(".")

    if is_known_malicious_domain(hostname):
        return {
            "reputation_status": "known_malicious",
            "source": "Local Threat Database",
            "reason": "Domain found in known malicious domain list"
        }

    return {
        "reputation_status": "unknown",
        "source": "Local Threat Database",
        "reason": "Domain not found in known malicious domain list"
    }


if __name__ == "__main__":

    print("\n========== A12 REPUTATION + RISK TEST ==========\n")

    test_urls = [
    "http://malicious.example.com/login/verify-account",
    "https://google.com",
    "http://192.168.1.50/login"
]

    for url in test_urls:

        reputation = check_reputation(url)

        signals = {
            "known_malicious": reputation["reputation_status"] == "known_malicious"
        }

        risk_result = calculate_risk_score(signals)

        if reputation["reputation_status"] == "unknown":
            risk_result["risk_level"] = "UNKNOWN"


        print("URL:", url)
        print("Reputation:", reputation["reputation_status"])
        print("Source:", reputation["source"])
        print("Risk Score:", risk_result["risk_score"])
        print("Risk Level:", risk_result["risk_level"])
        print("Reasons:")

        for reason in risk_result["reasons"]:
            print("-", reason)

        print("\n" + "-" * 50 + "\n")