from urllib.parse import urlparse

from threat_database import is_known_malicious_domain


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
        known_malicious
    """

    hostname = get_hostname(url)

    if hostname is None:

        return {
            "reputation_status": "unknown",
            "source": "Local Threat Database",
            "reason": "Invalid URL hostname",
            "known_malicious": False
        }

    hostname = hostname.lower().rstrip(".")

    if is_known_malicious_domain(hostname):

        return {
            "reputation_status": "known_malicious",
            "source": "Local Threat Database",
            "reason": "Domain found in known malicious domain list",
            "known_malicious": True
        }

    return {
        "reputation_status": "unknown",
        "source": "Local Threat Database",
        "reason": "Domain not found in known malicious domain list",
        "known_malicious": False
    }


if __name__ == "__main__":

    print("\n========== A12 REPUTATION TEST ==========\n")

    test_urls = [
        "http://malicious.example.com/login/verify-account",
        "https://google.com",
        "http://192.168.1.50/login"
    ]

    for url in test_urls:

        reputation = check_reputation(url)

        print("URL:", url)
        print("Reputation:", reputation["reputation_status"])
        print("Source:", reputation["source"])
        print("Known Malicious:", reputation["known_malicious"])
        print("Reason:", reputation["reason"])

        print("\n" + "-" * 50 + "\n")