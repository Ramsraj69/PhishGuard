KNOWN_MALICIOUS_DOMAINS = [
    "malicious.example.com",
    "phishing.example.com"
]


def is_known_malicious_domain(domain):
    return domain.lower() in KNOWN_MALICIOUS_DOMAINS