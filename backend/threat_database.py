KNOWN_MALICIOUS_DOMAINS = [

    "malicious.example.com",

    "phishing.example.com"

]


def is_known_malicious_domain(domain):

    if not domain:
        return False

    domain = domain.lower().rstrip(".")

    return domain in KNOWN_MALICIOUS_DOMAINS