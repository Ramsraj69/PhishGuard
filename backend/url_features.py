from urllib.parse import urlparse
from difflib import SequenceMatcher


def is_long_url(url):
    return len(url) > 100


def has_at_symbol(url):
    return "@" in url


def has_excessive_numbers(url):
    digit_count = sum(char.isdigit() for char in url)
    return digit_count > 5


def has_excessive_hyphens(url):
    hyphen_count = url.count("-")
    return hyphen_count > 2


def has_encoded_characters(url):
    return "%" in url


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "account",
    "update",
    "password",
    "secure",
    "signin"
]


def find_suspicious_keywords(url):
    url = url.lower()

    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url:
            found_keywords.append(keyword)

    return found_keywords


def get_hostname(url):
    parsed = urlparse(url)
    return parsed.hostname


def count_subdomains(hostname):
    parts = hostname.split(".")

    return max(len(parts) - 2, 0)


def has_deep_subdomains(hostname):
    return count_subdomains(hostname) > 3


def has_brand_in_subdomain(hostname, brand):
    hostname = hostname.lower()
    brand = brand.lower()

    parts = hostname.split(".")

    # Remove the last two parts (main domain + extension)
    subdomain_parts = parts[:-2]

    return brand in subdomain_parts


def analyze_subdomain(hostname, brand):
    subdomain_count = count_subdomains(hostname)
    deep_subdomain = has_deep_subdomains(hostname)
    brand_hidden = has_brand_in_subdomain(hostname, brand)

    return {
        "subdomain_count": subdomain_count,
        "deep_subdomain": deep_subdomain,
        "brand_hidden": brand_hidden
    }


def get_domain_from_hostname(hostname):
    parts = hostname.split(".")

    if len(parts) < 2:
        return hostname

    return ".".join(parts[-2:])


def is_long_domain(domain):
    return len(domain) > 30


def analyze_domain_characters(domain):
    digit_count = sum(char.isdigit() for char in domain)
    hyphen_count = domain.count("-")

    return {
        "digit_count": digit_count,
        "hyphen_count": hyphen_count,
        "excessive_numbers": digit_count > 4,
        "excessive_hyphens": hyphen_count > 2
    }


def domain_similarity(domain, trusted_domain):
    domain = domain.lower()
    trusted_domain = trusted_domain.lower()

    return SequenceMatcher(None, domain, trusted_domain).ratio()


def has_suspicious_domain_pattern(domain):
    domain = domain.lower()

    suspicious_words = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "security",
        "password"
    ]

    word_count = 0

    for word in suspicious_words:
        if word in domain:
            word_count += 1

    hyphen_count = domain.count("-")
    digit_count = sum(char.isdigit() for char in domain)

    return word_count >= 2 and (hyphen_count >= 2 or digit_count >= 3)