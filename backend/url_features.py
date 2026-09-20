from ip_check import is_ip_address
from https_check import uses_https

from difflib import SequenceMatcher
from urllib.parse import urlparse
import re


# =========================
# TRUSTED BRANDS
# =========================

TRUSTED_BRANDS = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "paypal": "paypal.com",
    "instagram": "instagram.com"
}


# =========================
# A4 - URL FEATURES
# =========================

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


# =========================
# A5 - SUSPICIOUS KEYWORDS
# =========================

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


# =========================
# A6 - SUBDOMAIN ANALYSIS
# =========================

def get_hostname(url):

    parsed = urlparse(url)

    return parsed.hostname


def count_subdomains(hostname):

    parts = hostname.split(".")

    return max(len(parts) - 2, 0)


def has_deep_subdomains(hostname):

    return count_subdomains(hostname) > 3


def has_brand_in_subdomain(hostname, brand):

    hostname = hostname.lower().strip(".")
    brand = brand.lower().strip()

    if not hostname or not brand:
        return False

    parts = hostname.split(".")

    # Remove the registered domain + extension.
    subdomain_parts = parts[:-2]

    # Detect the brand as a meaningful token inside a
    # subdomain label, for example:
    # paypal-login-verify.example.com
    # google-security.example.com
    for label in subdomain_parts:

        tokens = re.findall(r"[a-z0-9]+", label)

        if brand in tokens:
            return True

    return False


def analyze_subdomain(hostname, brand):

    subdomain_count = count_subdomains(hostname)

    deep_subdomain = has_deep_subdomains(
        hostname
    )

    brand_hidden = has_brand_in_subdomain(
        hostname,
        brand
    )

    return {
        "subdomain_count": subdomain_count,
        "deep_subdomain": deep_subdomain,
        "brand_hidden": brand_hidden
    }


# =========================
# A7 - DOMAIN ANALYSIS
# =========================

def get_domain_from_hostname(hostname):

    parts = hostname.split(".")

    if len(parts) < 2:
        return hostname

    return ".".join(parts[-2:])


def is_trusted_brand_domain(domain, brand):

    brand = brand.lower()
    domain = domain.lower()

    trusted_domain = TRUSTED_BRANDS.get(
        brand
    )

    if trusted_domain is None:
        return False

    return domain == trusted_domain


def is_long_domain(domain):

    return len(domain) > 30


def analyze_domain_characters(domain):

    digit_count = sum(
        char.isdigit()
        for char in domain
    )

    hyphen_count = domain.count("-")

    return {
        "digit_count": digit_count,
        "hyphen_count": hyphen_count,
        "excessive_numbers": digit_count > 4,
        "excessive_hyphens": hyphen_count > 2
    }


# =========================
# A7.4 - DOMAIN SIMILARITY
# =========================

def domain_similarity(
    domain,
    trusted_domain
):

    domain = domain.lower()

    trusted_domain = trusted_domain.lower()

    return SequenceMatcher(
        None,
        domain,
        trusted_domain
    ).ratio()


# =========================
# DOMAIN PATTERN CHECK
# =========================

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

    digit_count = sum(
        char.isdigit()
        for char in domain
    )

    return word_count >= 2 and (
        hyphen_count >= 2
        or digit_count >= 3
    )


# =========================
# DECEPTIVE @ PATTERN
# =========================

def has_deceptive_at_pattern(url):

    parsed = urlparse(url)

    if "@" not in url:
        return False

    if parsed.hostname is None:
        return False

    userinfo = parsed.netloc.rsplit(
        "@",
        1
    )[0]

    return "." in userinfo


# =========================
# A7.5 - LOOKALIKE CHARACTERS
# =========================

def has_lookalike_characters(domain):

    domain = domain.lower()

    lookalike_map = {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "7": "t"
    }

    for char in domain:

        if char in lookalike_map:
            return True

    return False


# =========================
# A8 - BRAND IMPERSONATION
# =========================

def detect_brand_impersonation(
    domain,
    brand
):

    domain = domain.lower()
    brand = brand.lower()

    trusted_domain = TRUSTED_BRANDS.get(
        brand
    )

    if trusted_domain is None:
        return False

    # Legitimate domain
    if domain == trusted_domain:
        return False

    # Brand name appears inside a different
    # registered domain.
    if brand in domain:
        return True

    return False


def analyze_brand_impersonation(
    hostname,
    brand
):

    actual_domain = get_domain_from_hostname(
        hostname
    )

    trusted_domain = TRUSTED_BRANDS.get(
        brand.lower()
    )

    if trusted_domain is None:

        return {
            "brand": brand,
            "actual_domain": actual_domain,
            "trusted_domain": None,
            "impersonation": False,
            "brand_hidden": False
        }

    # Brand appears in a subdomain
    brand_hidden = has_brand_in_subdomain(
        hostname,
        brand
    )

    # Brand appears inside the actual
    # registered domain.
    domain_brand_match = detect_brand_impersonation(
        actual_domain,
        brand
    )

    domain_matches = (
        actual_domain == trusted_domain
    )

    impersonation = (
        not domain_matches
        and (
            brand_hidden
            or domain_brand_match
        )
    )

    return {
        "brand": brand,
        "actual_domain": actual_domain,
        "trusted_domain": trusted_domain,
        "impersonation": impersonation,
        "brand_hidden": brand_hidden
    }


# =========================
# A9 - COMBINE URL ANALYSIS
# =========================

def analyze_url_features(
    url,
    brand=None
):

    hostname = get_hostname(url)

    if hostname is None:

        return {
            "valid": False,
            "error": "Invalid URL"
        }

    ip_address = is_ip_address(
        hostname
    )

    if ip_address:

        actual_domain = hostname

    else:

        actual_domain = get_domain_from_hostname(
            hostname
        )

    result = {

        "valid": True,

        "url": url,

        # -------------------------
        # Basic URL checks
        # -------------------------

        "https": uses_https(url),

        "ip_address": ip_address,

        "long_url": is_long_url(url),

        "at_symbol": has_at_symbol(url),

        "deceptive_at_pattern":
            has_deceptive_at_pattern(url),

        "excessive_numbers":
            has_excessive_numbers(url),

        "excessive_hyphens":
            has_excessive_hyphens(url),

        "encoded_characters":
            has_encoded_characters(url),

        # -------------------------
        # Keyword analysis
        # -------------------------

        "suspicious_keywords":
            find_suspicious_keywords(url),

        # -------------------------
        # Hostname
        # -------------------------

        "hostname": hostname,

        "actual_domain":
            actual_domain,

        # -------------------------
        # Subdomain
        # -------------------------

        "subdomain_count":
            count_subdomains(hostname),

        "deep_subdomain":
            has_deep_subdomains(hostname),

        # -------------------------
        # Domain
        # -------------------------

        "long_domain":
            is_long_domain(actual_domain),

        "domain_characters":
            analyze_domain_characters(
                actual_domain
            ),

        "lookalike_characters":
            has_lookalike_characters(
                actual_domain
            ),

        "suspicious_domain_pattern":
            has_suspicious_domain_pattern(
                hostname
            )
    }

    # =========================
    # BRAND ANALYSIS
    # =========================

    if brand:

        result["brand_analysis"] = (
            analyze_brand_impersonation(
                hostname,
                brand
            )
        )

        trusted_domain = TRUSTED_BRANDS.get(
            brand.lower()
        )

        if trusted_domain:

            result["domain_similarity"] = (
                domain_similarity(
                    actual_domain,
                    trusted_domain
                )
            )

        else:

            result["domain_similarity"] = None

    return result


# =========================
# TESTS
# =========================

if __name__ == "__main__":

    print("A7.4 - Domain Similarity")

    print(
        domain_similarity(
            "google.com",
            "google.com"
        )
    )

    print(
        domain_similarity(
            "gooogle.com",
            "google.com"
        )
    )

    print(
        domain_similarity(
            "randomsite.com",
            "google.com"
        )
    )

    print("\nA7.5 - Lookalike Characters")

    print(
        has_lookalike_characters(
            "google.com"
        )
    )

    print(
        has_lookalike_characters(
            "g00gle.com"
        )
    )

    print(
        has_lookalike_characters(
            "paypa1.com"
        )
    )

    print(
        has_lookalike_characters(
            "example.com"
        )
    )

    print("\nA8 - Actual Domain")

    print(
        get_domain_from_hostname(
            "login.google.com"
        )
    )

    print(
        get_domain_from_hostname(
            "google.com.security-check.example.com"
        )
    )

    print(
        get_domain_from_hostname(
            "example.com"
        )
    )

    print("\nA8 - Trusted Brand Domain")

    print(
        is_trusted_brand_domain(
            "google.com",
            "google"
        )
    )

    print(
        is_trusted_brand_domain(
            "example.com",
            "google"
        )
    )

    print(
        is_trusted_brand_domain(
            "amazon.com",
            "amazon"
        )
    )

    print(
        is_trusted_brand_domain(
            "example.com",
            "amazon"
        )
    )

    print("\nA8 - Brand Impersonation")

    print(
        detect_brand_impersonation(
            "google.com",
            "google"
        )
    )

    print(
        detect_brand_impersonation(
            "google-login-security.com",
            "google"
        )
    )

    print(
        detect_brand_impersonation(
            "amazon-security-check.com",
            "amazon"
        )
    )

    print(
        detect_brand_impersonation(
            "example.com",
            "google"
        )
    )

    print("\nA8 - Hidden Brand Test")

    hostname = get_hostname(
        "https://google.com.security-check.example.com/login"
    )

    actual_domain = get_domain_from_hostname(
        hostname
    )

    print(
        "Hostname:",
        hostname
    )

    print(
        "Actual Domain:",
        actual_domain
    )

    print(
        analyze_subdomain(
            hostname,
            "google"
        )
    )

    print("\nA8 - Combined Brand Analysis")

    result = analyze_brand_impersonation(
        "google.com.security-check.example.com",
        "google"
    )

    print(result)

    print("\n--- A9 COMBINED ANALYSIS ---")

    result = analyze_url_features(
        "https://google-login-security.com/account/verify",
        "google"
    )

    print(result)