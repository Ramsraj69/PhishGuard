from url_features import domain_similarity
from urllib.parse import urlparse
import tldextract

# ==========================================
# A8.1 - Get Hostname
# ==========================================

def get_hostname(url):
    parsed = urlparse(url)
    return parsed.hostname


# ==========================================
# A8.1 - Get Real Domain
# ==========================================

def get_real_domain(hostname):
    if hostname is None:
        return None

    extracted = tldextract.extract(hostname)

    if not extracted.domain or not extracted.suffix:
        return hostname

    return f"{extracted.domain}.{extracted.suffix}"


# ==========================================
# Trusted Brands
# ==========================================

TRUSTED_BRANDS = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "paypal": "paypal.com",
    "instagram": "instagram.com"
}


# ==========================================
# A8.2 - Find Claimed Brands
# ==========================================

def find_claimed_brands(hostname):
    hostname = hostname.lower()

    claimed_brands = []

    for brand in TRUSTED_BRANDS:
        if brand in hostname:
            claimed_brands.append(brand)

    return claimed_brands


# ==========================================
# A8.3 - Check Brand Domain
# ==========================================

def check_brand_domain(hostname, claimed_brand):
    real_domain = get_real_domain(hostname)

    trusted_domain = TRUSTED_BRANDS.get(claimed_brand)

    if trusted_domain is None:
        return False

    return real_domain == trusted_domain


# ==========================================
# A8.5 - Normalize Lookalike Names
# ==========================================

def normalize_lookalike_name(name):
    replacements = {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s"
    }

    normalized = ""

    for char in name:
        normalized += replacements.get(char, char)

    return normalized


# ==========================================
# A8.5 - Find Lookalike Brands
# ==========================================

def find_lookalike_brands(real_domain):
    lookalikes = []

    real_domain = real_domain.lower()
    real_name = real_domain.split(".")[0]

    normalized_real_name = normalize_lookalike_name(real_name)

    for brand, trusted_domain in TRUSTED_BRANDS.items():

        trusted_name = trusted_domain.split(".")[0]

        normalized_trusted_name = normalize_lookalike_name(
            trusted_name
        )

        similarity = domain_similarity(
            normalized_real_name,
            normalized_trusted_name
        )

        if similarity >= 0.85 and real_domain != trusted_domain:
            lookalikes.append({
                "brand": brand,
                "trusted_domain": trusted_domain,
                "similarity": similarity
            })

    return lookalikes


# ==========================================
# A8.7 - Punycode Detection
# ==========================================

def has_punycode(hostname):
    if hostname is None:
        return False

    hostname = hostname.lower()

    return "xn--" in hostname


# ==========================================
# A8.8 - Complete Brand Impersonation Analysis
# ==========================================

def analyze_brand_impersonation(url):

    hostname = get_hostname(url)

    # Invalid URL / no hostname
    if hostname is None:
        return {
            "claimed_brands": [],
            "real_domain": None,
            "suspicious_brands": [],
            "lookalike_brands": [],
            "punycode": False,
            "impersonation": False
        }

    # Find brands mentioned in hostname
    claimed_brands = find_claimed_brands(hostname)

    # Find actual domain
    real_domain = get_real_domain(hostname)

    # Check whether claimed brand actually owns the domain
    suspicious_brands = []

    for brand in claimed_brands:

        trusted_domain = TRUSTED_BRANDS[brand]

        if real_domain != trusted_domain:
            suspicious_brands.append(brand)

    # Check for lookalike / typosquatting domains
    lookalike_brands = find_lookalike_brands(real_domain)

    # Check for Punycode
    punycode_detected = has_punycode(hostname)

    # Final impersonation signal
    impersonation = (
        len(suspicious_brands) > 0
        or len(lookalike_brands) > 0
    )

    return {
        "claimed_brands": claimed_brands,
        "real_domain": real_domain,
        "suspicious_brands": suspicious_brands,
        "lookalike_brands": lookalike_brands,
        "punycode": punycode_detected,
        "impersonation": impersonation
    }


# ==========================================
# TESTS
# ==========================================

print("\n========== A8 ADVERSARIAL TESTS ==========\n")

test_urls = [
    # Legitimate
    "https://google.com",
    "https://accounts.google.com/login",
    "https://microsoft.com",
    "https://paypal.com",

    # Hidden brand
    "https://google.com.security-check.example.com/login",
    "https://secure.google.example.com/login",

    # Lookalikes
    "https://gooogle.com/login",
    "https://goog1e.com/login",
    "https://g00gle.com/login",
    "https://paypa1.com/login",

    # Brand + hyphen
    "https://google-login.com",
    "https://google-secure.com",
    "https://paypal-login.com",
    "https://microsoft-security.com",

    # Brand in deeper subdomain
    "https://login.google.security.example.com",
    "https://account.paypal.verify.example.com",

    # Random
    "https://mycollege.com/login",
    "https://shopping-example.com"
]


for url in test_urls:
    print("\nURL:", url)
    print(analyze_brand_impersonation(url))


print("\n========== LOOKALIKE TESTS ==========\n")


print("Google:", find_lookalike_brands("google.com"))

print("Gooogle:", find_lookalike_brands("gooogle.com"))

print("Goog1e:", find_lookalike_brands("goog1e.com"))

print("G00gle:", find_lookalike_brands("g00gle.com"))

print("Random:", find_lookalike_brands("randomsite.com"))


print("\n========== PUNYCODE TESTS ==========\n")


print(
    "Punycode test 1:",
    has_punycode("xn--google-example.com")
)

print(
    "Punycode test 2:",
    has_punycode("google.com"))

print("\n========== A8.9 DOMAIN EXTRACTION TESTS ==========\n")

domain_test_urls = [
    "https://example.co.uk/login",
    "https://secure.example.co.uk/account",
    "https://example.com.au/login",
    "https://college.ac.in/login",
    "https://accounts.google.com/login",
    "https://google.com.security-check.example.com/login"
]

for url in domain_test_urls:
    hostname = get_hostname(url)

    print("URL:", url)
    print("Hostname:", hostname)
    print("Real domain:", get_real_domain(hostname))
    print()