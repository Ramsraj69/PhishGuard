def is_long_url(url):
    return len(url) > 100


# Test
print(is_long_url("https://google.com"))

long_url = "https://example.com/" + "a" * 120
print(is_long_url(long_url))
def has_at_symbol(url):
    return "@" in url


# Test
print(has_at_symbol("https://google.com"))
print(has_at_symbol("https://google.com@evil.example/login"))

def has_excessive_numbers(url):
    digit_count = sum(char.isdigit() for char in url)
    return digit_count > 5


# Test
print(has_excessive_numbers("https://google.com"))
print(has_excessive_numbers("https://secure-login-928374928374.com"))

def has_excessive_hyphens(url):
    hyphen_count = url.count("-")
    return hyphen_count > 2


# Test
print(has_excessive_hyphens("https://google.com"))
print(has_excessive_hyphens("https://google-login-security-update.com"))

def has_encoded_characters(url):
    return "%" in url

# Test
print(has_encoded_characters("https://google.com"))
print(has_encoded_characters("https://example.com/login%3Fverify"))

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
    print(find_suspicious_keywords("https://google.com"))

print(find_suspicious_keywords(
    "https://example.com/login/verify-account"
))

print(find_suspicious_keywords(
    "https://example.com/account/password"
))

print(find_suspicious_keywords(
    "https://secure-login-update.example.com"
))

print(find_suspicious_keywords(
    "https://example.com/products/shoes"
))

from urllib.parse import urlparse


def get_hostname(url):
    parsed = urlparse(url)
    return parsed.hostname


# Test
print(get_hostname("https://login.google.com/account"))
print(get_hostname("https://google.com"))

def count_subdomains(hostname):
    parts = hostname.split(".")

    return max(len(parts) - 2, 0)


# Test
print(count_subdomains("google.com"))
print(count_subdomains("login.google.com"))
print(count_subdomains("secure.login.google.com"))

def has_deep_subdomains(hostname):
    return count_subdomains(hostname) > 3


# Test
print(has_deep_subdomains("google.com"))
print(has_deep_subdomains("login.google.com"))
print(has_deep_subdomains("a.b.c.d.google.com"))

def has_brand_in_subdomain(hostname, brand):
    hostname = hostname.lower()
    brand = brand.lower()

    parts = hostname.split(".")

    # Remove the last two parts (main domain + extension)
    subdomain_parts = parts[:-2]

    return brand in subdomain_parts


# Test
print(has_brand_in_subdomain(
    "google.com.security-check.example.com",
    "google"
))

print(has_brand_in_subdomain(
    "login.google.com",
    "google"
))

def analyze_subdomain(hostname, brand):
    subdomain_count = count_subdomains(hostname)
    deep_subdomain = has_deep_subdomains(hostname)
    brand_hidden = has_brand_in_subdomain(hostname, brand)

    return {
        "subdomain_count": subdomain_count,
        "deep_subdomain": deep_subdomain,
        "brand_hidden": brand_hidden
    }


# Test
result = analyze_subdomain(
    "google.com.security-check.example.com",
    "google"
)

print(result)

def get_domain_from_hostname(hostname):
    parts = hostname.split(".")

    if len(parts) < 2:
        return hostname

    return ".".join(parts[-2:])


# Test
print(get_domain_from_hostname("login.google.com"))
print(get_domain_from_hostname("google.com"))

def is_long_domain(domain):
    return len(domain) > 30


# Test
print(is_long_domain("google.com"))
print(is_long_domain("secure-account-verification-login-update.com"))

def analyze_domain_characters(domain):
    digit_count = sum(char.isdigit() for char in domain)
    hyphen_count = domain.count("-")

    return {
        "digit_count": digit_count,
        "hyphen_count": hyphen_count,
        "excessive_numbers": digit_count > 4,
        "excessive_hyphens": hyphen_count > 2
    }


# Test
print(analyze_domain_characters("google.com"))

print(analyze_domain_characters(
    "google-login-security-928374.com"
))

from difflib import SequenceMatcher

def domain_similarity(domain, trusted_domain):
    domain = domain.lower()
    trusted_domain = trusted_domain.lower()

    return SequenceMatcher(None, domain, trusted_domain).ratio()


# Test
print(domain_similarity("google.com", "google.com"))
print(domain_similarity("gooogle.com", "google.com"))
print(domain_similarity("randomsite.com", "google.com"))

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


# Test
print(has_suspicious_domain_pattern("google.com"))

print(has_suspicious_domain_pattern(
    "google-login-security-update.com"
))

print(has_suspicious_domain_pattern(
    "secure-account-92837.com"
))

print(domain_similarity("gooogle.com", "google.com"))
print(domain_similarity("goog1e.com", "google.com"))
print(domain_similarity("google.com", "google.com"))
print(domain_similarity("randomsite.com", "google.com"))