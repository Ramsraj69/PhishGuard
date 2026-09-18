from host_analysis import analyze_host
from url_parser import parse_url
from ip_check import is_ip_address
from https_check import uses_https

from url_features import (
    is_long_url,
    has_at_symbol,
    has_deceptive_at_pattern,
    has_excessive_numbers,
    has_excessive_hyphens,
    has_encoded_characters,
    find_suspicious_keywords
)

from brand_detection import analyze_brand_impersonation
from redirect_check import check_redirects
from destination_analysis import analyze_destination
from downgrade_check import is_https_to_http_downgrade
from reputation_check import check_reputation
from risk_engine import calculate_risk_score


def analyze_url(url):
    """
    Main PhishGuard analysis pipeline.
    """

    parsed_url = parse_url(url)
    hostname = parsed_url["domain"]

    ip_address = is_ip_address(hostname)
    https = uses_https(url)

    host_analysis = analyze_host(url)

    url_features = {
        "long_url": is_long_url(url),
        "at_symbol": has_at_symbol(url),
        "deceptive_at_pattern": has_deceptive_at_pattern(url),
        "excessive_numbers": has_excessive_numbers(url),
        "excessive_hyphens": has_excessive_hyphens(url),
        "encoded_characters": has_encoded_characters(url),
        "suspicious_keywords": find_suspicious_keywords(url)
    }

    brand_analysis = analyze_brand_impersonation(url)

    redirect_analysis = check_redirects(url)

    final_url = redirect_analysis.get("final_url")

    destination_analysis = analyze_destination(
        url,
        final_url
    )

    if final_url:
        downgrade_analysis = is_https_to_http_downgrade(
            url,
            final_url
        )
    else:
        downgrade_analysis = {
            "downgrade": False,
            "error": "Final URL unavailable"
        }

    reputation_analysis = check_reputation(url)

    signals = {
        "long_url": url_features["long_url"],
        "at_symbol": url_features["at_symbol"],
        "deceptive_at_pattern": url_features["deceptive_at_pattern"],
        "unusual_port": host_analysis["unusual_port"],
        "excessive_numbers": url_features["excessive_numbers"],
        "excessive_hyphens": url_features["excessive_hyphens"],
        "encoded_characters": url_features["encoded_characters"],
        "suspicious_keywords": bool(
            url_features["suspicious_keywords"]
        ),
        "not_https": not https,
        "ip_address": ip_address,
        "impersonation": brand_analysis["impersonation"],
        "known_malicious": (
            reputation_analysis["reputation_status"]
            == "known_malicious"
        ),
        "downgrade": downgrade_analysis["downgrade"]
    }

    risk_result = calculate_risk_score(signals)

    return {
        "url": url,
        "parsed_url": parsed_url,
        "ip_address": ip_address,
        "https": https,
        "host_analysis": host_analysis,
        "url_features": url_features,
        "brand_analysis": brand_analysis,
        "redirect_analysis": redirect_analysis,
        "destination_analysis": destination_analysis,
        "downgrade_analysis": downgrade_analysis,
        "reputation_analysis": reputation_analysis,
        "risk_result": risk_result
    }


if __name__ == "__main__":

    print("\n========== A15 PIPELINE TEST ==========\n")

    test_urls = [
        "https://google.com",
        "http://malicious.example.com/login",
        "https://example.com/google/login",
        "https://example.com/account/update/security",
        "https://google.com/account/verify/security",
        "https://google.com.security-check.example.com/login/verify",
        "https://gooogle.com/login/verify",
        "https://google.com/security/account/login",
        "https://google.com/account/login?verify=security&update=password",
        "http://gooogle.com/login/verify/account",
        "http://192.168.1.50/login/verify/account",
        "http://google.com@evil-example.com/login",
        "https://google.com@evil-example.com/login",
        "https://google.com@evil-example.com/account/login",
            "https://example.com:4444/login"
    ]

    for test_url in test_urls:

        result = analyze_url(test_url)

        print("URL:", result["url"])

        print(
            "Reputation:",
            result["reputation_analysis"]["reputation_status"]
        )

        print(
            "HTTPS → HTTP Downgrade:",
            result["downgrade_analysis"]["downgrade"]
        )

        print(
            "Risk Score:",
            result["risk_result"]["risk_score"]
        )

        print(
            "Risk Level:",
            result["risk_result"]["risk_level"]
        )

        print("Reasons:")

        for reason in result["risk_result"]["reasons"]:
            print("-", reason)

        print("\n" + "-" * 50 + "\n")

    print("\n========== DOWNGRADE INTEGRATION TEST ==========\n")

    signals = {
        "downgrade": True
    }

    risk_result = calculate_risk_score(signals)

    print("Simulated HTTPS → HTTP downgrade")
    print("Risk Score:", risk_result["risk_score"])
    print("Risk Level:", risk_result["risk_level"])
    print("Reasons:")

    for reason in risk_result["reasons"]:
        print("-", reason)