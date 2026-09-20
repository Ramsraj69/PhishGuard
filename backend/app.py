from flask import Flask, request, jsonify
from flask_cors import CORS

from url_features import (
    analyze_url_features,
    TRUSTED_BRANDS
)

from risk_engine import calculate_risk_score
from redirect_check import check_redirects
from destination_analysis import analyze_destination
from reputation_check import check_reputation
from protection_engine import get_protection_action


app = Flask(__name__)
CORS(app)


# =========================================================
# BUILD RISK SIGNALS
# =========================================================

def build_risk_signals(
    analysis,
    brand_analysis,
    reputation_analysis,
    downgrade_analysis,
    redirect_analysis,
    destination_analysis
):

    signals = {}

    # Basic URL signals
    signals["long_url"] = analysis.get("long_url", False)
    signals["at_symbol"] = analysis.get("at_symbol", False)
    signals["deceptive_at_pattern"] = analysis.get(
        "deceptive_at_pattern",
        False
    )
    signals["encoded_characters"] = analysis.get(
        "encoded_characters",
        False
    )

    # Domain signals
    signals["long_domain"] = analysis.get(
        "long_domain",
        False
    )
    signals["excessive_numbers"] = analysis.get(
        "excessive_numbers",
        False
    )
    signals["excessive_hyphens"] = analysis.get(
        "excessive_hyphens",
        False
    )
    signals["suspicious_domain_pattern"] = analysis.get(
        "suspicious_domain_pattern",
        False
    )
    signals["lookalike_characters"] = analysis.get(
        "lookalike_characters",
        False
    )
    signals["deep_subdomain"] = analysis.get(
        "deep_subdomain",
        False
    )

    # Keywords
    signals["suspicious_keywords"] = bool(
        analysis.get("suspicious_keywords")
    )

    # HTTPS
    signals["not_https"] = not analysis.get(
        "https",
        False
    )

    # IP
    signals["ip_address"] = analysis.get(
        "ip_address",
        False
    )

    # Brand
    signals["impersonation"] = brand_analysis.get(
        "impersonation",
        False
    )

    signals["brand_hidden"] = brand_analysis.get(
        "brand_hidden",
        False
    )

    # Domain similarity
    signals["domain_similarity"] = analysis.get(
        "domain_similarity"
    )

    # Punycode / Unicode
    signals["punycode"] = analysis.get(
        "punycode",
        False
    )

    signals["unicode_confusable"] = analysis.get(
        "unicode_confusable",
        False
    )

    # Reputation
    signals["known_malicious"] = reputation_analysis.get(
        "known_malicious",
        False
    )

    # HTTPS downgrade
    signals["downgrade"] = downgrade_analysis.get(
        "downgrade",
        False
    )

    # Unusual port
    signals["unusual_port"] = analysis.get(
        "unusual_port",
        False
    )

    # =====================================================
    # REDIRECT / DESTINATION SIGNALS
    # =====================================================

    signals["redirect_detected"] = (
        redirect_analysis.get("redirect_count", 0) > 0
    )

    signals["domain_changed"] = destination_analysis.get(
        "domain_changed",
        False
    )

    signals["too_many_redirects"] = redirect_analysis.get(
        "too_many_redirects",
        False
    )

    return signals


# =========================================================
# ANALYZE URL
# =========================================================

def analyze_url(url):

    # -----------------------------------------------------
    # Trusted brand detection
    # -----------------------------------------------------

    detected_brand = None

    for brand in TRUSTED_BRANDS:

        brand_result = analyze_url_features(
            url,
            brand=brand
        )

        if brand_result.get("brand_analysis", {}).get(
            "impersonation",
            False
        ):
            detected_brand = brand
            break

    # -----------------------------------------------------
    # Main URL analysis
    # -----------------------------------------------------

    analysis = analyze_url_features(
        url,
        brand=detected_brand
    )

    # -----------------------------------------------------
    # Brand analysis
    # -----------------------------------------------------

    brand_analysis = analysis.get(
        "brand_analysis",
        {}
    )

    # -----------------------------------------------------
    # Reputation analysis
    # -----------------------------------------------------

    reputation_analysis = check_reputation(url)

    # -----------------------------------------------------
    # Redirect analysis
    # -----------------------------------------------------

    redirect_result = check_redirects(url)

    final_url = redirect_result.get(
        "final_url"
    )

    # If redirect checking failed or destination
    # could not be reached, keep original URL
    # for response handling.
    if final_url is None:
        final_url = url

    redirect_analysis = {
        "redirect_count": redirect_result.get(
            "redirect_count",
            0
        ),
        "redirect_chain": redirect_result.get(
            "redirect_chain",
            []
        ),
        "final_url": final_url,
        "too_many_redirects": redirect_result.get(
            "too_many_redirects",
            False
        )
    }

    if redirect_result.get("error"):

        redirect_analysis["error"] = redirect_result.get(
            "error"
        )

    # -----------------------------------------------------
    # Destination analysis
    # -----------------------------------------------------

    destination_analysis = analyze_destination(
        url,
        final_url
    )

    # -----------------------------------------------------
    # HTTPS downgrade
    # -----------------------------------------------------

    downgrade_analysis = {
        "downgrade": False
    }

    try:

        from urllib.parse import urlparse

        original_scheme = urlparse(url).scheme.lower()
        final_scheme = urlparse(final_url).scheme.lower()

        if (
            original_scheme == "https"
            and final_scheme == "http"
        ):
            downgrade_analysis["downgrade"] = True

    except Exception:

        downgrade_analysis["downgrade"] = False

    # -----------------------------------------------------
    # Build all risk signals
    # -----------------------------------------------------

    signals = build_risk_signals(
        analysis,
        brand_analysis,
        reputation_analysis,
        downgrade_analysis,
        redirect_analysis,
        destination_analysis
    )

    # -----------------------------------------------------
    # Calculate risk
    # -----------------------------------------------------

    risk_result = calculate_risk_score(
        signals
    )

    # -----------------------------------------------------
    # Protection decision
    # -----------------------------------------------------

    protection_result = get_protection_action(
        risk_result.get("risk_level")
    )

    # -----------------------------------------------------
    # Final response
    # -----------------------------------------------------

    return {
        "url": url,
        "analysis": analysis,
        "brand_analysis": {
            "brand_hidden": brand_analysis.get(
                "brand_hidden",
                False
            ),
            "impersonation": brand_analysis.get(
                "impersonation",
                False
            )
        },
        "https": analysis.get(
            "https",
            False
        ),
        "ip_address": analysis.get(
            "ip_address",
            False
        ),
        "reputation_analysis": reputation_analysis,
        "redirect_analysis": redirect_analysis,
        "destination_analysis": destination_analysis,
        "downgrade_analysis": downgrade_analysis,
        "risk_result": risk_result,
        "protection_result": protection_result
    }


# =========================================================
# API ENDPOINT
# =========================================================

@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json()

    if not data:

        return jsonify({
            "error": "JSON request body is required"
        }), 400

    url = data.get("url")

    if not url:

        return jsonify({
            "error": "URL is required"
        }), 400

    try:

        result = analyze_url(url)

        return jsonify(result)

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 500


# =========================================================
# SERVER
# =========================================================

if __name__ == "__main__":

    print("\n====================================")
    print("       PHISHGUARD API SERVER")
    print("====================================")
    print("Running at:")
    print("http://127.0.0.1:5000")
    print("====================================\n")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )