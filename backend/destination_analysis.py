from urllib.parse import urlparse


def analyze_destination(original_url, final_url):
    """
    Compares the original URL with the final destination URL.
    """

    if not original_url or not final_url:
        return {
            "original_url": original_url,
            "final_url": final_url,
            "original_domain": None,
            "final_domain": None,
            "destination_changed": False,
            "domain_changed": False,
            "error": "Missing original or final URL"
        }

    original_parsed = urlparse(original_url)
    final_parsed = urlparse(final_url)

    original_domain = original_parsed.hostname
    final_domain = final_parsed.hostname

    if original_domain is None or final_domain is None:
        return {
            "original_url": original_url,
            "final_url": final_url,
            "original_domain": original_domain,
            "final_domain": final_domain,
            "destination_changed": False,
            "domain_changed": False,
            "error": "Invalid URL"
        }

    destination_changed = original_url != final_url
    domain_changed = original_domain.lower() != final_domain.lower()

    return {
        "original_url": original_url,
        "final_url": final_url,
        "original_domain": original_domain,
        "final_domain": final_domain,
        "destination_changed": destination_changed,
        "domain_changed": domain_changed
    }


if __name__ == "__main__":

    print("\n========== A13 DESTINATION ANALYSIS TEST ==========\n")

    test_cases = [
        {
            "original": "https://example.com",
            "final": "https://example.com"
        },
        {
            "original": "https://short.example/start",
            "final": "https://google.com/login"
        },
        {
            "original": "http://example.com",
            "final": "https://example.com"
        },
        {
            "original": "https://example.com",
            "final": ""
        },
        {
            "original": "",
            "final": "https://google.com"
        },
        {
            "original": "not-a-valid-url",
            "final": "https://google.com"
        },
        {
            "original": "https://example.com",
            "final": "not-a-valid-url"
        }
    ]

    for test in test_cases:

        result = analyze_destination(
            test["original"],
            test["final"]
        )

        print("Original URL:", result["original_url"])
        print("Final URL:", result["final_url"])
        print("Original Domain:", result["original_domain"])
        print("Final Domain:", result["final_domain"])
        print("Destination Changed:", result["destination_changed"])
        print("Domain Changed:", result["domain_changed"])

        if result.get("error"):
            print("Error:", result["error"])

        print("\n" + "-" * 50 + "\n")