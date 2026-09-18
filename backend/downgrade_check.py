from urllib.parse import urlparse


def is_https_to_http_downgrade(original_url, final_url):
    """
    Detects whether a URL changed from HTTPS to HTTP.
    """

    if not original_url or not final_url:
        return {
            "downgrade": False,
            "error": "Missing original or final URL"
        }

    original = urlparse(original_url)
    final = urlparse(final_url)

    if not original.scheme or not final.scheme:
        return {
            "downgrade": False,
            "error": "Invalid URL"
        }

    downgrade = (
        original.scheme.lower() == "https"
        and final.scheme.lower() == "http"
    )

    return {
        "downgrade": downgrade
    }


if __name__ == "__main__":

    print("\n========== A14 HTTPS → HTTP DOWNGRADE TEST ==========\n")

    test_cases = [
        {
            "name": "HTTPS to HTTP",
            "original": "https://example.com",
            "final": "http://example.com"
        },
        {
            "name": "HTTPS to HTTPS",
            "original": "https://example.com",
            "final": "https://google.com"
        },
        {
            "name": "HTTP to HTTPS",
            "original": "http://example.com",
            "final": "https://example.com"
        },
        {
            "name": "Same HTTPS URL",
            "original": "https://example.com",
            "final": "https://example.com"
        },
        {
            "name": "Missing final URL",
            "original": "https://example.com",
            "final": ""
        },
        {
            "name": "Invalid original URL",
            "original": "not-a-valid-url",
            "final": "http://example.com"
        }
    ]

    for test in test_cases:

        result = is_https_to_http_downgrade(
            test["original"],
            test["final"]
        )

        print("Test:", test["name"])
        print("Original:", test["original"])
        print("Final:", test["final"])
        print("Downgrade:", result["downgrade"])

        if result.get("error"):
            print("Error:", result["error"])

        print("\n" + "-" * 50 + "\n")
        