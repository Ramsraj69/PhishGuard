from urllib.parse import urlparse
import tldextract


def analyze_destination(original_url, final_url):

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

    original_registered = (
        tldextract.extract(original_domain).registered_domain
    )

    final_registered = (
        tldextract.extract(final_domain).registered_domain
    )

    domain_changed = (
        original_registered.lower()
        != final_registered.lower()
    )

    return {
        "original_url": original_url,
        "final_url": final_url,
        "original_domain": original_domain,
        "final_domain": final_domain,
        "destination_changed": destination_changed,
        "domain_changed": domain_changed
    }