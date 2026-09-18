from urllib.parse import urlparse


def parse_url(url):
    parsed = urlparse(url)

    return {
        "scheme": parsed.scheme,
        "domain": parsed.netloc,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment
    }


# Test URL

