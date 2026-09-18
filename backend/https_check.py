from urllib.parse import urlparse


def uses_https(url):
    parsed = urlparse(url)
    return parsed.scheme.lower() == "https"


