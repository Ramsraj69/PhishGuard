from urllib.parse import urlparse


def uses_https(url):
    parsed = urlparse(url)
    return parsed.scheme.lower() == "https"


# Tests
print(uses_https("https://google.com"))
print(uses_https("http://google.com"))