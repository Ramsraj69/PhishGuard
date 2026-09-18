import ipaddress
import socket
from urllib.parse import urlparse


def is_private_or_local_host(hostname):
    if not hostname:
        return True

    hostname = hostname.lower().rstrip(".")

    # Block obvious local hostnames
    if hostname in {"localhost", "localhost.localdomain"}:
        return True

    try:
        ip = ipaddress.ip_address(hostname)

        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        )

    except ValueError:
        pass

    # Resolve domain names and check their IP addresses
    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
            ):
                return True

    except (socket.gaierror, ValueError, OSError):
        return False

    return False


def validate_url_for_request(url):
    parsed = urlparse(url)

    if parsed.scheme.lower() not in {"http", "https"}:
        return {
            "allowed": False,
            "reason": "Only HTTP and HTTPS URLs are allowed"
        }

    hostname = parsed.hostname

    if not hostname:
        return {
            "allowed": False,
            "reason": "URL does not contain a valid hostname"
        }

    if is_private_or_local_host(hostname):
        return {
            "allowed": False,
            "reason": "Private or local network address blocked"
        }

    return {
        "allowed": True,
        "reason": "URL is allowed for network request"
    }

if __name__ == "__main__":

    test_urls = [
        "https://google.com",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://192.168.1.50/login",
        "http://10.0.0.5/login",
        "https://example.com"
    ]

    for url in test_urls:
        print("\nURL:", url)
        print(validate_url_for_request(url))