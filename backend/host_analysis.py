from urllib.parse import urlparse



COMMON_PORTS = {
    80,
    443,
    8080,
    8443
}


def analyze_host(url):
    parsed = urlparse(url)

    hostname = parsed.hostname
    port = parsed.port

    if hostname is None:
        return {
            "hostname": None,
            "port": None,
            "unusual_port": False,
            "error": "Invalid URL hostname"
        }

    if port is None:
        return {
            "hostname": hostname,
            "port": None,
            "unusual_port": False
        }

    return {
        "hostname": hostname,
        "port": port,
        "unusual_port": port not in COMMON_PORTS
    }