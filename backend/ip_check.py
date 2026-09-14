import ipaddress


def is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


# Tests
print(is_ip_address("192.168.1.50"))
print(is_ip_address("google.com"))
