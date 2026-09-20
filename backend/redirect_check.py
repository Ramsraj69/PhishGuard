import requests
from unittest.mock import patch
from url_security import validate_url_for_request


def check_redirects(url, max_redirects=5):

    redirect_chain = []
    current_url = url

    security_check = validate_url_for_request(current_url)

    if not security_check["allowed"]:
        return {
            "redirect_count": 0,
            "redirect_chain": [],
            "final_url": None,
            "too_many_redirects": False,
            "error": security_check["reason"]
        }

    try:

        for _ in range(max_redirects + 1):

            response = requests.get(
                current_url,
                allow_redirects=False,
                timeout=5
            )

            redirect_chain.append(current_url)

            # Final destination reached
            if response.status_code not in [301, 302, 303, 307, 308]:

                return {
                    "redirect_count": len(redirect_chain) - 1,
                    "redirect_chain": redirect_chain,
                    "final_url": current_url,
                    "too_many_redirects": False
                }

            next_url = response.headers.get("Location")

            if not next_url:

                return {
                    "redirect_count": len(redirect_chain) - 1,
                    "redirect_chain": redirect_chain,
                    "final_url": current_url,
                    "too_many_redirects": False
                }

            # Convert relative URL to absolute URL
            next_url = requests.compat.urljoin(
                current_url,
                next_url
            )

            # SECURITY CHECK BEFORE FOLLOWING REDIRECT
            security_check = validate_url_for_request(next_url)

            if not security_check["allowed"]:

                redirect_chain.append(next_url)

                return {
                    "redirect_count": len(redirect_chain) - 1,
                    "redirect_chain": redirect_chain,
                    "final_url": None,
                    "too_many_redirects": False,
                    "error": security_check["reason"]
                }

            current_url = next_url

        return {
            "redirect_count": max(
                0,
                len(redirect_chain) - 1
            ),
            "redirect_chain": redirect_chain,
            "final_url": None,
            "too_many_redirects": True
        }

    except requests.RequestException as e:

        return {
            "redirect_count": max(
                0,
                len(redirect_chain) - 1
            ),
            "redirect_chain": redirect_chain,
            "final_url": None,
            "too_many_redirects": False,
            "error": str(e)
        }


def run_normal_redirect_test():

    print("\n========== NORMAL REDIRECT TEST ==========\n")

    test_url = "https://httpbin.org/redirect/2"

    result = check_redirects(test_url)

    print("Redirect Count:", result["redirect_count"])

    print("\nRedirect Chain:")

    for url in result["redirect_chain"]:
        print("-", url)

    print("\nFinal URL:", result["final_url"])
    print("Too Many Redirects:", result["too_many_redirects"])

    if result.get("error"):
        print("Error:", result["error"])


def run_ssrf_redirect_test():

    print("\n========== SSRF REDIRECT TEST ==========\n")

    safe_url = "https://safe.example.com/start"
    private_url = "http://127.0.0.1:8000/private"

    class MockResponse:

        status_code = 302

        headers = {
            "Location": private_url
        }

    def fake_get(*args, **kwargs):

        return MockResponse()

    with patch(
        "redirect_check.requests.get",
        side_effect=fake_get
    ):

        result = check_redirects(safe_url)

    print("Starting URL:", safe_url)
    print("Redirect Target:", private_url)

    print("\nRedirect Count:", result["redirect_count"])

    print("Redirect Chain:")

    for url in result["redirect_chain"]:
        print("-", url)

    print("\nFinal URL:", result["final_url"])
    print("Too Many Redirects:", result["too_many_redirects"])
    print("Error:", result.get("error"))

    if result.get("error") == "Private or local network address blocked":

        print("\nRESULT: SSRF REDIRECT BLOCKED SUCCESSFULLY")

    else:

        print("\nRESULT: SSRF TEST FAILED")


if __name__ == "__main__":

    run_normal_redirect_test()

    run_ssrf_redirect_test()