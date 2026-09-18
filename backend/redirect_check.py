import requests
from url_security import validate_url_for_request


def check_redirects(url, max_redirects=5):

    redirect_chain = []
    current_url = url

    # Validate the initial URL before making a request
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

            # No redirect — final destination reached
            if response.status_code not in [301, 302, 303, 307, 308]:

                return {
                    "redirect_count": len(redirect_chain) - 1,
                    "redirect_chain": redirect_chain,
                    "final_url": current_url,
                    "too_many_redirects": False
                }

            # Get redirect destination
            next_url = response.headers.get("Location")

            if not next_url:

                return {
                    "redirect_count": len(redirect_chain) - 1,
                    "redirect_chain": redirect_chain,
                    "final_url": current_url,
                    "too_many_redirects": False
                }

            # Build the next absolute URL
            current_url = requests.compat.urljoin(
                current_url,
                next_url
            )

            # Validate the redirect destination
            security_check = validate_url_for_request(current_url)

            if not security_check["allowed"]:
                redirect_chain.append(current_url)

                return {
                    "redirect_count": len(redirect_chain) - 1,
                    "redirect_chain": redirect_chain,
                    "final_url": None,
                    "too_many_redirects": False,
                    "error": security_check["reason"]
                }

        return {
            "redirect_count": len(redirect_chain) - 1,
            "redirect_chain": redirect_chain,
            "final_url": current_url,
            "too_many_redirects": True
        }

    except requests.RequestException as e:

        return {
            "redirect_count": len(redirect_chain) - 1,
            "redirect_chain": redirect_chain,
            "final_url": None,
            "too_many_redirects": False,
            "error": str(e)
        }


if __name__ == "__main__":

    test_url = "http://localhost:8000/start"

    result = check_redirects(test_url)

    print("\n========== A18 SAFE REDIRECT TEST ==========\n")
    print("Redirect Count:", result["redirect_count"])

    print("Redirect Chain:")

    for url in result["redirect_chain"]:
        print("-", url)

    print("Final URL:", result["final_url"])
    print("Too Many Redirects:", result["too_many_redirects"])

    if result.get("error"):
        print("Error:", result["error"])