import requests


def check_redirects(url, max_redirects=5):

    redirect_chain = []
    current_url = url

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

            # Move to the next URL
            current_url = requests.compat.urljoin(
                current_url,
                next_url
            )

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

    print("\n========== A11 SAFE REDIRECT TEST ==========\n")
    print("Redirect Count:", result["redirect_count"])
    print("Redirect Chain:")

    for url in result["redirect_chain"]:
        print("-", url)

    print("Final URL:", result["final_url"])
    print("Too Many Redirects:", result["too_many_redirects"])

    if result.get("error"):
        print("Error:", result["error"])