import requests


def check_redirects(url, max_redirects=5):

    try:
        response = requests.get(
            url,
            allow_redirects=True,
            timeout=5
        )

        redirect_count = len(response.history)

        if redirect_count > max_redirects:
            return {
                "redirect_count": redirect_count,
                "redirect_chain": [r.url for r in response.history],
                "final_url": response.url,
                "too_many_redirects": True
            }

        redirect_chain = [r.url for r in response.history]
        redirect_chain.append(response.url)

        return {
            "redirect_count": redirect_count,
            "redirect_chain": redirect_chain,
            "final_url": response.url,
            "too_many_redirects": False
        }

    except requests.RequestException as e:

        return {
            "redirect_count": 0,
            "redirect_chain": [],
            "final_url": None,
            "too_many_redirects": False,
            "error": str(e)
        }


if __name__ == "__main__":

    test_url = "https://www.google.com"

    result = check_redirects(test_url)

    print("\n========== A11 REDIRECT TEST ==========\n")
    print("Redirect Count:", result["redirect_count"])
    print("Redirect Chain:")

    for url in result["redirect_chain"]:
        print("-", url)

    print("Final URL:", result["final_url"])

    if result.get("too_many_redirects"):
        print("WARNING: Too many redirects!")

    if result.get("error"):
        print("Error:", result["error"])