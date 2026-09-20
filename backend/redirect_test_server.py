from flask import Flask, redirect

app = Flask(__name__)


@app.route("/start")
def start():
    return redirect(
        "http://127.0.0.1:8000/private",
        code=302
    )


@app.route("/private")
def private():
    return "PRIVATE SERVER REACHED"


if __name__ == "__main__":
    print("\nRedirect SSRF test server running at:")
    print("http://localhost:8000/start\n")

    app.run(
        host="0.0.0.0",
        port=8000,
        debug=False
    )