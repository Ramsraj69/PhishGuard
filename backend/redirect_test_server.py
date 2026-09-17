from http.server import BaseHTTPRequestHandler, HTTPServer


class RedirectHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        if self.path == "/start":
            self.redirect("/step1")

        elif self.path == "/step1":
            self.redirect("/step2")

        elif self.path == "/step2":
            self.redirect("/final")

        elif self.path == "/final":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Final destination reached.")

        else:
            self.send_response(404)
            self.end_headers()

    def redirect(self, location):

        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()


if __name__ == "__main__":

    server = HTTPServer(("localhost", 8000), RedirectHandler)

    print("Redirect test server running at:")
    print("http://localhost:8000/start")

    server.serve_forever()