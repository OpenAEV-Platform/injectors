"""Embedded tracking web server (stdlib http.server, no framework).

Serves the open pixel, the landing page (click) and the credential-submission
endpoint (submit), recording each event against the campaign store. Runs on a
background thread next to the injector's RabbitMQ listener.
"""

import base64
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from phishing_injector.tracking.store import CampaignStore

# 1x1 transparent GIF.
PIXEL_GIF = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")

DEFAULT_LANDING_HTML = (
    "<html><body><h3>Please sign in</h3>"
    '<form method="POST" action="{submit_path}">'
    '<input name="username" placeholder="username" />'
    '<input name="password" type="password" placeholder="password" />'
    '<button type="submit">Sign in</button></form></body></html>'
)


def build_handler(
    store: CampaignStore,
    landing_html: str,
    redirect_url: str,
):
    class TrackingHandler(BaseHTTPRequestHandler):
        # Silence default stderr logging.
        def log_message(self, *args):  # noqa: N802
            return

        def _token(self, prefix: str) -> Optional[str]:
            if self.path.startswith(prefix):
                return self.path[len(prefix) :].split("?", 1)[0]
            return None

        def do_GET(self):  # noqa: N802
            open_token = self._token("/o/")
            if open_token is not None:
                store.record_open(open_token)
                self.send_response(200)
                self.send_header("Content-Type", "image/gif")
                self.end_headers()
                self.wfile.write(PIXEL_GIF)
                return

            click_token = self._token("/c/")
            if click_token is not None:
                store.record_click(click_token)
                page = landing_html.format(submit_path=f"/s/{click_token}")
                body = page.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            self.send_response(404)
            self.end_headers()

        def do_POST(self):  # noqa: N802
            submit_token = self._token("/s/")
            if submit_token is not None:
                length = int(self.headers.get("Content-Length", 0))
                if length:
                    self.rfile.read(length)  # consume body; never stored
                store.record_submit(submit_token)
                self.send_response(302)
                self.send_header("Location", redirect_url)
                self.end_headers()
                return

            self.send_response(404)
            self.end_headers()

    return TrackingHandler


class TrackingServer:
    def __init__(
        self,
        store: CampaignStore,
        host: str = "0.0.0.0",
        port: int = 8080,
        landing_html: str = DEFAULT_LANDING_HTML,
        redirect_url: str = "https://www.office.com/",
    ):
        handler = build_handler(store, landing_html, redirect_url)
        self._httpd = ThreadingHTTPServer((host, port), handler)
        self._thread: Optional[threading.Thread] = None

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    def start(self) -> None:
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
