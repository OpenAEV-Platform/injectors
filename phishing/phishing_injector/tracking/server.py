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

# Cap the credential-submission body so a malicious/oversized Content-Length
# cannot tie up a handler thread reading an unbounded request body.
MAX_SUBMIT_BODY_BYTES = 64 * 1024

# Socket read timeout for every request. Without it, a client can advertise a
# small Content-Length and then slow-send (or never finish) the body, keeping a
# handler thread blocked indefinitely (slowloris-style) and defeating the size
# cap above. StreamRequestHandler applies this via socket.settimeout(), so a
# stalled read raises and frees the thread.
REQUEST_TIMEOUT_SECONDS = 10

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
        # Bound every request so a stalled/slow client cannot pin a handler
        # thread indefinitely while reading headers or the body.
        timeout = REQUEST_TIMEOUT_SECONDS

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
                # Prevent browsers/proxies from caching the pixel, which would
                # undercount repeated opens and shared clients.
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
                self.send_header("Pragma", "no-cache")
                self.send_header("Expires", "0")
                self.send_header("Content-Length", str(len(PIXEL_GIF)))
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
                try:
                    length = int(self.headers.get("Content-Length", 0))
                except (TypeError, ValueError):
                    length = -1
                if length < 0 or length > MAX_SUBMIT_BODY_BYTES:
                    # The body is not drained (it may be absent, malformed or
                    # oversized), so unread bytes could remain on the socket.
                    # Force the connection closed to avoid desynchronizing a
                    # keep-alive client (leftover bytes read as the next request).
                    self.close_connection = True
                    self.send_response(413)
                    self.end_headers()
                    return
                if length:
                    try:
                        self.rfile.read(length)  # consume body; never stored
                    except (TimeoutError, OSError):
                        # A slow/stalled client hit the per-request socket
                        # timeout mid-body. Close the connection instead of
                        # letting the exception bubble up to
                        # BaseHTTPRequestHandler as a logged traceback.
                        self.close_connection = True
                        return
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
        # shutdown() must only be called while serve_forever() is running on
        # the background thread; calling it before start() would deadlock, so
        # guard it behind the started-thread check. server_close() is always
        # safe and releases the listening socket.
        if self._thread is not None:
            self._httpd.shutdown()
            self._thread.join(timeout=5)
            self._thread = None
        self._httpd.server_close()
