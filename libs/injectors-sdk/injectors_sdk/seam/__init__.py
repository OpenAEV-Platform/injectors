"""The seam: the stable boundary between the public surface and ``_core``.

- **``helpers``** — the injector runtime: registration, heartbeat and inject
  queue listening.

The public layer reaches ``_core`` exclusively through this layer; nothing in
``_core`` imports ``public``.
"""
