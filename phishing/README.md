# OpenAEV Native Phishing Injector

A fully self-contained phishing injector - no external Gophish server required.
The single container both launches the campaign and measures the human response:

- Embedded SMTP sender renders a bundled template (password reset, MFA
  re-enrollment, shared document) or custom HTML per recipient with a unique
  tracking token.
- Embedded tracking web server (stdlib `http.server`, background thread)
  exposes `GET /o/<token>` (open pixel), `GET /c/<token>` (click/landing page)
  and `POST /s/<token>` (submission), recording each event.
- Human-response results are aggregated per campaign and reported to the
  platform.

For a variant that leverages an existing Gophish deployment, see the `gophish`
injector.

## Constraints

- `phishing.public_url` MUST be reachable by the targets (reverse proxy + TLS in
  production); the tracking server listens on `listen_port` (default 8080).
- The token to recipient mapping is in-memory (MVP); a persistent store can be
  added for restart safety.
- Submitted credentials are never stored - only the fact of submission is
  recorded, for privacy.

## Development

```bash
poetry install
poetry run python -m unittest
```

## Icon

`phishing_injector/img/icon-phishing.png` must follow the injector icon standard
(square 1:1, 512x512 PNG, solid opaque background) - see
OpenAEV-Platform/injectors#305. This injector wraps no single vendor, so use a
clean generic phishing/security mark confirmed with the product team.
