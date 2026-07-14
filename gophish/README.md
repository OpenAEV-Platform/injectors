# OpenAEV Gophish Injector

Launches phishing simulation campaigns through a [Gophish](https://getgophish.com/)
server and reports open / click / credential-submission activity as
human-response expectations.

For a self-contained option that needs no external server, see the native
`phishing` injector.

## How it works

- Gophish server connection (`GOPHISH_BASE_URL`, `GOPHISH_API_KEY`) is injector
  configuration; per-campaign parameters (template, landing page, sending
  profile, target group, URL) are contract fields.
- The injector creates and launches the campaign via `POST /api/campaigns/` and
  reports the initial campaign id and stats. Open/click/submit progress is read
  from the campaign `stats`.

## Development

```bash
poetry install
poetry run python -m unittest
```

## Icon

`gophish_injector/img/icon-gophish.png` must follow the injector icon standard
(square 1:1, 512x512 PNG, solid opaque background, genuine Gophish artwork) -
see OpenAEV-Platform/injectors#305.
