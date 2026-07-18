# OpenAEV Censys Injector

Queries the [Censys](https://censys.io/) Search API to discover an
organization's external attack surface - exposed hosts, open ports and
certificates - complementing the existing Shodan injector.

## Contracts

- Censys - Host search: returns matching hosts (IPv4) and distinct ports as
  findings.
- Censys - Certificate search: returns matching certificate fingerprints.

## Credentials

Censys Search API credentials (`CENSYS_API_ID`, `CENSYS_API_SECRET`) are
injector-level operator credentials configured in `config.yml`/`.env`, never
logged.

## Development

```bash
poetry install
poetry run python -m unittest
```

## Icon

`censys_injector/img/icon-censys.png` currently ships as a square opaque
512x512 placeholder; it must be replaced with genuine Censys brand artwork
following the injector icon standard (square 1:1, 512x512 PNG, solid opaque
background) - tracked by OpenAEV-Platform/injectors#305.
