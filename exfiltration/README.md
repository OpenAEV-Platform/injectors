# OpenAEV Data Exfiltration Injector

Exercises egress filtering and DLP controls by simulating data exfiltration from
the injector container. Payloads are random bytes (no real sensitive data), so
nothing confidential ever leaves the environment.

## Contracts

- Exfiltration - DNS tunneling: encodes a random payload into DNS queries to a
  controlled domain.
- Exfiltration - HTTPS upload: POSTs a random payload to a controlled endpoint.
- Exfiltration - Cloud storage upload: PUTs a random payload to a cloud storage
  URL (e.g. a presigned S3 URL).

A blocked attempt is a valid outcome (it means prevention worked); the injector
reports the observed result and the DETECTION / PREVENTION expectations are
scored by the relevant collectors.

## Development

```bash
poetry install
poetry run python -m unittest
```

## Icon

`exfiltration_injector/img/icon-exfiltration.png` must follow the injector icon
standard (square 1:1, 512x512 PNG, solid opaque background) - see
OpenAEV-Platform/injectors#305. This injector wraps no single vendor, so use a
clean generic exfiltration/DLP mark confirmed with the product team.
