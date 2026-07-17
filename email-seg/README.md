# OpenAEV Email Gateway (SEG) Injector

Assesses a Secure Email Gateway by sending safe, industry-standard test payloads
to a target mailbox and measuring what the gateway blocks, strips or delivers.
No external tool is required - the injector sends over SMTP natively.

## Payloads

- EICAR test string in the email body
- EICAR test file attachment (`eicar.com`)
- EICAR test file inside a zip archive (evasion)
- Test URL in the body (URL filtering)

All payloads use the EICAR antivirus test artifact (not malware) or a benign
configurable URL, so no real malicious content is transmitted.

## Expectations

PREVENTION (the gateway blocked/stripped the payload) and DETECTION. Scoring is
completed by the operator or by EDR/SIEM alerting collectors.

## Credentials

SMTP profile fields are provided per inject through the contract; only the
OpenAEV connection lives in `config.yml`/`.env`. SMTP passwords are never logged.

## Development

```bash
poetry install
poetry run python -m unittest
```

## Icon

`email_seg/img/icon-email-seg.png` must follow the injector icon standard
(square 1:1, 512x512 PNG, solid opaque background) - see
OpenAEV-Platform/injectors#305. This injector wraps no single vendor, so use a
clean generic email/security mark confirmed with the product team.
