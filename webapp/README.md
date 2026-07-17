# OpenAEV Web Application Attack Injector

Performs active web-application testing using [OWASP ZAP](https://www.zaproxy.org/)
(baseline scan) and [SQLMap](https://sqlmap.org/) (SQL injection), surfacing
discovered issues as findings.

## Contracts

- Web App - OWASP ZAP baseline scan: runs `zap-baseline.py` against the target
  and reports alerts as vulnerability findings.
- Web App - SQLMap injection test: runs `sqlmap` against the target URL and
  reports injectable parameters.

DETECTION (WAF/monitoring) and VULNERABILITY expectations are scored by the
relevant collectors.

## Development

```bash
poetry install
poetry run python -m unittest
```

## Icon

`webapp_injector/img/icon-webapp.png` must follow the injector icon standard
(square 1:1, 512x512 PNG, solid opaque background, genuine OWASP ZAP artwork) -
see OpenAEV-Platform/injectors#305.
