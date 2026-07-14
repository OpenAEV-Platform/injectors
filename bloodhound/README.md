# OpenAEV BloodHound AD Injector

Runs the [BloodHound.py](https://github.com/dirkjanm/BloodHound.py) Active
Directory collector (SharpHound-compatible) and surfaces users, computers and
privilege-escalation attack paths (Kerberoastable, AS-REP roastable) as
findings.

## Contract

- BloodHound - Collect AD attack paths: fields for domain, username, password
  and domain controller. Produces VULNERABILITY (attack paths exist) and
  DETECTION (enumeration detected) expectations.

## Credentials

The AD credentials are provided per inject through the contract fields and are
never logged (the password argument is redacted in logs).

## Development

```bash
poetry install
poetry run python -m unittest
```

## Icon

`bloodhound_injector/img/icon-bloodhound.png` must follow the injector icon
standard (square 1:1, 512x512 PNG, solid opaque background, genuine BloodHound
artwork) - see OpenAEV-Platform/injectors#305.
