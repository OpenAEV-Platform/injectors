# OpenAEV C2 Emulation Injector

Emulates command-and-control beaconing traffic with configurable interval and
jitter toward a listener, so NDR and network C2 detections (e.g. the NetWitness
collector) can be validated. Point it at a [Sliver](https://github.com/BishopFox/sliver)
or Mythic HTTP listener, or any sink.

Rather than deploying a full C2 framework inside the injector, it generates the
observable beaconing pattern (periodic callbacks, malware-like user agent, jitter)
that network detections key on. A blocked beacon still generates traffic and is a
valid outcome.

## Contract

- C2 - Emulate beaconing: fields for listener URL, beacon profile, count,
  interval and jitter. Produces a DETECTION expectation.

## Development

```bash
poetry install
poetry run python -m unittest
```

## Icon

`c2_injector/img/icon-c2.png` must follow the injector icon standard (square
1:1, 512x512 PNG, solid opaque background, genuine Sliver artwork) - see
OpenAEV-Platform/injectors#305.
