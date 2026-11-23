# injectors-sdk

The **injector runtime** of the OpenAEV connector ecosystem. Every injector has to
register on the platform, stay alive, and catch the injects it must execute as they
land on its RabbitMQ queue. This SDK does that work.

It stands on [`xtm-oaev-sdk`](https://github.com/OpenAEV-Platform/client-python/tree/main/libs/xtm-oaev-sdk)
(configuration, contracts, signatures, heartbeat, errors) and never depends on
`pyoaev`. The OpenAEV API client gets **injected** (`xtm_oaev_sdk.BaseClient`);
`pyoaev.OpenAEV` is one implementation of it, nothing more.

```
xtm-oaev-sdk  ←  injectors-sdk  ←  your injector
                                   (+ pyoaev for the API client)
```

## What's inside

| Public API | Role | Former `pyoaev` path |
|---|---|---|
| `OpenAEVInjectorHelper` | registers the injector, starts its heartbeat, listens on its queue | `pyoaev.helpers` |
| `OpenAEVConfigHelper` | forgiving configuration access (defaults, required keys, `config.yml`) | `pyoaev.helpers` |
| `ListenQueue` | RabbitMQ consumer thread that hands inject messages to a callback | `pyoaev.helpers` |
| `create_mq_ssl_context` | SSL context for the queue connection, built from the `mq` configuration | `pyoaev.helpers` |

## Quickstart

```python
from pyoaev import OpenAEV
from xtm_oaev_sdk import Configuration
from injectors_sdk import OpenAEVConfigHelper, OpenAEVInjectorHelper

config = OpenAEVConfigHelper.from_configuration_object(Configuration(config_hints={...}))
api = OpenAEV(
    url=config.get_conf("openaev_url"),
    token=config.get_conf("openaev_token"),
    tenant_id=config.get_conf("openaev_tenant_id"),
)
with open("img/icon.png", "rb") as icon:
    helper = OpenAEVInjectorHelper(config, icon, api_client=api)


def process_message(message: dict) -> None:
    ...  # execute the inject, then report its result


helper.listen(message_callback=process_message)
```

## Architecture

Same layering as `xtm-oaev-sdk`:

```
public/helpers.py   adapters: what users import; delegate to _core through the seam ports
seam/helpers/       contracts: Protocol ports, including the queue listener state (closed, versioned)
_core/helpers/      implementations of the seam ports
```

The seam imports nothing from `_core` or `public`. The core never touches `public`.
And `public` never hands a core object to users. `ListenQueue` keeps its public
attributes (connection, channel, thread…), while the RabbitMQ loop itself runs in
the core, wired through the `QueueListenerProtocol` state contract. The full
rationale lives in `xtm-oaev-sdk`'s `docs/seam_strategy.md`.

## Migrating from pyoaev

The former `pyoaev.helpers` names still work, and each one fires a
`DeprecationWarning`. During the deprecation window `pyoaev` depends on this SDK and
serves the very same objects (`pyoaev.helpers.OpenAEVInjectorHelper` still builds
the `OpenAEV` client on its own). New code should depend on `injectors-sdk` and
import from `injectors_sdk`.

## Development

```bash
pip install -e ../../../client-python/libs/xtm-oaev-sdk -e .
python -m pytest test
```

Runtime dependencies: `xtm-oaev-sdk`, pika.
