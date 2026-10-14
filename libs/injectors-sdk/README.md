# injectors-sdk

OpenAEV Injectors SDK: the injector runtime (registration, heartbeat and
inject queue listening), built on the shared
[`xtm-oaev-sdk`](https://github.com/OpenAEV-Platform/client-python/tree/main/libs/xtm-oaev-sdk).

It never depends on the `pyoaev` client: the OpenAEV API client is injected.

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
helper.listen(message_callback=process_message)
```

| Symbol | Former `pyoaev` path |
|---|---|
| `OpenAEVInjectorHelper` | `pyoaev.helpers.OpenAEVInjectorHelper` |
| `OpenAEVConfigHelper` | `pyoaev.helpers.OpenAEVConfigHelper` |
| `ListenQueue` | `pyoaev.helpers.ListenQueue` |
| `create_mq_ssl_context` | `pyoaev.helpers.create_mq_ssl_context` |

## Development

```bash
pip install -e ../../../client-python/libs/xtm-oaev-sdk -e .
pytest test
```
