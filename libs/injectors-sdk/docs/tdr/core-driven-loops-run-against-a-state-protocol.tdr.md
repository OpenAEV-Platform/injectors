# A stateful loop run by the core works against a seam state protocol
---
scope: [injectors-sdk, helpers, architecture]
status: draft
superseded_by:
supersedes:
Aliases:
Creation Date: 2026/10/14 16:25:31
Modification Date: 2026/10/14 16:25:31
---

## ELI5

`ListenQueue` reads messages from RabbitMQ in a loop and keeps its connection details in
attributes anyone can see. The loop moved to the core. So the seam spells out exactly
which state the loop reads and changes, and the core works on the `ListenQueue` object
through that description. Users still see the same attributes as before.

---

## **Why This Exists**
| *The forcing reality that demanded this TDR.*

> `ListenQueue` is a public `threading.Thread` whose RabbitMQ loop reads and rewrites its
> own attributes (`pika_connection`, `channel`, `thread`…), in plain sight of users and
> tests. Moving the loop into the core must not hide that state, and the core may not
> import the public class.

---

## **The TDR**
| **When the core drives a stateful loop of a public adapter, the seam must declare that state as a Protocol, the core must run the loop against it, and the adapter keeps the state and delegates in one-line methods.**

> A specific case of xtm-oaev-sdk TDR [adapters-keep-the-user-facing-shape](https://github.com/OpenAEV-Platform/client-python/blob/main/libs/xtm-oaev-sdk/docs/tdr/adapters-keep-the-user-facing-shape.tdr.md) (adapters keep their attributes and hooks).

---

## **In Practice**
| *How this TDR manifests in the real world.*

- `seam/helpers/ports.py`: `QueueListenerProtocol` (callback, connection settings, `exit_event`, `thread`, pika objects, `_process_message`, `_data_handler`) and `QueueConsumerPort`.
- `public/helpers.py`:

```python
def run(self) -> None:
    _consumer.run(self)
```

The core runs the whole cycle against the protocol: connect, consume, recover, process, stop.

---

## **Alternatives Explored**
| *The paths we tried and why they failed.*

No alternative was explored for this decision.

---

## **Mutation Trigger**
| *When this TDR should be reconsidered.*

This TDR becomes questionable if:
- `ListenQueue`'s attributes are no longer part of the public API;
- the consumer becomes stateless or async.

## **Hansei**
| *Scars, surprises, and extracted wisdom.*

What we learned while forging this TDR:
- No material lesson beyond the TDR itself.

---

## **Resources**
- [Helpers seam ports](../../injectors_sdk/seam/helpers/ports.py)
- [Listen queue tests](../../test/test_listen_queue.py)
- [Seam strategy](https://github.com/OpenAEV-Platform/client-python/blob/main/libs/xtm-oaev-sdk/docs/seam_strategy.md)
