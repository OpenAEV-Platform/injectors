# Technical Decision Records

The technical decision records that belong to injectors-sdk alone. The decisions all
three SDKs share live in the [xtm-oaev-sdk TDRs](https://github.com/OpenAEV-Platform/client-python/blob/main/libs/xtm-oaev-sdk/docs/tdr/TDR_ToC.md).

| TDR | Status | Rule |
|---|---|---|
| [injectors-sdk builds on the xtm-oaev-sdk public API only](injectors-sdk-builds-on-xtm-oaev-sdk-public-api-only.tdr.md) | draft | injectors-sdk must import xtm-oaev-sdk only through its package root and never import pyoaev, collectors-sdk, thefuzz or requests; the API client is injected. |
| [A stateful loop run by the core works against a seam state protocol](core-driven-loops-run-against-a-state-protocol.tdr.md) | draft | When the core drives a stateful loop of a public adapter, the seam must declare that state as a Protocol, the core must run the loop against it, and the adapter keeps the state and delegates in one-line methods. |

## Adding a TDR

Create `<slug>.tdr.md`, the slug naming the rule. Same header as the other records,
`status: draft`, then a row in this table. A TDR moves to `accepted` once validated. The
day it stops governing, it goes `superseded` (with `superseded_by` / `supersedes` set on
both records) or `revoked`.
