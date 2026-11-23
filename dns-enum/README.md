# OpenAEV DNS Enumeration Injector

The DNS Enumeration injector lets OpenAEV map the external DNS footprint of one or more root domains as part of an
attack scenario. It collects candidate hostnames from passive sources with
[subfinder](https://github.com/projectdiscovery/subfinder) and, optionally, from a wordlist, resolves them actively with
[dnsx](https://github.com/projectdiscovery/dnsx), reports one finding per resolved host, and can import the discovered
hosts as OpenAEV endpoints so that the next injects of the scenario (Nmap, Nuclei, ...) target the real external attack
surface.

## Requirements

- OpenAEV Platform reachable from the injector (along with its RabbitMQ broker)
- For a manual (non-Docker) deployment:
  - Python >= 3.11 and [Poetry](https://python-poetry.org/) >= 2.1
  - The `subfinder` and `dnsx` binaries on the `PATH` (the Docker image bundles pinned versions, tracked by Renovate)
- The token must allow creating tags and endpoints when the endpoint import option is used, and writing the asset
  group when one is given.

## Configuration variables

Copy `.env.sample` (Docker) or `config.yml.sample` (manual) and fill in the values flagged with `ChangeMe`.

| Parameter         | config.yml           | Docker environment variable | Mandatory | Description                                              |
|-------------------|----------------------|-----------------------------|-----------|----------------------------------------------------------|
| OpenAEV URL       | `openaev.url`        | `OPENAEV_URL`               | Yes       | The URL of the OpenAEV platform.                         |
| OpenAEV Token     | `openaev.token`      | `OPENAEV_TOKEN`             | Yes       | The administrator token of the OpenAEV platform.         |
| OpenAEV Tenant ID | `openaev.tenant_id`  | `OPENAEV_TENANT_ID`         | No        | Tenant identifier for multi-tenant deployments.          |
| Injector ID       | `injector.id`        | `INJECTOR_ID`               | Yes       | A unique `UUIDv4` identifier for this injector instance. |
| Injector Name     | `injector.name`      | `INJECTOR_NAME`             | No        | Name of the injector (default `DNS Enumeration`).        |
| Log Level         | `injector.log_level` | `INJECTOR_LOG_LEVEL`        | No        | `debug`, `info`, `warn` or `error`.                      |

## Deployment

```shell
docker compose up -d
```

Manual deployment: `poetry install` then `poetry run python -m dns_enum.openaev_dns_enum`.

## Inject contract: DNS / subdomain enumeration

| Field                                  | Default            | Description                                                                                         |
|----------------------------------------|--------------------|-----------------------------------------------------------------------------------------------------|
| Root domains                           | (mandatory)        | One or more root domains, comma-separated. Validated as DNS names before any command runs.         |
| Passive sources (subfinder)            | on                 | Collect subdomains from subfinder's passive sources.                                                |
| DNS record types (dnsx)                | A, AAAA, CNAME     | Any of A, AAAA, CNAME, MX, NS, TXT.                                                                 |
| Brute force with a wordlist            | off                | Add `word.<root domain>` for every word of the wordlist (one label per line, 10,000 at most).       |
| Rate limit                             | 100                | DNS queries per second (1 to 1,000), applied to subfinder and dnsx.                                 |
| Timeout                                | 600                | Seconds for the whole enumeration (1 to 3,600).                                                     |
| Create endpoints for discovered hosts  | off                | Import every resolved host that has an address as an endpoint (see below).                          |
| Tag set on the created endpoints       | `discovered:dns`   | Tag created if missing and set on every imported endpoint.                                          |
| Asset group ID                         | (empty)            | When set, the imported endpoints are added to this asset group (existing members are kept).        |
| Classify the endpoints                 | on                 | Set the category, subcategory and URL of each imported endpoint and attach a name to the existing asset of its address (see below). |

The root domains themselves are always resolved; hosts outside the requested root domains are dropped.

### Outputs

| Output             | Type            | Finding | Content                                                                                   |
|--------------------|-----------------|---------|-------------------------------------------------------------------------------------------|
| `discovered_hosts` | Text            | Yes     | One finding per resolved host: `host \| A: ip, ip \| CNAME: target ...`.                  |
| `ipv4`             | IPv4            | Yes     | Every resolved IPv4 address.                                                              |
| `hostnames`        | Text            | No      | The resolved hostnames, one value each, for chaining.                                     |
| `manual_targets`   | Text            | No      | The resolved hostnames comma-separated: map it to the "Manual targets" field of a next Nmap or Nuclei inject. |
| `action_output`    | Action output   | No      | The raw dnsx JSON lines.                                                                  |
| `expectation_signatures` | Expectation signature | No | Detection and prevention signatures, like the other network injectors.            |

### Endpoint import

With the option on, each resolved host with at least one address is upserted through the platform's agentless endpoint
upsert (`POST /api/endpoints/agentless/upsert`):

- name and hostname: the host; IPs: its A and AAAA addresses; internet facing; the tag above;
- external reference `dns-enum:<host>`: the platform matches an existing endpoint on it first, so a rerun updates the
  same endpoint and never creates a duplicate;
- a host on the address of an asset another source created (a collector, an agent, a person) is never upserted, with
  or without classification: it is attached to that asset (added to the asset group when one is set) and listed in
  the execution message. That asset's name, category, subcategory and every other field are left unchanged (the
  platform's upsert matches on hostname + IP, so sending the host could rename or reclassify it);
- a host whose addresses cannot be checked against the inventory (`POST /api/assets/search` fails) is not imported
  and is listed in the execution message.

With "Classify the endpoints" on (the default):

- a name that shares an address with another discovered name (virtual hosts behind one ingress or load balancer), or
  whose CNAME points at a CDN (CloudFront, Akamai, Fastly, Cloudflare, Azure Front Door, ...), is a web application:
  category `WEB_APPLICATION`, subcategory `WEBSITE`, URL `https://<name>`;
- a name alone on its addresses is a host: category `HOST`, subcategory `SERVER`;
- the classification is written only on an asset nobody classified yet (new, or `HOST` / `GENERIC_ASSET` with no
  subcategory): a category, subcategory or criticality a person set is never changed, and a rerun changes nothing;
- the execution message counts the hosts classified in this run as web applications and as servers.

When the existing endpoints cannot be read, the hosts are imported without classification and the message says so.
An endpoint created from a name alone has no agent, so its platform stays `Unknown`: that is expected, the category
and subcategory carry the classification.

A host resolving only to a CNAME is reported as a finding but not imported. With the option off, no asset is created
or changed.

## Behavior

1. Candidates: the root domains, then subfinder's results (when on), then the wordlist expansion (when on).
2. dnsx resolves every candidate for the selected record types and prints one JSON line per host.
3. The injector parses those lines into one entry per host (deduplicated, sorted), sends the structured outputs, then
   imports the endpoints when asked, and sends the expectation signatures.

A tool failure or a timeout ends the inject in error with the tool's message; an invalid input (domain, record type,
empty wordlist with brute force on) ends it in error before any command runs.
