# System Architecture

The Autonomous Security & Intelligence Assistant is an asynchronous, tool-using
agent for **authorized** security assessments. A central engine plans and
executes work; the security capabilities themselves are plug-in *tools* that the
engine dispatches under a uniform safety policy.

## Design principles

1. **The core is dependency-free.** `security_assistant.core` imports nothing
   outside the standard library, so the engine builds, imports and tests in any
   environment. Every third-party package belongs to a feature module and is an
   optional extra.
2. **Authorization is structural, not advisory.** Scope enforcement lives in the
   dispatcher, above every tool. A tool author cannot forget to check scope,
   because tools never get to decide. Default-deny; denies beat allows; risk is
   capped per engagement.
3. **Failures are values, not exceptions.** Dispatch returns a `ToolResult` with
   a status. One failing collector never aborts a whole assessment unless the
   operator asks for that.
4. **Everything is auditable.** Each invocation records its target, the scope
   rule that authorized it, timing, attempts and outcome.

## Component map

```
                       ┌──────────────────────────┐
                       │    AgentOrchestrator     │  process lifecycle,
                       │  queue · workers · svcs  │  signals, back-pressure
                       └────────────┬─────────────┘
                                    │ jobs
                       ┌────────────▼─────────────┐
                       │          Agent           │  recall → plan → execute
                       │   reason-act run loop    │  → refine → remember
                       └──┬──────────┬─────────┬──┘
                          │          │         │
              ┌───────────▼──┐  ┌────▼─────┐ ┌─▼──────────────┐
              │ TaskPlanner  │  │ Long-term│ │ ToolDispatcher │
              │  (DAG build) │  │  Memory  │ │ ── SAFETY GATE │
              └──────────────┘  └──────────┘ └───┬────────────┘
                                                 │ resolve · validate
                                                 │ authorize · rate-limit
                                                 │ timeout · retry · audit
                                   ┌─────────────▼─────────────┐
                                   │       ToolRegistry        │
                                   └─────────────┬─────────────┘
                                                 │
        ┌───────────────┬────────────────┬───────┴────────┬──────────────────┐
        │               │                │                │                  │
  ┌─────▼─────┐  ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐   ┌───────▼──────┐
  │  OSINT &  │  │   IoT &     │  │  Threat &   │  │  Network &  │   │   Analysis   │
  │  Entity   │  │   Asset     │  │  URL Deep   │  │  VPN Daemon │   │  Correlation │
  │  Graph    │  │  Discovery  │  │  Scanner    │  │             │   │              │
  └───────────┘  └─────────────┘  └─────────────┘  └─────────────┘   └──────────────┘
     Module 2       Module 3          Module 4         Module 5         Module 6

                 ┌──────────────────────────────────────────┐
                 │           AuthorizationScope             │
                 │  consulted by the dispatcher on every    │
                 │  scope-gated invocation. Default deny.   │
                 └──────────────────────────────────────────┘
```

## Directory tree

Entries marked `[built]` exist today; the rest are the planned layout for the
remaining modules.

```
autonomous-security-intelligence-assistant/
├── src/security_assistant/
│   ├── __init__.py                     [built]
│   ├── __main__.py                     [built]  CLI entry point
│   │
│   ├── core/                           [built]  Module 1 — the agent engine
│   │   ├── __init__.py                          public API surface
│   │   ├── types.py                             enums, ToolContext/Invocation/Result
│   │   ├── exceptions.py                        exception hierarchy
│   │   ├── authorization.py                     engagement scope + safety gate
│   │   ├── tool.py                              ToolSpec, @tool, BaseTool, validation
│   │   ├── registry.py                          capability index & introspection
│   │   ├── dispatcher.py                        dispatch engine (safety/reliability)
│   │   ├── memory.py                            vector-backed long-term memory
│   │   ├── planner.py                           Plan/PlanStep DAG + strategies
│   │   ├── agent.py                             reason-act run loop
│   │   └── orchestrator.py                      event loop, queue, workers, services
│   │
│   ├── config/                         [planned] settings models, YAML+env loading
│   │   ├── settings.py
│   │   └── loader.py
│   │
│   ├── osint/                          [built]  Module 2 — OSINT & Entity Graph
│   │   ├── __init__.py                          public API surface
│   │   ├── models.py                            Entity/Relationship + canonicalization
│   │   ├── graph.py                             EntityGraph + NetworkX/Neo4j/JSON export
│   │   ├── correlator.py                        entity resolution + link inference
│   │   ├── collectors/
│   │   │   ├── base.py                          injectable provider plumbing
│   │   │   ├── dns_collector.py                 A/AAAA/MX/NS/TXT/CNAME
│   │   │   ├── whois_collector.py               registration metadata
│   │   │   ├── tls_collector.py                 certificate chain + SANs
│   │   │   └── social_collector.py              username footprinting hooks
│   │   └── engine.py                   [legacy]  superseded by the collectors
│   │
│   ├── iot/                            [built]  Module 3 — IoT & Asset Recon
│   │   ├── __init__.py                          public API surface
│   │   ├── models.py                            devices/services + graph projection
│   │   ├── fingerprints.py                      port/banner -> device classification
│   │   ├── shodan_client.py                     async index client, rate-limited
│   │   ├── stream_discovery.py                  connect scan, banners, exposure
│   │   └── tools.py                             @tool registrations
│   ├── iot_recon/                      Module 3 — superseded
│   │   ├── scanner.py                  [legacy]  placeholder
│   │   ├── shodan_client.py            [planned] Shodan/IoT search integration
│   │   ├── port_scan.py                [planned] async TCP connect scanning
│   │   ├── banner.py                   [planned] service/banner fingerprinting
│   │   └── tools.py                    [planned]
│   │
│   ├── threat/                         [built]  Module 4 — Threat Intel & URL Scanner
│   │   ├── __init__.py                          public API surface
│   │   ├── models.py                            findings, verdicts, scoring, projection
│   │   ├── safety.py                            SSRF guard for fetched URLs
│   │   ├── virustotal.py                        VT client, token bucket, parsing
│   │   ├── urlscan.py                           URLScan search/submit + parsing
│   │   ├── sandbox.py                           container browser + static fallback
│   │   ├── analyzer.py                          phishing/typosquat/homoglyph rules
│   │   └── tools.py                             six @tool registrations
│   ├── threat_scanner/                 [legacy]  superseded by threat/
│   │   └── scanner.py                  [built]   placeholder
│   │
│   ├── network/                        Module 5 — Network & VPN
│   │   ├── vpn_daemon.py               [built]   placeholder
│   │   ├── providers/                  [planned] wireguard, openvpn, networkmanager
│   │   ├── health.py                   [planned] tunnel health, kill-switch
│   │   └── service.py                  [planned] BackgroundService implementation
│   │
│   ├── analysis/                       [planned] Module 6 — correlation, scoring
│   │   ├── correlate.py
│   │   └── severity.py
│   │
│   ├── reporting/                      [planned] Module 7 — report rendering
│   │   ├── models.py
│   │   └── renderers/                            json, markdown, html
│   │
│   └── orchestrator.py                 [built]   legacy sync pipeline (superseded
│                                                 by core/orchestrator.py)
│
├── tests/
│   ├── unit/
│   │   ├── conftest.py                 [built]   shared tool/scope fixtures
│   │   ├── test_core_authorization.py  [built]
│   │   ├── test_core_registry.py       [built]
│   │   ├── test_core_dispatcher.py     [built]
│   │   ├── test_core_memory.py         [built]
│   │   ├── test_core_planner.py        [built]
│   │   ├── test_core_agent.py          [built]
│   │   ├── test_core_orchestrator.py   [built]
│   │   ├── test_osint_models.py        [built]
│   │   ├── test_osint_graph.py         [built]
│   │   ├── test_osint_collectors.py    [built]
│   │   ├── test_osint_correlator.py    [built]
│   │   └── test_orchestrator.py        [built]   legacy pipeline
│   └── integration/
│       ├── test_osint_pipeline.py      [built]   core + OSINT end to end
│       └── test_pipeline.py            [built]
│
├── config/
│   ├── config.yaml                     [built]   runtime config + engagement scope
│   └── logging.yaml                    [built]
├── docs/
│   └── architecture.md                 [built]   this file
├── .env.example                        [built]
├── pyproject.toml                      [built]
├── requirements.txt                    [built]   application scaffolding
├── requirements-modules.txt            [built]   optional per-module extras
├── requirements-dev.txt                [built]
├── Dockerfile                          [built]
└── docker-compose.yml                  [built]
```

## Module 1 — the agent core

### Execution flow

An `Agent.run(goal, target=...)` proceeds:

```
recall ──► plan ──► ┌─ wave: ready steps dispatched concurrently ─┐ ──► remember
                    │        ▲                                    │
                    │        └──── refine (bounded rounds) ◄──────┘
                    └─ repeat until nothing is runnable ──────────┘
```

A plan is a DAG, so independent collectors run in parallel while analysis waits
for the data it reads. A step whose dependency failed is marked `SKIPPED` rather
than run against missing input.

### The dispatch pipeline

Every tool call passes through the same seven stages:

| # | Stage | Failure status |
|---|-------|----------------|
| 1 | Resolve the tool by name | `NOT_FOUND` |
| 2 | Validate arguments against the spec | `INVALID` |
| 3 | **Authorize the target against the scope** | `DENIED` |
| 4 | Acquire a per-tool rate-limit token | `RATE_LIMITED` |
| 5 | Acquire the process-wide concurrency slot | — |
| 6 | Execute under a timeout, retry transient failures | `TIMEOUT` / `ERROR` |
| 7 | Record the outcome in the audit trail | — |

Stage 3 is the one that matters most. It is unconditional for any tool declaring
`requires_scope=True` (the default — a tool must opt *out* explicitly, so
forgetting to think about it fails closed), and it fails closed when no scope is
configured at all.

### Risk levels

A scope caps how intrusively the agent may act, independently of which hosts are
in scope:

| Level | Meaning | Example |
|-------|---------|---------|
| `PASSIVE` | Never contacts the target | Threat-intel lookup, cached WHOIS |
| `ACTIVE` | Contacts the target non-intrusively | DNS resolution, TCP connect, HTTP GET |
| `INTRUSIVE` | May change state or trip alerting | Authenticated scanning, enumeration |

An engagement limited to `PASSIVE` cannot execute an active scan even against an
in-scope host — the tool is simply never selected by the planner and would be
denied by the dispatcher if invoked directly.

### Extension points

Each is a `Protocol`; implementing one requires no changes to the engine.

| Protocol | Default | Swap in |
|----------|---------|---------|
| `Tool` | `@tool` / `BaseTool` | any capability |
| `PlannerStrategy` | `RuleBasedPlanner` | LLM-backed planner |
| `RefinementStrategy` | none | adaptive re-planning |
| `EmbeddingProvider` | `HashingEmbeddingProvider` | hosted embedding model |
| `VectorStore` | `InMemoryVectorStore` | Chroma, Qdrant, pgvector |
| `BackgroundService` | none | VPN supervisor, health monitor |
| `EventSink` | none | metrics, tracing, SIEM forwarding |

## Data flow

1. The operator defines an `AuthorizationScope` from the written authorization
   and supplies a goal plus a target.
2. `AgentOrchestrator` brings up background services — critically the VPN
   supervisor — *before* accepting work, so all egress uses the authorized path.
3. A worker's `Agent` recalls prior knowledge, plans a DAG, and executes it.
4. Each invocation is authorized, rate-limited, executed and audited.
5. OSINT results populate the entity graph; recon results feed the scanners;
   analysis correlates across both.
6. Salient findings are written to long-term memory, namespaced per engagement.
7. Results are aggregated into a report.

## Configuration

Runtime configuration lives in `config/config.yaml`; secrets come from
environment variables (see `.env.example`) and are never committed. The
`engagement:` block defines the authorization scope and is the single most
important setting in the file — an empty `allow` list authorizes nothing, which
is the intended default.

## Usage scope

This project is for authorized security assessment and defensive research only,
against assets the operator owns or has explicit written permission to test. The
`AuthorizationScope` gate exists to make that boundary enforceable in code rather
than a line in a README, but it is a safeguard, not a substitute for having
permission in the first place.

## Module 2 — OSINT & Entity Graph

### Entity model

Six node types (`EntityType`): `DOMAIN`, `IP_ADDRESS`, `EMAIL`, `PHONE`,
`SOCIAL_HANDLE`, `ORGANIZATION`. Thirteen typed edges (`EdgeType`) connect
them, from `RESOLVES_TO` and `MAIL_HANDLED_BY` through `REGISTERED_BY`,
`SECURES` and `SAME_AS`.

Every entity and relationship carries **provenance** (which tool observed it,
when, with what detail) and a **confidence score**. Corroborating observations
are combined with a noisy-OR: two independent sources at 0.6 give 0.84 — more
than either alone, never reaching certainty.

**Canonicalization does the easy half of deduplication.** Each type defines one
canonical form, and the entity key is `type:canonical`. `Example.COM.` and
`example.com` therefore produce the same node by construction, so merging
duplicate observations is a dictionary lookup rather than a similarity search.
Organization names additionally strip legal suffixes (`Acme, Inc.` → `acme`)
and accents, so only genuinely ambiguous cases reach the correlator.

### Collectors

| Tool | Risk | Produces | Contacts the target? |
|---|---|---|---|
| `osint.whois` | PASSIVE | `registration`, `contacts` | No — registry only |
| `osint.dns` | ACTIVE | `hosts`, `dns_records` | Possibly — may reach its NS |
| `osint.tls` | ACTIVE | `certificates`, `sans` | Yes — TLS handshake |
| `osint.social` | ACTIVE | `handles` | Yes — profile URLs |

A passive-only engagement therefore plans WHOIS alone; the other three are
never selected and would be denied by the dispatcher if invoked directly.

All I/O goes through injectable providers looked up in `ToolContext.config`
(`dns_resolver`, `whois_client`, `tls_fetcher`, `profile_probe`), which is what
lets the entire module be tested with no network access and no optional
dependencies installed.

`osint.social` ships with **no platforms configured**. Username enumeration is
the part of OSINT most easily turned against an individual, so the operator
must register platform hooks explicitly; with none registered the tool returns
an empty result and says so. It is scope-gated on the engagement domain rather
than the handle, which ties any footprinting to a declared authorization.

### Correlation

Two distinct jobs, deliberately not conflated:

- **Entity resolution** decides when two *nodes* are the same thing —
  organizations differing beyond normalization, `www.` aliases, handles
  restating an email. Each candidate carries scored evidence and a rationale.
- **Link inference** decides when two nodes are *related* — subdomain
  containment, shared hosting, an email matching a known domain.

Both are biased toward missing a match over inventing one, because a false
merge silently fuses two organizations' infrastructure and corrupts every later
conclusion. Concretely: candidates scoring ≥ 0.85 merge, ≥ 0.6 are surfaced for
review rather than applied, certificate issuers and registrars are never merged
(they appear across unrelated targets), public email providers are not treated
as ownership evidence, high fan-out IPs are treated as shared hosting, and a
`www.` alias resolving to a *different* address than its apex is flagged for
review instead of merged.

### Exports

- `to_networkx()` — a real `nx.MultiDiGraph` for algorithms and visualization.
- `to_cypher()` — parameterized, idempotent Neo4j `MERGE` statements. Entity
  values are always parameters, never interpolated into query text.
- `to_json()` / `from_json()` — lossless round-trip including provenance.

The graph keeps its own adjacency index rather than holding a NetworkX object
as the source of truth, so it works without the optional extra and so
merge-on-insert semantics stay explicit.

## Module 3 — IoT & Asset Reconnaissance

### First-class asset nodes

`EntityType` gains `IOT_DEVICE` and `NETWORK_SERVICE`, with four new edges:
`EXPOSES_SERVICE`, `RUNS_ON`, `SERVICE_ON`, `MANUFACTURED_BY`.

Making assets graph nodes rather than a separate inventory is what lets IoT and
OSINT findings meet. Both attach to the shared `ip_address` node, so a camera
discovered at `192.0.2.10` and a domain whose A record points there are
connected with no cross-module wiring:

```
iot_device:192.0.2.10 ──RUNS_ON──> ip_address:192.0.2.10 <──RESOLVES_TO── domain:example.com
        │
        └──EXPOSES_SERVICE──> network_service:192.0.2.10:554/rtsp
```

"Whose exposed camera is this?" becomes a graph traversal.

Service identity is `host:port/protocol`. IPv6 hosts stay bracketed
(`[2001:db8::1]:554/rtsp`) so the canonical form re-parses to itself.

### Risk classification

| Tool | Risk | Why |
|---|---|---|
| `iot.shodan_host` | PASSIVE | Queries the index; never the target |
| `iot.shodan_search` | PASSIVE | Same, for a query |
| `iot.scan` | ACTIVE | TCP connect + banner grab |
| `iot.stream_probe` | ACTIVE | HEAD/OPTIONS against HTTP/RTSP |
| `iot.control_port_probe` | INTRUSIVE | Touches PLC/BAS control ports at all |

The last is why `INTRUSIVE` exists. A default `ACTIVE` engagement will not run
it — enforced by the dispatcher, with tests proving the gate holds.

### What the scanner puts on the wire

Three deliberate restraints, each pinned by tests:

- **HTTP gets `HEAD`, never `GET`.** Status and headers are enough to tell
  whether authentication is enforced; no page body is retrieved.
- **RTSP gets `OPTIONS`, never `DESCRIBE` or `PLAY`.** The capability
  handshake establishes that an endpoint exists and whether it challenges for
  credentials. No media session is ever opened. "This camera is reachable with
  no credentials" is the entire finding; watching the feed adds nothing to the
  assessment and is the part that harms the people in front of the lens.
- **Control ports receive zero bytes.** Modbus/S7/DNP3/BACnet get a TCP
  connect and an immediate close. Malformed input to a PLC has physical
  consequences, so the module never speaks those protocols.

### Confidence reflects provenance

A completed TCP connect is `OBSERVED`. A vendor or model read out of a banner
is at most `STRONG` — banners are self-reported and trivially spoofed. Anything
from the Shodan index is `MODERATE` and carries the index timestamp, because it
reports what Shodan last saw, not what is true now.

### Credentials

`SHODAN_API_KEY` is read from the environment at call time, never passed as a
tool argument — an argument would land in plan structures, audit records and
logs. The key is redacted from every error message and `repr`.

## Module 4 — Threat Intelligence & URL Deep Scanner

### Three independent directions

A URL is assessed from evidence that fails independently, so no single source
can dominate the verdict:

| Direction | Module | Contacts the target? |
|---|---|---|
| Heuristics — typosquat, homoglyph, structure, hosting, TLS | `analyzer.py` | No |
| Reputation — what third parties already know | `virustotal.py`, `urlscan.py` | No |
| Observation — what the page does when loaded | `sandbox.py` | Yes |

### Tools and risk

| Tool | Risk | Notes |
|---|---|---|
| `threat.url_analyze` | PASSIVE | String heuristics; contacts nothing |
| `threat.virustotal` | PASSIVE | Queries VT's index |
| `threat.urlscan` | PASSIVE | Searches existing scans |
| `threat.urlscan_submit` | ACTIVE | urlscan.io fetches the target on our behalf |
| `threat.url_inspect` | ACTIVE | Loads the page in the sandbox |
| `threat.url_score` | PASSIVE | Pure aggregation of prior evidence |

`urlscan_submit` is ACTIVE deliberately. The request reaches the target from
urlscan.io rather than from us, which changes whose address appears in the
target's logs but not whether the target was contacted. Classifying it passive
would let a passive-only engagement cause a visit — precisely what the risk
levels exist to prevent.

### Scoring

Findings are grouped by category, the strongest signal in each category is
taken, and categories are combined with a noisy-OR. This is not a sum, for two
reasons: a sum lets a handful of cosmetic observations out-vote one decisive
finding, and it makes the maximum an artifact of how many heuristics exist.
Correlated indicators therefore cannot stack — "long URL" and "deep subdomains"
are both structural, so together they count once plus a small corroboration
increment.

Severity weights: `low` 0.08, `medium` 0.30, `high` 0.65, `critical` 0.92.
`info` carries zero weight, so a note like "inspected without a browser"
records reduced coverage without inflating the score.

### The sandbox boundary

This is the only component that deliberately executes attacker-controlled
content, so the isolation is the design:

* One throwaway container per URL: `--rm`, non-root `--user`, `--cap-drop=ALL`,
  `--security-opt no-new-privileges`, `--read-only` with a `noexec,nosuid`
  tmpfs, `--memory` and `--pids-limit` caps, and **no bind mounts** — results
  return over stdout.
* An operator-defined `--network` with restricted egress. This is what actually
  contains SSRF; the checks in `safety.py` are the second layer.
* Killed on timeout and again in a `finally`, then awaited, so no container or
  zombie process outlives the call.

Where Docker is unavailable it degrades to HTTP-only inspection that executes
nothing, marking the report `engine="static"` and emitting an INFO finding.
That distinction matters when reading a result: an absent behavioural finding
then means "not looked for", not "not present".

### SSRF guard (`safety.py`)

Every other module points outward at an operator-named target. This one takes
a URL chosen by whoever is being investigated, so it is itself an attack
surface — `http://169.254.169.254/latest/meta-data/` attacks the scanner, not
the target. Scheme allowlist (http/https only), address denylist (loopback,
private, link-local, multicast, reserved, and IPv4-mapped IPv6), and a port
allowlist. Redirects are re-checked at every hop, since a redirect is
attacker-controlled and is the standard way to walk a fetcher inward.

The documented limit: a hostname is only checked when it is an IP literal or
when a resolver is supplied, and DNS rebinding can still change the answer
between check and fetch. The container's network boundary is the durable
mitigation; this is defence in depth.

### Graph integration

`EntityType` gains `URL` and `FILE_HASH`; `EdgeType` gains `REDIRECTS_TO`,
`SERVED_BY`, `CONTACTS` and `REFERENCES_FILE`. A URL's host becomes a domain
or address node, which is the join with everything OSINT and IoT discovered:

```
url:https://paypa1.com/login ──SERVED_BY──> domain:paypa1.com
        │
        └──REDIRECTS_TO──> url:https://collector.example/harvest
                                   └──SERVED_BY──> domain:collector.example
                                                          │
                                        RESOLVES_TO ──────┘
                                              ↓
                                   ip_address:203.0.113.77
```
