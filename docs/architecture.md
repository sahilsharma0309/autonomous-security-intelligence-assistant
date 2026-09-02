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
│   ├── osint/                          Module 2 — OSINT & Entity Graph
│   │   ├── engine.py                   [built]   placeholder, to be rebuilt as tools
│   │   ├── collectors/                 [planned] dns, whois, tls, subdomains,
│   │   │                                         username, email, phone, breach
│   │   ├── graph/                      [planned] entity/edge schema, NetworkX +
│   │   │                                         Neo4j backends, export
│   │   └── tools.py                    [planned] @tool wrappers over collectors
│   │
│   ├── iot_recon/                      Module 3 — IoT & Asset Discovery
│   │   ├── scanner.py                  [built]   placeholder
│   │   ├── shodan_client.py            [planned] Shodan/IoT search integration
│   │   ├── port_scan.py                [planned] async TCP connect scanning
│   │   ├── banner.py                   [planned] service/banner fingerprinting
│   │   └── tools.py                    [planned]
│   │
│   ├── threat_scanner/                 Module 4 — Threat Intel & URL Scanner
│   │   ├── scanner.py                  [built]   placeholder
│   │   ├── url_analysis.py             [planned] redirect chains, reputation
│   │   ├── tls_inspect.py              [planned] certificate/chain verification
│   │   ├── sandbox.py                  [planned] headless-browser detonation
│   │   ├── feeds/                      [planned] VirusTotal, URLScan, NVD clients
│   │   └── tools.py                    [planned]
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
│   │   └── test_orchestrator.py        [built]   legacy pipeline
│   └── integration/
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
