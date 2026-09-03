# Autonomous Security & Intelligence Assistant

An asynchronous agent platform for **authorized** security assessments: OSINT
collection into a link graph, IoT asset discovery, URL threat analysis behind a
container sandbox, VPN lifecycle management, and a private web operations
console over all of it.

```
ruff · ruff format · mypy --strict · pytest (3.11 / 3.12 / 3.13)   — all green
~32,300 lines · 1,072 tests
```

---

## The idea

Security capabilities are **tools registered with a dispatcher**, not features
wired into an engine. A capability declares what it is — its risk level, what
it produces and consumes, its rate limit and timeout — and the engine does the
rest: planning, concurrency, authorization, retries, audit.

That bet is what let Modules 2–6 add twenty capabilities and a web console
**without a single change to the core**.

```
                        ┌──────────────────────────────┐
                        │   CLI  ·  Web Dashboard      │
                        └──────────────┬───────────────┘
                                       │
                        ┌──────────────▼───────────────┐
                        │      Agent Orchestrator      │   Module 1
                        │  plan → authorize → dispatch │
                        │  ┌────────────────────────┐  │
                        │  │  AuthorizationScope    │  │ ← every call
                        │  │  default deny          │  │   passes here
                        │  │  denies beat allows    │  │
                        │  │  risk cap per engagement│ │
                        │  └────────────────────────┘  │
                        └──┬────────┬────────┬─────────┘
                           │        │        │
              ┌────────────▼──┐ ┌───▼─────┐ ┌▼──────────────┐
              │  OSINT   (2)  │ │ IoT (3) │ │  Threat  (4)  │
              │ dns whois tls │ │ shodan  │ │ vt urlscan    │
              │ social        │ │ scan    │ │ sandbox       │
              └────────┬──────┘ └───┬─────┘ └──────┬────────┘
                       │            │              │
                       └────────────▼──────────────┘
                            ┌───────────────┐
                            │ Entity Graph  │  one graph, ten node types
                            │ NetworkX/Neo4j│  findings converge here
                            └───────────────┘

              ┌───────────────────────────────────────────┐
              │ Network & Daemon (5)                      │
              │ VPN lifecycle · kill-switch · leak checks │
              │ health · worker supervision · heartbeat   │
              └───────────────────────────────────────────┘
```

### Why findings converge

Every module writes into the same graph, and they meet at shared nodes without
any cross-module wiring:

```
url:https://paypa1.com/login ──SERVED_BY──▶ domain:paypa1.com
        └──REDIRECTS_TO──▶ url:https://collector.example/harvest
                                  └──SERVED_BY──▶ domain:collector.example
                                                         │ RESOLVES_TO
                                                         ▼
   iot_device:192.0.2.10 ──RUNS_ON──▶ ip_address:192.0.2.10
        └──EXPOSES_SERVICE──▶ network_service:192.0.2.10:554/rtsp
```

"Whose exposed camera is this, and is it on the infrastructure that phishing
URL redirects to?" is a `graph.shortest_path()` call.

---

## Safety model

This is dual-use tooling. Four properties are structural, not advisory.

**Default deny.** An empty scope authorizes nothing. Forgetting `--scope` is a
refusal, not an unbounded scan. Denies always beat allows.

**Risk is capped per engagement.**

| Level | Meaning | Examples |
|---|---|---|
| `PASSIVE` | Never contacts the target | WHOIS, VirusTotal, Shodan |
| `ACTIVE` | Contacts it non-intrusively | DNS, TLS, port scan, sandbox load |
| `INTRUSIVE` | May change state or trip alerting | control-port probes |

A passive-only engagement *cannot* run an active scan, enforced in the
dispatcher above every tool — a tool author cannot forget to check.

**Nothing touches your system by default.** Module 5's default command runner
records intent and executes nothing. `--execute` is required, and combining it
with a non-loopback dashboard bind is refused outright.

**Honest negatives.** A check that could not run reports `UNKNOWN`, never `OK`.
A leak report with unperformed checks says *inconclusive*, never *protected*.
An unreadable health metric is `None`, never `0`.

---

## Quickstart

### 1. Install

```bash
git clone https://github.com/sahilsharma0309/autonomous-security-intelligence-assistant
cd autonomous-security-intelligence-assistant

make setup                 # venv + runtime + dev dependencies
source .venv/bin/activate

make setup-all             # optional: every feature extra (dnspython, shodan, …)
```

The core engine and the full test suite need **no** optional package: all
network I/O is injected, so `make check` passes on a bare interpreter.

### 2. Configure

```bash
cp .env.example .env
```

At minimum set your engagement scope — everything is denied without it:

```bash
ENGAGEMENT_ALLOW=example.com,*.example.com,192.0.2.0/24
ENGAGEMENT_MAX_RISK=active
ENGAGEMENT_AUTHORIZATION_REF=SOW-2026-114
```

### 3. Create the sandbox network (before any URL detonation)

```bash
make sandbox-network       # docker network create sandbox-egress
```

Restrict that network so it reaches the public internet and has **no route to
this host or to internal ranges** — that boundary is what actually contains a
hostile page. Without a container runtime the sandbox **fails closed**; pass
`--allow-static-fallback` to accept script-free HTTP inspection instead.

### 4. Run

```bash
# OSINT collection → entity graph
security-assistant recon osint example.com

# Asset discovery within an authorized engagement
security-assistant recon iot 'product:"IP Camera"' --target 192.0.2.10

# URL threat assessment
security-assistant scan url https://suspicious.example/login

# VPN (dry run unless --execute)
security-assistant vpn status
security-assistant vpn connect --execute

# What sudo grants that needs — review before installing
security-assistant privileges --interface wg0 > /tmp/sa.sudoers
visudo -c -f /tmp/sa.sudoers

# Background daemon
security-assistant run-daemon
```

Add `--json` to any command for machine-readable output.

### 5. Launch the dashboard

```bash
export DASHBOARD_SECRET_KEY=$(make -s secret)

security-assistant dashboard \
  --host 127.0.0.1 --port 8443 \
  --scope example.com \
  --open-browser
```

Open <http://127.0.0.1:8443/> and authenticate with that key.

| Panel | What it does |
|---|---|
| **Graph** | Force-directed entity graph, click-to-inspect, JSON/Cypher export |
| **Assets** | IoT grid — services, banners, vendor; filter by port or service |
| **Threat** | URL detonation with a risk gauge, findings, redirect chain, sandbox capture |
| **Network** | Tunnel state, kill-switch, leak badge, live health telemetry |
| **Console** | Dispatch agent runs, streaming log over WebSocket |

**The dashboard is a remote-control surface.** It refuses to start without
`DASHBOARD_SECRET_KEY` (min 32 chars), binds to loopback by default, and
**refuses a non-loopback bind combined with `--execute`**. To reach it from
another machine, tunnel rather than expose:

```bash
ssh -L 8443:127.0.0.1:8443 user@host
```

It vendors nothing from a CDN, so its Content-Security-Policy forbids every
external origin and it works on an isolated network.

---

## Development

```bash
make check          # lint + format-check + typecheck + test, in CI's order
make test           # pytest
make lint           # ruff check
make format         # apply ruff format
make typecheck      # mypy --strict
```

A clean `make check` is what CI runs, so it means a green PR.

```
src/security_assistant/
├── core/        Module 1 — orchestrator, dispatch, authorization, planner, memory
├── osint/       Module 2 — collectors, entity graph, correlation
├── iot/         Module 3 — Shodan, scanning, fingerprints, stream discovery
├── threat/      Module 4 — VirusTotal, URLScan, sandbox, analyzer, SSRF guard
├── network/     Module 5 — VPN, kill-switch, leaks, privileges
├── daemon/      Module 5 — health, worker supervision, heartbeat
├── web/         Module 6 — FastAPI dashboard, auth, telemetry
└── cli.py       Unified Typer + Rich CLI
```

---

## Operational notes

Read these before running against anything real.

- **`VPN_ADMIN_CIDRS` on a remote host.** The kill-switch lockout guard always
  preserves loopback, established connections and the VPN endpoint, but it
  cannot know the range you SSH from. Set it, or you can lock yourself out
  permanently. Engaging the switch also arms a dead-man's-switch rollback:
  unconfirmed rules revert automatically.
- **The VPN and firewall code has never been run against live infrastructure
  in this repository.** Every system call is behind an injected runner in
  tests. The parsers are tested against realistic fixtures, but first contact
  with a real `wg` will find things. Stage it on a machine you can physically
  reach.
- **`osint.social` ships with no platforms configured.** Username enumeration
  is the part of OSINT most easily turned against an individual, so the
  operator registers targets explicitly and it is scope-gated on the
  engagement domain.
- **`threat.urlscan_submit` is ACTIVE**, because urlscan.io fetching the target
  on your behalf still puts a visit in the target's logs. Submissions default
  to `unlisted` so a lookup does not publish what you are investigating.

---

## Licence & intended use

For authorized security assessment only: systems you own, or have written
permission to test. The authorization scope, risk levels and audit trail exist
to make that boundary explicit and enforceable — they are not a substitute for
having permission.
