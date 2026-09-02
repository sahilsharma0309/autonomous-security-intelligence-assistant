# Autonomous Security & Intelligence Assistant

A modular, autonomous assistant for authorized security assessments —
combining OSINT collection, IoT reconnaissance, threat correlation, and
controlled network egress under a single orchestrator.

> **Scope of use:** This project is intended for authorized security
> testing, defensive research, and CTF/educational use only, against
> assets you own or have explicit written permission to assess. It does
> not ship exploit payloads or automated attack capability.

## System Overview

The assistant runs a pipeline against a single authorized target:

1. **Reconnaissance** — OSINT and IoT recon engines gather information
   about the target in parallel.
2. **Correlation** — the threat scanner matches discovered assets and
   services against vulnerability/threat-intel feeds.
3. **Reporting** — results are aggregated by the orchestrator for review.

All outbound scan traffic is routed through a managed VPN daemon so the
assistant's network posture stays controlled and auditable.

## Core Architecture

| Component | Location | Responsibility |
|---|---|---|
| **Agent core** | `src/security_assistant/core/` | The engine: async orchestrator, tool dispatch, planner, memory, and the authorization gate. |
| **OSINT Engine** | `src/security_assistant/osint/` | Collects open-source intelligence: domains, subdomains, breach exposure, public records. |
| **IoT Recon** | `src/security_assistant/iot_recon/` | Fingerprints and inventories IoT/embedded devices on an authorized network. |
| **Threat Scanner** | `src/security_assistant/threat_scanner/` | Correlates recon output against known vulnerability and threat-intel feeds. |
| **Network/VPN Daemon** | `src/security_assistant/network/` | Manages VPN connection lifecycle and kill-switch for scan traffic. |

Security capabilities are not hard-wired into the engine — they are *tools*
registered with a `ToolRegistry` and dispatched under a uniform safety policy.
The core depends on nothing outside the standard library.

See [`docs/architecture.md`](docs/architecture.md) for the full blueprint,
directory tree, and data-flow diagram.

## Authorization model

Scope enforcement lives in the dispatcher, above every tool, so a tool author
cannot forget to check it:

- **Default deny.** An empty scope authorizes nothing.
- **Denies beat allows.** A denied target is refused even if an allow rule also matches.
- **Risk is capped.** A scope declares the most intrusive class of action it permits:
  `passive` (never contacts the target), `active` (contacts it non-intrusively),
  or `intrusive` (may change state or trip alerting).
- **Fails closed.** With no scope configured, scope-gated tools refuse to run.
- **Audited.** Every invocation records its target and the rule that authorized it.

Configure it in the `engagement:` block of `config/config.yaml` (or via the
`ENGAGEMENT_*` environment variables). It is a safeguard that makes the boundary
enforceable in code — not a substitute for having permission in the first place.

```python
from security_assistant.core import Agent, AuthorizationScope, RiskLevel, ToolRegistry

scope = AuthorizationScope(
    allow=["example.com", "192.0.2.0/24"],
    deny=["prod.example.com"],
    max_risk=RiskLevel.ACTIVE,
    authorization_reference="ENG-2024-114",
)

agent = Agent(registry, scope)
result = await agent.run("Map external attack surface", target="example.com")
print(result.summary())
```

## Repository Layout

```
.
├── src/security_assistant/
│   ├── core/                 # Agent engine: orchestrator, dispatch, planner, memory
│   ├── osint/                # OSINT & entity graph
│   ├── iot_recon/            # IoT & asset discovery
│   ├── threat_scanner/       # Threat intel & URL scanning
│   └── network/              # VPN lifecycle & kill-switch
├── config/                   # YAML configs, logging config, engagement scope
├── tests/                    # Unit and integration tests
├── docs/                     # Architecture blueprints
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── requirements.txt          # application scaffolding
├── requirements-modules.txt  # optional per-module extras
└── .env.example
```

## Setup & Local Run

### Requirements

- Python 3.11+
- [Poetry](https://python-poetry.org/) (recommended) or `pip`
- Docker (optional, for containerized runs)

### Option A — Poetry

```bash
poetry install
cp .env.example .env      # fill in real values
poetry run pytest
poetry run python -m security_assistant
```

### Option B — pip + venv

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env      # fill in real values
pytest
python -m security_assistant
```

Feature modules pull in extra dependencies. Install only what you enable:

```bash
poetry install -E osint -E iot          # or: -E all
pip install -r requirements-modules.txt # pip equivalent (all modules)
```

### Option C — Docker

```bash
cp .env.example .env      # fill in real values
docker compose up --build
```

## Configuration

- Non-secret runtime settings live in `config/config.yaml`.
- Logging is configured in `config/logging.yaml`.
- Secrets (API keys, VPN credentials, webhook URLs) are supplied via
  environment variables — copy `.env.example` to `.env` and fill it in.
  `.env` is git-ignored and must never be committed.

## Testing

```bash
pytest                      # full suite
pytest tests/unit           # unit tests only
pytest tests/integration    # integration tests only
```

Static analysis (both are clean on `main`):

```bash
ruff check src/ tests/      # lint
mypy src/                   # strict type checking
```

The agent core needs no third-party packages, so its tests run in a bare
Python 3.11 environment with only `pytest` installed.

## License

Private project — all rights reserved unless a `LICENSE` file states
otherwise.
