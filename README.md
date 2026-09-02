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
| **Orchestrator** | `src/security_assistant/orchestrator.py` | Wires the engines together and runs a full assessment against a target. |
| **OSINT Engine** | `src/security_assistant/osint/` | Collects open-source intelligence: domains, subdomains, breach exposure, public records. |
| **IoT Recon** | `src/security_assistant/iot_recon/` | Fingerprints and inventories IoT/embedded devices on an authorized network. |
| **Threat Scanner** | `src/security_assistant/threat_scanner/` | Correlates recon output against known vulnerability and threat-intel feeds. |
| **Network/VPN Daemon** | `src/security_assistant/network/` | Manages VPN connection lifecycle and kill-switch for scan traffic. |

See [`docs/architecture.md`](docs/architecture.md) for the full blueprint
and data-flow diagram.

## Repository Layout

```
.
├── src/security_assistant/   # Core orchestrator, engines, modules
├── config/                   # YAML configs, logging config, templates
├── tests/                    # Unit and integration tests
├── docs/                     # Architecture blueprints
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── requirements.txt
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

## License

Private project — all rights reserved unless a `LICENSE` file states
otherwise.
