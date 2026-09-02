# Architecture Blueprint

## Overview

The Autonomous Security & Intelligence Assistant is a modular pipeline for
running authorized security assessments end to end: reconnaissance,
threat correlation, and reporting, coordinated by a central orchestrator.

## Components

```
                    +----------------------+
                    |     Orchestrator     |
                    +----------------------+
                     /        |        \        \
                    /         |         \         \
          +--------+   +-----------+  +---------+  +--------------+
          | OSINT  |   | IoT Recon |  | Threat  |  | Network/VPN  |
          | Engine |   | Scanner   |  | Scanner |  | Daemon       |
          +--------+   +-----------+  +---------+  +--------------+
```

- **Orchestrator** (`src/security_assistant/orchestrator.py`): entry point
  that wires the engines together and runs a full assessment against a
  single authorized target.
- **OSINT Engine** (`src/security_assistant/osint/`): collects
  open-source intelligence (domains, subdomains, breach exposure, public
  records).
- **IoT Recon** (`src/security_assistant/iot_recon/`): fingerprints and
  inventories IoT/embedded devices on an authorized network.
- **Threat Scanner** (`src/security_assistant/threat_scanner/`):
  correlates recon output against vulnerability and threat-intel feeds.
- **Network/VPN Daemon** (`src/security_assistant/network/`): manages the
  outbound network posture (VPN lifecycle, kill-switch) so all scan
  traffic goes through a controlled, authorized path.

## Data Flow

1. Operator supplies an authorized target to the orchestrator.
2. OSINT Engine and IoT Recon Scanner run reconnaissance in parallel.
3. Threat Scanner correlates recon output against configured feeds.
4. Results are aggregated and returned/reported to the operator.

## Configuration

Runtime configuration lives in `config/config.yaml`; secrets (API keys,
VPN credentials) are supplied via environment variables (see
`.env.example`) and never committed to the repository.

## Usage Scope

This project is intended for authorized security testing and defensive
research only, against assets the operator owns or has explicit
permission to assess.
