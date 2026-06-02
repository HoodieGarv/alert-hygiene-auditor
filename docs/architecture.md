# Architecture

## Overview

Alert Hygiene Auditor connects to one or more monitoring back-ends (Prometheus,
Alertmanager, or compatible systems), collects historical alert data, and
produces actionable hygiene reports that identify noisy, stale, and redundant
alert rules.

## High-level component diagram

```
┌─────────────────────────────────────────────────────┐
│                   CLI / Entry-point                 │
└────────────────────────┬────────────────────────────┘
                         │
           ┌─────────────▼──────────────┐
           │        Auditor Core        │
           │  (orchestration & scoring) │
           └──┬──────────────────────┬──┘
              │                      │
   ┌──────────▼──────┐    ┌──────────▼──────┐
   │  Data Fetchers  │    │    Analyzers     │
   │  (Prometheus /  │    │  (noise, drift,  │
   │  Alertmanager)  │    │   redundancy)    │
   └──────────┬──────┘    └──────────┬──────┘
              │                      │
              └──────────┬───────────┘
                         │
              ┌──────────▼──────────┐
              │   Report Renderer   │
              │  (table/JSON/MD)    │
              └─────────────────────┘
```

## Key design decisions

| Decision | Rationale |
|---|---|
| Config-driven thresholds | Lets operators tune sensitivity without code changes |
| Pluggable fetcher interface | Supports Prometheus today; easy to add Datadog, Grafana, etc. |
| Immutable analyzer inputs | Analyzers receive plain data classes — no side effects |
| Report-dir output | Keeps reports auditable and version-controllable |

## Directory layout

```
src/auditor/      # application package
tests/            # pytest test suite
config/           # default configuration
docs/             # design and runbook documentation
scripts/          # helper shell scripts (migration, seed data, etc.)
docker/           # Dockerfiles and compose files
```
