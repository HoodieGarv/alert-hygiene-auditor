"""Data ingestion layer — fetches, normalises, and persists alert firing data.

Submodules
----------
prometheus_client    : HTTP client for the Prometheus rules and query_range APIs.
alertmanager_client  : HTTP client for the Alertmanager v2 alerts API.
normalizer           : Converts raw API payloads into AlertFiring ORM rows.
runner               : Orchestrates a full ingestion pass and records an audit trail.
"""
