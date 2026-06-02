"""Transform raw API responses into AlertFiring ORM instances.

Pydantic models are used as intermediate validation schemas to catch malformed
API responses before any data reaches the database.  This means a single
unexpected field shape from the upstream API raises a clear ValidationError
rather than a cryptic AttributeError or silent data corruption.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, field_validator

from auditor.db.models import AlertFiring

# ---------------------------------------------------------------------------
# Intermediate Pydantic schemas
# ---------------------------------------------------------------------------


class _PrometheusAlertSeries(BaseModel):
    """One element from the ``result`` list in a Prometheus query_range response.

    ``metric`` holds the label set (including ``alertname`` and ``alertstate``).
    ``values`` is a list of ``[unix_timestamp_float, "1"]`` pairs — one per
    evaluation cycle where the alert was in the firing state.
    """

    metric: dict[str, str]
    values: list[tuple[float, str]]


class _AlertmanagerAlert(BaseModel):
    """One element from the Alertmanager ``/api/v2/alerts`` response array."""

    labels: dict[str, str]
    annotations: dict[str, str]
    startsAt: datetime
    endsAt: datetime
    status: dict[str, Any]
    fingerprint: str

    @field_validator("startsAt", "endsAt", mode="before")
    @classmethod
    def _coerce_to_utc(cls, value: Any) -> datetime:
        # Alertmanager timestamps are RFC 3339 strings with explicit timezone
        # offsets (e.g. "2024-01-01T12:00:00.000Z").  Parse them and normalise
        # to UTC so every stored timestamp is comparable regardless of the
        # server's local time configuration.
        if isinstance(value, str):
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            dt = value
        return dt.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _unix_to_utc(ts: float) -> datetime:
    """Convert a Unix epoch float to a UTC-aware datetime."""
    # Prometheus timestamps are always UTC epoch floats; fromtimestamp with
    # tz=utc converts without relying on the host's local timezone setting.
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def _group_consecutive(
    timestamps: list[float], step_seconds: float = 15.0
) -> list[tuple[float, float]]:
    """Collapse a sorted list of Unix timestamps into (start, end) firing windows.

    Two consecutive samples are considered part of the same continuous firing
    if the gap between them is no greater than ``step_seconds * 2``.  Allowing
    two missed evaluations before splitting a window tolerates occasional scrape
    jitter without fragmenting a single long-running firing into many short rows.

    Returns a list of ``(window_start, window_end)`` Unix timestamp pairs.
    """
    if not timestamps:
        return []

    windows: list[tuple[float, float]] = []
    window_start = timestamps[0]
    prev = timestamps[0]

    for ts in timestamps[1:]:
        if ts - prev > step_seconds * 2:
            # Gap exceeds tolerance — close the current window and open a new one.
            windows.append((window_start, prev))
            window_start = ts
        prev = ts

    windows.append((window_start, prev))
    return windows


# ---------------------------------------------------------------------------
# Public normalisation functions
# ---------------------------------------------------------------------------


def normalize_prometheus_series(
    raw_series: list[dict[str, Any]],
    step_seconds: float = 15.0,
) -> list[AlertFiring]:
    """Convert Prometheus ALERTS matrix entries into AlertFiring rows.

    Each entry in ``raw_series`` represents one unique alert label set.  Its
    ``values`` list is collapsed into one or more AlertFiring rows using
    ``_group_consecutive``: a continuous run of samples maps to a single row,
    and a gap larger than 2× the step interval produces a new row to represent
    a distinct resolve/re-fire event.

    Prometheus ``query_range`` does not return annotation data — only the
    metric label set.  The ``annotations`` column is stored as an empty dict
    for Prometheus-sourced rows; annotations can be back-filled from
    ``/api/v1/rules`` in a later enrichment pass if needed.
    """
    rows: list[AlertFiring] = []

    for raw in raw_series:
        # Validate the raw dict through the Pydantic schema before accessing
        # any fields, so that unexpected API response shapes fail loudly.
        entry = _PrometheusAlertSeries.model_validate(raw)

        alert_name = entry.metric.get("alertname", "unknown")
        # Extract only the timestamp component; the value column is always "1".
        timestamps = sorted(ts for ts, _ in entry.values)
        windows = _group_consecutive(timestamps, step_seconds)

        for start_ts, end_ts in windows:
            rows.append(
                AlertFiring(
                    alert_name=alert_name,
                    # Store the complete metric label set as JSON so the
                    # analysis engine can filter on arbitrary dimensions
                    # (severity, team, etc.) without schema changes.
                    labels=dict(entry.metric),
                    # Prometheus query_range carries no annotation data.
                    annotations={},
                    # Convert Unix epoch floats to UTC-aware datetimes.
                    starts_at=_unix_to_utc(start_ts),
                    ends_at=_unix_to_utc(end_ts),
                    state="firing",
                    source="prometheus",
                )
            )

    return rows


def normalize_alertmanager_alerts(
    raw_alerts: list[dict[str, Any]],
) -> list[AlertFiring]:
    """Convert Alertmanager alert objects into AlertFiring rows.

    Alertmanager uses RFC 3339 timestamps with explicit timezone offsets.  The
    ``_AlertmanagerAlert`` Pydantic schema normalises these to UTC-aware
    datetimes, so all rows written by this function are timezone-consistent with
    rows written by ``normalize_prometheus_series``.

    Alertmanager's three-value state vocabulary (``active``, ``suppressed``,
    ``unprocessed``) is mapped to the auditor's two-value enum: ``active``
    becomes ``"firing"``; everything else becomes ``"resolved"``.  The full
    status dict (including ``silencedBy`` and ``inhibitedBy``) is preserved
    inside the ``labels`` JSON column so downstream analyses can distinguish
    suppressed noise from unsuppressed noise.
    """
    rows: list[AlertFiring] = []

    for raw in raw_alerts:
        # Pydantic validates field types, coerces timestamps to UTC, and raises
        # a clear ValidationError on malformed input rather than propagating a
        # KeyError or TypeError into the database write path.
        alert = _AlertmanagerAlert.model_validate(raw)

        alert_name = alert.labels.get("alertname", "unknown")

        # Map Alertmanager state to the auditor's two-value enum.
        state = "firing" if alert.status.get("state") == "active" else "resolved"

        # Merge the status block into the labels JSON so analysts can query
        # "was this alert silenced?" without a separate join.
        labels_with_status = {
            **alert.labels,
            "_am_state": alert.status.get("state", ""),
            "_am_silenced_by": ",".join(alert.status.get("silencedBy", [])),
            "_am_inhibited_by": ",".join(alert.status.get("inhibitedBy", [])),
        }

        rows.append(
            AlertFiring(
                alert_name=alert_name,
                labels=labels_with_status,
                annotations=dict(alert.annotations),
                starts_at=alert.startsAt,
                ends_at=alert.endsAt,
                state=state,
                source="alertmanager",
            )
        )

    return rows
