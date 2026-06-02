"""SQLAlchemy ORM models for the alert hygiene auditor."""

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, DateTime, String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class AlertFiring(Base):
    """Represents a single alert firing event.

    Each row represents one discrete firing of a named alert rule.  The
    combination of ``alert_name`` and ``starts_at`` is the natural key used for
    deduplication: if an incoming record matches an existing row on both
    columns it is skipped, preventing double-counting of events that span
    two consecutive ingestion windows.

    ``labels`` and ``annotations`` are stored as JSON so that the analysis
    engine can filter and group on arbitrary label dimensions (e.g. severity,
    team, service) without requiring schema migrations when label sets change.
    """

    __tablename__ = "alert_firings"

    id: Mapped[int] = mapped_column(primary_key=True)

    # The name of the Prometheus alerting rule, e.g. "HighCPU".
    alert_name: Mapped[str] = mapped_column(String, index=True)

    # Full label set of the alert instance, stored verbatim from the source API.
    labels: Mapped[dict[str, Any]] = mapped_column(JSON)

    # Annotations attached to the alert rule (summary, description, runbook, etc.).
    annotations: Mapped[dict[str, Any]] = mapped_column(JSON)

    # UTC timestamp when the alert first entered the firing state.
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

    # UTC timestamp when the alert resolved.  NULL means the alert is still active.
    ends_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # "firing" or "resolved" — the state of the alert at ingestion time.
    state: Mapped[str] = mapped_column(String(16))

    # "prometheus" or "alertmanager" — which API the row was sourced from.
    source: Mapped[str] = mapped_column(String(32))

    # UTC timestamp when this row was written to the database.
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )


class IngestionRun(Base):
    """Tracks each execution of the ingestion service.

    This table provides an audit trail for ingestion runs and is used to
    implement incremental ingestion: each run queries only for alerts that
    fired after the last successful run's ``ran_at`` timestamp.  On the very
    first run (no prior IngestionRun rows with ``status == "success"``), the
    service falls back to ``now - lookback_days`` to bootstrap the initial
    history window.
    """

    __tablename__ = "ingestion_runs"

    id: Mapped[int] = mapped_column(primary_key=True)

    # UTC timestamp at which this ingestion run started.
    ran_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    # Total number of raw records returned by the upstream APIs.
    records_fetched: Mapped[int] = mapped_column()

    # Number of new rows actually written to alert_firings (after deduplication).
    records_inserted: Mapped[int] = mapped_column()

    # Which source(s) were queried, e.g. "prometheus+alertmanager".
    source: Mapped[str] = mapped_column(String(64))

    # "success" or "error".
    status: Mapped[str] = mapped_column(String(16))

    # Populated only when status == "error"; contains the exception message.
    error_message: Mapped[str | None] = mapped_column(String, nullable=True)
