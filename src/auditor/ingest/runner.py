"""Ingestion orchestration — runs one complete ingestion cycle."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select

from auditor.config import get_settings
from auditor.db.models import AlertFiring, IngestionRun
from auditor.db.session import get_session
from auditor.ingest.alertmanager_client import AlertmanagerClient
from auditor.ingest.normalizer import (
    normalize_alertmanager_alerts,
    normalize_prometheus_series,
)
from auditor.ingest.prometheus_client import PrometheusClient

logger = logging.getLogger(__name__)


def _last_successful_run_at(session: Any) -> datetime | None:
    """Return the ``ran_at`` timestamp of the most recent successful run, or None."""
    return session.execute(
        select(IngestionRun.ran_at)
        .where(IngestionRun.status == "success")
        .order_by(IngestionRun.ran_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def _existing_keys(session: Any, since: datetime) -> set[tuple[str, datetime]]:
    """Return the (alert_name, starts_at) natural keys already in the database.

    Filtered to rows with ``starts_at >= since`` to avoid a full-table scan.
    Used for bulk deduplication: one query loads all existing keys in the
    relevant window; incoming rows are checked against the resulting set in
    Python rather than with N individual SELECT statements.
    """
    rows = session.execute(
        select(AlertFiring.alert_name, AlertFiring.starts_at).where(
            AlertFiring.starts_at >= since
        )
    ).all()
    return {(row.alert_name, row.starts_at) for row in rows}


def run_ingestion() -> None:
    """Orchestrate one full ingestion cycle.

    Incremental ingestion strategy
    --------------------------------
    On each run the service determines a ``since`` timestamp:

    * If a prior successful ``IngestionRun`` row exists, ``since`` is its
      ``ran_at`` timestamp.  This means each run fetches only the window of
      new alerts rather than re-fetching the entire history.
    * On the very first run (no prior successful run), ``since`` defaults to
      ``now - lookback_days``, bootstrapping an initial history window.

    After fetching and normalising alerts from both Prometheus and Alertmanager,
    incoming rows are deduplicated against existing database records on the
    ``(alert_name, starts_at)`` natural key.  This makes the ingestion
    idempotent: re-running the cycle for any reason (crash recovery, manual
    backfill) will not produce duplicate rows.

    The audit ``IngestionRun`` record is written in a separate session inside
    a ``finally`` block so that it is persisted regardless of whether the
    ingestion succeeded or failed.  This ensures the audit trail is complete
    even when the main data write was rolled back due to an error.
    """
    settings = get_settings()
    run_start = datetime.now(tz=timezone.utc)

    records_fetched: int = 0
    records_inserted: int = 0
    status: str = "success"
    error_message: str | None = None

    try:
        # Determine the ingestion window start in its own session so that any
        # error in the lookup does not taint the session used for inserts.
        with get_session() as session:
            since = _last_successful_run_at(session) or (
                run_start - timedelta(days=settings.lookback_days)
            )

        logger.info(
            "Starting ingestion run — window: %s → %s",
            since.isoformat(),
            run_start.isoformat(),
        )

        # --- Prometheus --------------------------------------------------
        with PrometheusClient(settings.prometheus_url) as prom:
            raw_series = prom.fetch_alert_history(start=since, end=run_start)
        records_fetched += len(raw_series)
        prom_rows = normalize_prometheus_series(raw_series)
        logger.debug(
            "Prometheus: %d series → %d AlertFiring rows",
            len(raw_series),
            len(prom_rows),
        )

        # --- Alertmanager ------------------------------------------------
        with AlertmanagerClient(settings.alertmanager_url) as am:
            raw_alerts = am.fetch_alerts()
        records_fetched += len(raw_alerts)
        am_rows = normalize_alertmanager_alerts(raw_alerts)
        logger.debug(
            "Alertmanager: %d alerts → %d AlertFiring rows",
            len(raw_alerts),
            len(am_rows),
        )

        all_rows = prom_rows + am_rows

        # --- Deduplication and insert ------------------------------------
        with get_session() as session:
            # Load existing keys in the relevant window with a single bulk
            # SELECT rather than checking each incoming row individually.
            existing = _existing_keys(session, since)

            new_rows = [
                row
                for row in all_rows
                if (row.alert_name, row.starts_at) not in existing
            ]
            records_inserted = len(new_rows)

            session.add_all(new_rows)

        logger.info(
            "Ingestion complete — fetched: %d, inserted: %d, skipped: %d",
            records_fetched,
            records_inserted,
            len(all_rows) - records_inserted,
        )

    except Exception as exc:
        status = "error"
        error_message = str(exc)
        logger.exception("Ingestion failed: %s", exc)
        raise

    finally:
        # Write the audit record in its own session so it commits even if the
        # main data session was rolled back.  An IngestionRun row with
        # status="error" is more useful than no row at all.
        with get_session() as audit_session:
            audit_session.add(
                IngestionRun(
                    ran_at=run_start,
                    records_fetched=records_fetched,
                    records_inserted=records_inserted,
                    source="prometheus+alertmanager",
                    status=status,
                    error_message=error_message,
                )
            )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )
    run_ingestion()
