"""Tests for ThresholdDriftDetector.

Threshold drift detection identifies alerts whose firing rate increases
monotonically across consecutive time slices.  A monotonically increasing
rate — as opposed to simply a high rate — indicates that the gap between the
alert threshold and the actual system baseline is growing.  This is the
signature of a threshold that was calibrated once and never revisited.

The detector divides the lookback window into equal slices (default: 7 days)
and counts how many firings fall in each slice.  An alert is flagged when its
per-slice counts form a strictly increasing sequence across at least
``min_consecutive_slices`` (default: 3) consecutive slices.

Test cases
----------
- Monotonically increasing: slice counts [2, 5, 9, 14] produce a run of 4
  consecutive increases, which satisfies the default threshold of 3.
- High but stable: slice counts [10, 10, 10, 10] represent chronic noise but
  not drift — no consecutive increases, so no finding.
- Increase then decrease: slice counts [2, 8, 3, 5] produce a maximum run of
  two consecutive increases, which is below the threshold of 3, confirming
  that a transient spike followed by recovery is not classified as drift.
"""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from auditor.analysis.detectors.threshold_drift import ThresholdDriftDetector
from auditor.db.models import AlertFiring, Base


@pytest.fixture()
def session():
    """Fresh in-memory SQLite session, isolated per test."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    sess = sessionmaker(bind=engine, expire_on_commit=False)()
    yield sess
    sess.close()


def _firing(alert_name: str, starts_at: datetime) -> AlertFiring:
    return AlertFiring(
        alert_name=alert_name,
        labels={"alertname": alert_name},
        annotations={},
        starts_at=starts_at,
        ends_at=None,
        state="firing",
        source="prometheus",
    )


def _add_firings_in_slice(
    session: object,
    alert_name: str,
    since: datetime,
    slice_idx: int,
    count: int,
    slice_days: int = 7,
) -> None:
    """Insert ``count`` firings for ``alert_name`` into a specific weekly slice.

    Records are placed at hourly offsets from the start of the slice so they
    land safely inside the slice boundary and do not accidentally cross into
    the adjacent slice due to floating-point timestamp rounding.
    """
    slice_start = since + timedelta(days=slice_idx * slice_days)
    for i in range(count):
        # Cap at 23 hours to guarantee all records stay within the slice.
        hour_offset = min(i, 23)
        session.add(_firing(alert_name, slice_start + timedelta(hours=hour_offset)))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_monotonically_increasing_rate_is_flagged(session: object) -> None:
    """An alert with strictly increasing firing counts across four weekly slices must be flagged.

    Slice counts: [2, 5, 9, 14].  The longest consecutive increasing run is 4,
    which satisfies the minimum threshold of 3.
    """
    # since must be close enough to now that the detector builds a meaningful
    # set of slices.  28 days produces exactly four 7-day slices.
    since = datetime.now(timezone.utc) - timedelta(days=28)

    _add_firings_in_slice(session, "DriftingAlert", since, 0, 2)
    _add_firings_in_slice(session, "DriftingAlert", since, 1, 5)
    _add_firings_in_slice(session, "DriftingAlert", since, 2, 9)
    _add_firings_in_slice(session, "DriftingAlert", since, 3, 14)
    session.commit()

    issues = ThresholdDriftDetector(slice_days=7, min_consecutive_slices=3).detect(
        session, since
    )

    assert len(issues) == 1
    assert issues[0].alert_name == "DriftingAlert"
    assert issues[0].evidence["longest_increasing_run"] >= 3


def test_high_but_stable_rate_is_not_flagged(session: object) -> None:
    """An alert with a consistently high but flat firing rate must not be classified as drifting.

    Slice counts: [10, 10, 10, 10].  There are no consecutive increases
    (equal adjacent values are not considered strictly increasing), so the
    longest run is 1 and the alert is not flagged.
    """
    since = datetime.now(timezone.utc) - timedelta(days=28)

    for i in range(4):
        _add_firings_in_slice(session, "StableNoisyAlert", since, i, 10)
    session.commit()

    issues = ThresholdDriftDetector(slice_days=7, min_consecutive_slices=3).detect(
        session, since
    )

    assert issues == []


def test_increase_then_decrease_is_not_flagged(session: object) -> None:
    """An alert whose rate rises and then falls must not be classified as drifting.

    Slice counts: [2, 8, 3, 5].
    Consecutive increasing runs: [2 (slices 0–1), 2 (slices 2–3)].
    Maximum run length is 2, which is below the minimum threshold of 3.
    """
    since = datetime.now(timezone.utc) - timedelta(days=28)

    _add_firings_in_slice(session, "SpikeyAlert", since, 0, 2)
    _add_firings_in_slice(session, "SpikeyAlert", since, 1, 8)
    _add_firings_in_slice(session, "SpikeyAlert", since, 2, 3)
    _add_firings_in_slice(session, "SpikeyAlert", since, 3, 5)
    session.commit()

    issues = ThresholdDriftDetector(slice_days=7, min_consecutive_slices=3).detect(
        session, since
    )

    assert issues == []
