"""Tests for CoFiringDetector.

Co-firing detection identifies pairs of alert rules that consistently appear
within the same narrow time window across multiple independent incidents.  When
two alerts co-fire in the majority of their incidents, they are likely
responding to the same underlying failure — making them candidates for
consolidation into a single, better-targeted rule.

The detector buckets alert firings into fixed-width time slots (default: 5
minutes) and computes a co-occurrence ratio: how often do two alerts appear in
the same bucket, divided by how often the less-frequent alert fires at all.
A pair is flagged when this ratio exceeds the configured threshold (default:
70%).

Test cases
----------
- Always co-fire: two alerts that fire together in every bucket should be
  flagged with a ratio of 1.0.
- Never co-fire: alerts that fire hours apart should produce zero findings,
  confirming that the bucket logic correctly separates non-related firings.
- Three alerts, only two co-fire: validates that the detector flags only the
  correlated pair and does not incorrectly implicate the third independent
  alert.
"""

from datetime import datetime, timezone, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from auditor.analysis.detectors.co_firing import CoFiringDetector
from auditor.db.models import AlertFiring, Base

SINCE = datetime(2024, 1, 1, tzinfo=timezone.utc)
BASE_TIME = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_two_alerts_that_always_co_fire_produce_one_finding(session: object) -> None:
    """Two alerts that fire within the same 5-minute bucket on every incident must be flagged.

    Ten incidents are simulated.  In each incident DiskPressure fires first,
    then SlowDiskIO fires 90 seconds later — both within the same 5-minute
    bucket.  The incidents are spaced 2 hours apart so they are clearly
    independent events.  Expected co-occurrence ratio: 10/10 = 1.0.
    """
    for i in range(10):
        incident_start = BASE_TIME + timedelta(hours=i * 2)
        session.add(_firing("DiskPressure", incident_start + timedelta(seconds=30)))
        session.add(_firing("SlowDiskIO", incident_start + timedelta(seconds=90)))
    session.commit()

    issues = CoFiringDetector(window_minutes=5, co_fire_threshold=0.70).detect(
        session, SINCE
    )

    assert len(issues) == 1
    assert "DiskPressure" in issues[0].alert_name
    assert "SlowDiskIO" in issues[0].alert_name
    assert issues[0].evidence["co_occurrence_ratio"] >= 0.70


def test_two_alerts_that_never_co_fire_produce_no_findings(session: object) -> None:
    """Alerts that fire in completely different time buckets must not be flagged.

    AlertA fires on the hour; AlertB fires six hours later each day.  With a
    5-minute bucket width, six hours (= 72 buckets) is far beyond any
    co-occurrence window, so the pair's co-occurrence count is zero.
    """
    for i in range(10):
        session.add(_firing("AlertA", BASE_TIME + timedelta(hours=i * 12)))
        session.add(_firing("AlertB", BASE_TIME + timedelta(hours=i * 12 + 6)))
    session.commit()

    issues = CoFiringDetector(window_minutes=5, co_fire_threshold=0.70).detect(
        session, SINCE
    )

    assert issues == []


def test_only_correlated_pair_is_flagged_among_three_alerts(session: object) -> None:
    """When three alerts are present but only two consistently co-fire, exactly one finding is produced.

    AlertA and AlertB fire within 60 seconds of each other in every incident.
    AlertC fires two hours after each incident — always in a different bucket.
    The detector must flag exactly the (AlertA, AlertB) pair and must not
    include AlertC in any finding.
    """
    for i in range(10):
        incident_time = BASE_TIME + timedelta(hours=i * 3)
        # AlertA and AlertB share a 5-minute bucket (60 s apart).
        session.add(_firing("AlertA", incident_time))
        session.add(_firing("AlertB", incident_time + timedelta(seconds=60)))
        # AlertC fires 2 hours later — 24 buckets away from the incident window.
        session.add(_firing("AlertC", incident_time + timedelta(hours=2)))
    session.commit()

    issues = CoFiringDetector(window_minutes=5, co_fire_threshold=0.70).detect(
        session, SINCE
    )

    assert len(issues) == 1
    assert "AlertA" in issues[0].alert_name
    assert "AlertB" in issues[0].alert_name
    assert "AlertC" not in issues[0].alert_name
