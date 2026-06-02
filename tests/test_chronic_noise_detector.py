"""Tests for ChronicNoiseDetector.

The ChronicNoiseDetector finds alert rules that fire too frequently within a
time window AND whose firings rarely reach a resolved state.  The combination
of both conditions is intentional: high firing frequency alone may indicate a
legitimately busy system, but high frequency with a low resolved ratio indicates
an alert that on-call engineers have learned to ignore — the worst form of alert
fatigue because it erodes trust in the entire alerting system silently.

Test cases
----------
- Below threshold: confirms the detector does not flag alerts that fire
  infrequently, even if they never resolve.
- High severity noisy alert: exercises the happy-path detection case and
  validates that severity is HIGH when the resolved ratio is near zero.
- Frequently firing but resolved: confirms that a high resolved ratio
  suppresses the finding, because frequent resolution means the alert is
  actionable, not noisy.
- Empty table: exercises the edge case where no data exists in the window;
  the detector must return an empty list rather than raising a division-by-zero
  or ORM error.
"""

from datetime import datetime, timezone, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from auditor.analysis.detectors.chronic_noise import ChronicNoiseDetector
from auditor.analysis.schemas import Severity
from auditor.db.models import AlertFiring, Base

# Fixed window start used across all tests.  A static value avoids any
# possibility of flakiness from clock-dependent comparisons.
SINCE = datetime(2024, 1, 1, tzinfo=timezone.utc)

# All test records are created well inside the window so there is no ambiguity
# about whether a record falls before or after the SINCE boundary.
BASE_TIME = datetime(2024, 1, 15, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def session():
    """Provide a fresh in-memory SQLite session with all tables created.

    SQLite is used rather than PostgreSQL so tests run without any external
    service dependency.  Each call creates an isolated database — tests cannot
    interfere with each other.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    sess = sessionmaker(bind=engine, expire_on_commit=False)()
    yield sess
    sess.close()


def _firing(
    alert_name: str, state: str = "firing", offset_hours: int = 0
) -> AlertFiring:
    """Build one AlertFiring row with minimal required fields populated."""
    return AlertFiring(
        alert_name=alert_name,
        labels={"alertname": alert_name},
        annotations={},
        starts_at=BASE_TIME + timedelta(hours=offset_hours),
        ends_at=None,
        state=state,
        source="prometheus",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_no_findings_when_below_threshold(session: object) -> None:
    """Alerts that fire fewer times than the threshold must never be flagged.

    Five firings is well below the default threshold of 20.  The detector
    should return an empty list regardless of the resolved ratio.
    """
    for i in range(5):
        session.add(_firing("LowVolumeAlert", offset_hours=i))
    session.commit()

    issues = ChronicNoiseDetector().detect(session, SINCE)

    assert issues == []


def test_high_severity_finding_for_noisy_unresolved_alert(session: object) -> None:
    """An alert above the threshold with a near-zero resolved ratio must produce a HIGH finding.

    25 firings exceeds the default threshold of 20.  All rows have
    state="firing" so the resolved ratio is 0.0%, which is below the 5%
    boundary used to assign HIGH severity.
    """
    for i in range(25):
        session.add(_firing("HighCPU", state="firing", offset_hours=i))
    session.commit()

    issues = ChronicNoiseDetector(firing_threshold=20).detect(session, SINCE)

    assert len(issues) == 1
    issue = issues[0]
    assert issue.alert_name == "HighCPU"
    assert issue.severity == Severity.HIGH
    assert issue.evidence["total_firings"] == 25
    assert issue.evidence["resolved_ratio"] == 0.0


def test_no_finding_when_alert_resolves_frequently(session: object) -> None:
    """An alert that fires often but resolves most of the time must not be flagged.

    25 firings exceeds the threshold, but 20 of them are in the 'resolved'
    state.  Resolved ratio = 20/25 = 80%, which is above the 30% threshold,
    so the alert is considered actionable rather than noisy.
    """
    for i in range(5):
        session.add(_firing("ActionableAlert", state="firing", offset_hours=i))
    for i in range(5, 25):
        session.add(_firing("ActionableAlert", state="resolved", offset_hours=i))
    session.commit()

    issues = ChronicNoiseDetector(firing_threshold=20).detect(session, SINCE)

    assert issues == []


def test_empty_table_returns_no_findings_without_error(session: object) -> None:
    """The detector must return an empty list when the table contains no rows.

    This is the most common state on a freshly initialised database.  An
    implementation that uses division (e.g. resolved / total) must guard
    against dividing by zero in this case.
    """
    # No records added — alert_firings table is completely empty.
    issues = ChronicNoiseDetector().detect(session, SINCE)

    assert issues == []
