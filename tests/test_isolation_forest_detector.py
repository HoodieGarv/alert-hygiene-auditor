"""Tests for IsolationForestDetector and its integration with AnalysisEngine.

These tests cover the detector's two defining behaviours: the data-sufficiency
gate that protects against training on too little history, and the graceful
degradation path that keeps a sparse-data analysis run from failing entirely.
They also confirm the happy-path output shape — that findings are well-formed
ANOMALOUS_PATTERN issues carrying the full seven-feature evidence payload.

A fixed random_state makes the model deterministic, so the set of flagged
alerts is stable across runs.

Test cases
----------
- Data sufficiency gate: too few records must raise InsufficientDataError.
- Happy path: sufficient data yields ANOMALOUS_PATTERN AlertHygieneIssues.
- Evidence completeness: every finding carries all seven feature keys.
- Graceful degradation: the engine logs and continues when the ML detector
  refuses to run on sparse data, rather than propagating the exception.
"""

import logging
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from auditor.analysis.engine import AnalysisEngine
from auditor.analysis.detectors.isolation_forest import (
    InsufficientDataError,
    IsolationForestDetector,
)
from auditor.analysis.features import FEATURE_NAMES
from auditor.analysis.schemas import AlertHygieneIssue, IssueType
from auditor.db.models import AlertFiring, Base

# The detector computes its window as (now - since); use a live-relative since so
# the per-day trend and recency features map onto the intended window.
SINCE = datetime.now(timezone.utc) - timedelta(days=30)
BASE_TIME = datetime.now(timezone.utc) - timedelta(days=20)


@pytest.fixture()
def session():
    """Provide a fresh in-memory SQLite session with all tables created."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    sess = sessionmaker(bind=engine, expire_on_commit=False)()
    yield sess
    sess.close()


def _add_firings(
    session,
    alert_name: str,
    count: int,
    *,
    hour: int = 12,
    resolved: bool = True,
    spread_days: int = 10,
) -> None:
    """Add ``count`` firings for one alert, spread across ``spread_days`` days."""
    for i in range(count):
        starts = BASE_TIME + timedelta(days=(i % spread_days), hours=hour, minutes=i)
        session.add(
            AlertFiring(
                alert_name=alert_name,
                labels={},
                annotations={},
                starts_at=starts,
                ends_at=starts + timedelta(minutes=5) if resolved else None,
                state="resolved" if resolved else "firing",
                source="prometheus",
            )
        )
    session.commit()


def _populate_sufficient(session) -> None:
    """Create a realistic population: several normal alerts plus one outlier.

    Nine well-behaved alerts (5 firings each, resolved, varied hours) establish a
    baseline, and one pathological alert (40 unresolved firings all at the same
    hour) sits far from that baseline.  Total = 85 records, comfortably above the
    50-record gate, and the outlier guarantees the forest has a genuine anomaly
    to find.
    """
    for idx in range(9):
        _add_firings(
            session,
            f"NormalAlert{idx}",
            count=5,
            hour=(idx * 2) % 24,
            resolved=True,
        )
    _add_firings(
        session,
        "PathologicalAlert",
        count=40,
        hour=3,
        resolved=False,
        spread_days=2,
    )


def test_insufficient_data_raises(session, tmp_path) -> None:
    """Fewer than min_records_required records must raise InsufficientDataError."""
    _add_firings(session, "SparseAlert", count=10, resolved=True)

    detector = IsolationForestDetector(
        min_records_required=50,
        model_path=str(tmp_path / "m.joblib"),
    )

    with pytest.raises(InsufficientDataError):
        detector.detect(session, SINCE)


def test_sufficient_data_returns_anomaly_findings(session, tmp_path) -> None:
    """With sufficient data the detector returns ANOMALOUS_PATTERN issues."""
    _populate_sufficient(session)

    detector = IsolationForestDetector(
        contamination=0.1,
        model_path=str(tmp_path / "m.joblib"),
    )
    issues = detector.detect(session, SINCE)

    assert len(issues) >= 1
    assert all(isinstance(i, AlertHygieneIssue) for i in issues)
    assert all(i.issue_type == IssueType.ANOMALOUS_PATTERN for i in issues)


def test_every_finding_has_all_seven_feature_keys(session, tmp_path) -> None:
    """Each finding's evidence must include all seven engineered feature values."""
    _populate_sufficient(session)

    detector = IsolationForestDetector(
        contamination=0.1,
        model_path=str(tmp_path / "m.joblib"),
    )
    issues = detector.detect(session, SINCE)

    assert issues, "expected at least one finding to validate evidence keys"
    for issue in issues:
        for feature_name in FEATURE_NAMES:
            assert feature_name in issue.evidence
        assert "anomaly_score" in issue.evidence


def test_engine_degrades_gracefully_on_insufficient_data(session, caplog) -> None:
    """The engine must log and continue, not raise, when the ML detector refuses.

    With only a handful of records the IsolationForestDetector raises
    InsufficientDataError internally; the engine must catch it, record zero ML
    findings, and still return a complete report from the rule-based detectors.
    """
    _add_firings(session, "SparseAlert", count=5, resolved=True)

    with caplog.at_level(logging.WARNING):
        report = AnalysisEngine(session, lookback_days=30).run()

    # The run completed and the ML detector is recorded as having found nothing.
    assert "IsolationForestDetector" in report.metadata["detectors_run"]
    assert report.metadata["issues_per_detector"]["IsolationForestDetector"] == 0
    # A warning explaining the skip was emitted.
    assert any("IsolationForestDetector" in rec.message for rec in caplog.records)
