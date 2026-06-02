"""Analysis engine — orchestrates all three detectors and produces a unified report.

This module is the public entry point for the analysis layer.  Callers obtain
an AnalysisEngine, call run(), and receive an AnalysisReport without needing
to know which detectors exist or how they work internally.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from auditor.analysis.detectors.chronic_noise import ChronicNoiseDetector
from auditor.analysis.detectors.co_firing import CoFiringDetector
from auditor.analysis.detectors.isolation_forest import (
    InsufficientDataError,
    IsolationForestDetector,
)
from auditor.analysis.detectors.threshold_drift import ThresholdDriftDetector
from auditor.analysis.schemas import AlertHygieneIssue, AnalysisReport
from auditor.db.models import AlertFiring

logger = logging.getLogger(__name__)


class AnalysisEngine:
    """Runs all detectors and assembles their findings into a single AnalysisReport.

    **Why detectors run independently rather than in a pipeline**

    A pipeline design would have each detector receive the output of the
    previous one, filtering or annotating as it goes.  That approach tightly
    couples detectors to each other's output format and makes it impossible to
    run them in parallel or in isolation during testing.  Independent detectors
    can each query the database directly for exactly the data they need, can
    be swapped in and out without affecting others, and can be tested with a
    mock session without setting up the full chain.  The cost is a small number
    of additional SQL queries (one per detector), which is negligible compared
    to the flexibility gained.

    **Why deduplication happens at the engine level rather than inside detectors**

    Each detector is designed with a single responsibility: find one type of
    issue.  Asking a detector to also know about the output of sibling detectors
    would break that separation.  The engine is the natural place to apply
    cross-cutting concerns like deduplication because it is the only component
    that sees all detector outputs simultaneously.

    Deduplication key: ``(alert_name, issue_type)``.  An alert can legitimately
    have both a CHRONIC_NOISE finding and a THRESHOLD_DRIFT finding — those are
    different issue types and both are preserved.  What is deduplicated is the
    case where the same detector could theoretically produce duplicate rows for
    the same alert (e.g. if a future detector is stateful and runs incrementally
    with overlapping windows).
    """

    def __init__(
        self,
        session: Session,
        lookback_days: int = 30,
    ) -> None:
        self._session = session
        self._lookback_days = lookback_days

        # Detectors are instantiated here with default thresholds.  In a future
        # phase these thresholds will be read from Settings to allow per-install
        # tuning without code changes.
        self._detectors: list[
            ChronicNoiseDetector | CoFiringDetector | ThresholdDriftDetector
        ] = [
            ChronicNoiseDetector(),
            CoFiringDetector(),
            ThresholdDriftDetector(),
        ]

        # The ML detector is held separately rather than in the list above
        # because it can raise InsufficientDataError and must be run inside a
        # try/except (see run()).  The rule-based detectors above never raise on
        # sparse data — they simply return no findings — so they can run in a
        # plain loop, whereas the ML detector needs graceful-failure handling.
        self._ml_detector = IsolationForestDetector()

    def run(self) -> AnalysisReport:
        """Execute all detectors and return a deduplicated AnalysisReport.

        Detectors are run sequentially in the order they appear in
        ``self._detectors``.  All issues are collected, deduplicated on
        ``(alert_name, issue_type)``, then assembled into the report.  The
        ``metadata`` field records the names of detectors that ran, the total
        issue count before deduplication, and the elapsed wall-clock time.
        """
        since = datetime.now(tz=timezone.utc) - timedelta(days=self._lookback_days)
        started_at = time.monotonic()

        # Count distinct alert names in the window — this is the denominator
        # for any "what fraction of alerts have issues?" calculation.
        total_alerts_analyzed: int = (
            self._session.execute(
                select(func.count(func.distinct(AlertFiring.alert_name))).where(
                    AlertFiring.starts_at >= since
                )
            ).scalar_one()
            or 0
        )

        # --- Run each detector --------------------------------------------
        all_issues: list[AlertHygieneIssue] = []
        detector_names: list[str] = []
        issues_per_detector: dict[str, int] = {}

        for detector in self._detectors:
            name = type(detector).__name__
            detector_names.append(name)
            found = detector.detect(self._session, since)
            issues_per_detector[name] = len(found)
            all_issues.extend(found)

        # --- Run the ML detector with graceful failure --------------------
        #
        # The rule-based detectors can produce findings with minimal data, but
        # the Isolation Forest detector deliberately refuses to run on too few
        # records (raising InsufficientDataError).  That refusal must not block
        # the rest of the report: a sparse-data run should still return the
        # rule-based findings.  So the ML detector is wrapped here and its
        # failure is downgraded to a logged warning recorded in metadata.
        ml_name = type(self._ml_detector).__name__
        detector_names.append(ml_name)
        try:
            ml_found = self._ml_detector.detect(self._session, since)
            issues_per_detector[ml_name] = len(ml_found)
            all_issues.extend(ml_found)
        except InsufficientDataError as exc:
            logger.warning("Skipping %s: %s", ml_name, exc)
            issues_per_detector[ml_name] = 0

        raw_count = len(all_issues)

        # --- Deduplicate on (alert_name, issue_type) ----------------------
        #
        # Iterate in the order issues were produced so that when duplicates
        # exist the first detector's finding is kept (ChronicNoise before
        # CoFiring before ThresholdDrift).
        seen: set[tuple[str, str]] = set()
        deduplicated: list[AlertHygieneIssue] = []

        for issue in all_issues:
            key = (issue.alert_name, issue.issue_type.value)
            if key not in seen:
                seen.add(key)
                deduplicated.append(issue)

        elapsed_ms = round((time.monotonic() - started_at) * 1000)

        return AnalysisReport(
            generated_at=datetime.now(tz=timezone.utc),
            lookback_days=self._lookback_days,
            total_alerts_analyzed=total_alerts_analyzed,
            issues_found=deduplicated,
            metadata={
                "detectors_run": detector_names,
                "issues_per_detector": issues_per_detector,
                "issues_before_deduplication": raw_count,
                "issues_after_deduplication": len(deduplicated),
                "analysis_window_start": since.isoformat(),
                "elapsed_ms": elapsed_ms,
            },
        )
