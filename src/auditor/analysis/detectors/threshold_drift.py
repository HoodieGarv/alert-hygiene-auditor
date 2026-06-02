"""Detector for alert rules exhibiting threshold drift.

Threshold drift occurs when the system being monitored moves away from the
state it was in when an alert threshold was first configured, causing the alert
to fire with increasing frequency over time.  Unlike chronic noise — which is
high and roughly flat — drift has a directional signature: the firing rate
grows monotonically from slice to slice, indicating the gap between the
threshold and the actual system baseline is widening.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from auditor.analysis.schemas import AlertHygieneIssue, IssueType, Severity
from auditor.db.models import AlertFiring


def _longest_increasing_run(counts: list[int]) -> int:
    """Return the length of the longest strictly increasing consecutive run.

    A "run" here means a sequence of time slices where each slice has more
    firings than the one before it.  A run of length 3 means three consecutive
    slices with strictly increasing firing counts: [5, 9, 14] is a run of 3.

    Returns 1 if the list has a single element (vacuously non-decreasing), and
    0 for an empty list.
    """
    if not counts:
        return 0
    if len(counts) == 1:
        return 1

    current_run = 1
    max_run = 1

    for i in range(1, len(counts)):
        if counts[i] > counts[i - 1]:
            # This slice fired more than the previous — extend the current run.
            current_run += 1
            if current_run > max_run:
                max_run = current_run
        else:
            # Run broken — reset to 1 (the current slice alone is a run of 1).
            current_run = 1

    return max_run


def _severity(run_length: int, total_slices: int) -> Severity:
    """Severity is proportional to how much of the window shows monotonic growth.

    If nearly the full lookback window is monotonically increasing, the drift
    is both severe and established — the threshold was likely set long ago and
    the system has moved far from its original baseline.  A short run at the
    end of the window may be an emerging issue that warrants monitoring.
    """
    ratio = run_length / total_slices if total_slices > 0 else 0.0
    if ratio >= 0.85:
        return Severity.HIGH
    if ratio >= 0.60:
        return Severity.MEDIUM
    return Severity.LOW


class ThresholdDriftDetector:
    """Identifies alerts whose firing rate is growing monotonically over time.

    **Why monotonic increase is a stronger signal than high frequency**

    An alert that fires 40 times in 30 days and has always fired 40 times in
    30 days is noisy, but stable — the ChronicNoiseDetector handles that case.
    An alert whose firing rate was 2/week in week 1, 4/week in week 2, 7/week
    in week 3, and 12/week in week 4 is exhibiting something different: the
    gap between its threshold and the actual system state is *growing*.  This
    is the signature of a threshold that was calibrated once against a specific
    system state and never revisited as the system evolved.

    Monotonic increase is used rather than simple linear regression because it
    is directional and interpretable without statistical background: if firing
    counts go up in each consecutive time slice, the drift hypothesis is
    supported regardless of the absolute values or the slope magnitude.  A
    monotonic run of 3+ consecutive slices is required to exclude random
    variation that happens to be upward in two adjacent slices.

    **Algorithm**

    1. Divide the lookback window into equal time slices (default: 7-day slices
       over a 30-day window → 4 slices, plus a partial slice at the end).
    2. Count the number of ``AlertFiring`` rows per alert per slice.
    3. For each alert, find the longest consecutive run of strictly increasing
       slice counts.
    4. Flag alerts whose longest run meets or exceeds ``min_consecutive_slices``
       (default: 3).
    """

    def __init__(
        self,
        slice_days: int = 7,
        min_consecutive_slices: int = 3,
    ) -> None:
        self._slice_days = slice_days
        self._min_consecutive_slices = min_consecutive_slices

    def detect(self, session: Session, since: datetime) -> list[AlertHygieneIssue]:
        """Return one AlertHygieneIssue per alert with a monotonically increasing rate.

        Args:
            session: An active SQLAlchemy session.
            since:   The start of the lookback window (UTC).
        """
        now = datetime.now(tz=timezone.utc)

        # --- Build the time slice boundaries --------------------------------
        #
        # Produce a list of (slice_start, slice_end) pairs that tile the
        # window [since, now).  The final slice may be shorter than slice_days
        # if the window does not divide evenly — this is intentional; a partial
        # final slice still contributes meaningful direction information.
        slices: list[tuple[datetime, datetime]] = []
        cursor = since
        while cursor < now:
            slice_end = min(cursor + timedelta(days=self._slice_days), now)
            slices.append((cursor, slice_end))
            cursor = slice_end

        if len(slices) < self._min_consecutive_slices:
            # The lookback window is too short to detect the configured number
            # of consecutive increases — return no findings rather than
            # producing results based on insufficient data.
            return []

        slice_count = len(slices)
        slice_seconds = self._slice_days * 86400

        # --- Fetch firings and assign each row to a slice ------------------
        #
        # Rather than issuing one query per slice (N+1 pattern), fetch all
        # rows once and assign each to a slice index in Python using integer
        # division.  This is O(rows) in Python rather than O(rows × slices)
        # in SQL round-trips.
        stmt = select(AlertFiring.alert_name, AlertFiring.starts_at).where(
            AlertFiring.starts_at >= since
        )
        rows = session.execute(stmt).all()

        # slice_counts[alert_name][slice_index] = firing count in that slice
        slice_counts: dict[str, list[int]] = {}

        for row in rows:
            # SQLite returns naive datetimes; coerce to UTC so the subtraction
            # is always between two aware datetimes.
            starts_at = row.starts_at
            if starts_at.tzinfo is None:
                starts_at = starts_at.replace(tzinfo=timezone.utc)
            elapsed_seconds = (starts_at - since).total_seconds()
            # Integer division gives the zero-based slice index.  Clamp to
            # slice_count - 1 to handle the edge case where starts_at == now.
            idx = min(int(elapsed_seconds // slice_seconds), slice_count - 1)

            if row.alert_name not in slice_counts:
                # Initialise with zeros for all slices so that a slice with no
                # firings is represented as 0, not absent.
                slice_counts[row.alert_name] = [0] * slice_count
            slice_counts[row.alert_name][idx] += 1

        # --- Check each alert for monotonic increase ------------------------
        issues: list[AlertHygieneIssue] = []

        for alert_name, counts in slice_counts.items():
            run = _longest_increasing_run(counts)

            if run < self._min_consecutive_slices:
                # Does not meet the minimum consecutive-increase threshold.
                continue

            issues.append(
                AlertHygieneIssue(
                    alert_name=alert_name,
                    issue_type=IssueType.THRESHOLD_DRIFT,
                    severity=_severity(run, slice_count),
                    evidence={
                        "slice_counts": counts,
                        "slice_labels": [
                            s.isoformat() for s, _ in slices
                        ],
                        "longest_increasing_run": run,
                        "total_slices": slice_count,
                        "slice_days": self._slice_days,
                        "min_consecutive_slices": self._min_consecutive_slices,
                        "window_start": since.isoformat(),
                        "window_end": now.isoformat(),
                    },
                    detected_at=now,
                )
            )

        return issues
