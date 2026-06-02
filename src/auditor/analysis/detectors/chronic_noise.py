"""Detector for chronically noisy alert rules.

A chronically noisy alert is one that fires repeatedly within a time window
but is almost never resolved or acted on by a human.  High firing frequency
combined with a low resolved-state ratio is strong evidence that the alert is
monitoring a condition that the team has accepted as permanently true, or that
the rule's threshold is so sensitive it fires on normal operating variance.
Either way, the alert is consuming on-call attention without providing signal.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from auditor.analysis.schemas import AlertHygieneIssue, IssueType, Severity
from auditor.db.models import AlertFiring


def _severity(total_firings: int, resolved_ratio: float, threshold: int) -> Severity:
    """Assign severity based on how far the alert exceeds the noise thresholds.

    Both axes matter: an alert that fires 100 times is worse than one that
    fires 21 times, and an alert that is never resolved is worse than one
    that resolves occasionally.  HIGH requires either very high frequency or
    near-zero resolved ratio; MEDIUM is the middle band.
    """
    if total_firings >= threshold * 3 or resolved_ratio < 0.05:
        return Severity.HIGH
    if total_firings >= threshold * 2 or resolved_ratio < 0.15:
        return Severity.MEDIUM
    return Severity.LOW


class ChronicNoiseDetector:
    """Identifies alerts that fire constantly without being acted on.

    An alert that fires more than ``firing_threshold`` times in the lookback
    window AND whose firings are resolved in fewer than
    ``resolved_ratio_threshold`` of cases is classified as chronic noise.

    The reasoning behind this definition:

    Frequency alone is not sufficient — some high-value alerts fire often and
    are resolved quickly (e.g. a deployment alert in a busy CI environment).
    The resolved ratio captures whether the alert is *actionable*: if an alert
    fires 40 times and is never seen in the "resolved" state, it is either a
    metric that only ever increases, a threshold set so low that it fires before
    any human can respond, or a rule that was written once and forgotten.  All
    three are misconfiguration, not traffic.

    The "resolved" state in this context means the alert transitioned from
    ``firing`` to ``resolved`` in the source data.  Alerts that are silenced
    or inhibited by Alertmanager (and thus never reach a receiver) are treated
    the same as unresolved — they represent suppressed noise, not remediated
    noise.
    """

    def __init__(
        self,
        firing_threshold: int = 20,
        resolved_ratio_threshold: float = 0.30,
    ) -> None:
        self._firing_threshold = firing_threshold
        self._resolved_ratio_threshold = resolved_ratio_threshold

    def detect(self, session: Session, since: datetime) -> list[AlertHygieneIssue]:
        """Return one AlertHygieneIssue per alert that meets the noise criteria.

        Args:
            session: An active SQLAlchemy session.
            since:   The start of the lookback window (UTC).
        """
        now = datetime.now(tz=timezone.utc)

        # --- Build the aggregation query -----------------------------------
        #
        # SELECT alert_name,
        #        COUNT(*)                                     AS total_firings,
        #        SUM(CASE WHEN state = 'resolved' THEN 1
        #                 ELSE 0 END)                        AS resolved_count
        # FROM   alert_firings
        # WHERE  starts_at >= :since          -- constrain to the lookback window
        # GROUP  BY alert_name
        # HAVING COUNT(*) > :firing_threshold -- pre-filter in SQL to avoid
        #                                     -- pulling every alert into Python
        stmt = (
            select(
                AlertFiring.alert_name,
                # Total number of firing events for this alert in the window.
                func.count().label("total_firings"),
                # Count only rows where the alert was observed in the resolved
                # state.  Prometheus records a "resolved" state transition when
                # the PromQL expression evaluates to empty for a full evaluation
                # cycle; Alertmanager records it when endsAt is in the past.
                func.sum(case((AlertFiring.state == "resolved", 1), else_=0)).label(
                    "resolved_count"
                ),
            )
            .where(
                # Restrict to the configured lookback window only.  Without this
                # filter the query would scan the full table and weight old alerts
                # equally with recent ones, producing stale findings.
                AlertFiring.starts_at
                >= since
            )
            .group_by(AlertFiring.alert_name)
            .having(
                # Apply the frequency threshold in SQL so that only candidate
                # alerts are transferred to Python.  Alerts below the threshold
                # cannot satisfy the full criteria and are cheaply excluded here.
                func.count()
                > self._firing_threshold
            )
        )

        rows = session.execute(stmt).all()

        issues: list[AlertHygieneIssue] = []

        for row in rows:
            total = row.total_firings
            resolved = int(row.resolved_count or 0)
            # Compute the resolved ratio in Python rather than in SQL to avoid
            # division-by-zero edge cases and to keep the HAVING clause simple.
            resolved_ratio = resolved / total if total > 0 else 0.0

            # Apply the second threshold: drop alerts that resolve frequently
            # even though they fire often — those are high-traffic but healthy.
            if resolved_ratio >= self._resolved_ratio_threshold:
                continue

            issues.append(
                AlertHygieneIssue(
                    alert_name=row.alert_name,
                    issue_type=IssueType.CHRONIC_NOISE,
                    severity=_severity(total, resolved_ratio, self._firing_threshold),
                    evidence={
                        "total_firings": total,
                        "resolved_count": resolved,
                        "resolved_ratio": round(resolved_ratio, 4),
                        "firing_threshold": self._firing_threshold,
                        "resolved_ratio_threshold": self._resolved_ratio_threshold,
                        "window_start": since.isoformat(),
                        "window_end": now.isoformat(),
                    },
                    detected_at=now,
                )
            )

        return issues
