"""Detector for co-firing alert clusters.

Two alerts "co-fire" when they consistently appear in the same narrow time
window across multiple independent incidents.  Co-firing clusters are a signal
that several alert rules share a common upstream cause and could be replaced by
a single, higher-fidelity rule that fires closer to the root cause.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from itertools import combinations

from sqlalchemy import select
from sqlalchemy.orm import Session

from auditor.analysis.schemas import AlertHygieneIssue, IssueType, Severity
from auditor.db.models import AlertFiring


def _bucket_key(dt: datetime, window_minutes: int) -> int:
    """Return the integer bucket index for a datetime.

    Divides Unix time into contiguous ``window_minutes``-wide slots.  Two
    events that fall in the same slot share the same bucket key and are
    considered co-temporal for the purposes of this detector.
    """
    bucket_seconds = window_minutes * 60
    return int(dt.timestamp()) // bucket_seconds


def _severity(co_ratio: float) -> Severity:
    """Severity scales with how reliably the two alerts fire together."""
    if co_ratio >= 0.90:
        return Severity.HIGH
    if co_ratio >= 0.80:
        return Severity.MEDIUM
    return Severity.LOW


class CoFiringDetector:
    """Identifies pairs of alerts that consistently fire in the same time window.

    **Algorithm overview**

    1. Fetch every ``AlertFiring`` row in the lookback window.
    2. Group rows into ``window_minutes``-wide time buckets (default: 5 min).
       Each bucket records which distinct alert names fired during that slot.
    3. For every pair of alerts that appear in the same bucket, increment a
       shared co-occurrence counter.
    4. Compute the co-occurrence ratio for each pair as:
       ``co_count / min(buckets_with_A, buckets_with_B)``.
       Using the minimum means we ask: "of all the windows where the *less
       frequent* alert fired, what fraction also contained its partner?"  This
       is the most conservative interpretation and avoids inflating the ratio
       when one alert fires far more often than the other.
    5. Flag pairs whose ratio exceeds ``co_fire_threshold`` (default: 0.70).

    **What this detector can conclude**

    A high co-occurrence ratio means that whenever alert A fires, alert B tends
    to fire too, and vice versa.  This is strong evidence that both alerts
    respond to the same upstream event and that the underlying cause, once
    fixed, would silence both simultaneously.  Consolidating the two rules into
    one that fires closer to the root cause reduces alert fatigue without losing
    signal.

    **What this detector cannot conclude**

    Temporal correlation is *not* causation.  A pair may co-fire because they
    share a root cause, but they may also co-fire because two independent
    failure modes happen to affect the same machine during the same incident
    window.  The detector flags candidates for human review — a platform
    engineer must examine the PromQL expressions and alert history to determine
    whether consolidation is appropriate.  The ``evidence`` dict provides the
    raw co-occurrence counts to support that review.
    """

    def __init__(
        self,
        window_minutes: int = 5,
        co_fire_threshold: float = 0.70,
    ) -> None:
        self._window_minutes = window_minutes
        self._co_fire_threshold = co_fire_threshold

    def detect(self, session: Session, since: datetime) -> list[AlertHygieneIssue]:
        """Return one AlertHygieneIssue per co-firing pair above the threshold.

        The ``alert_name`` field of each issue uses the format
        ``"AlertA ↔ AlertB"`` (alphabetically ordered) so that a pair is
        represented by a single canonical name regardless of which alert is
        considered primary.

        Args:
            session: An active SQLAlchemy session.
            since:   The start of the lookback window (UTC).
        """
        now = datetime.now(tz=timezone.utc)

        # Fetch the minimal columns needed: alert name and start timestamp.
        # Fetching full rows (including JSON labels) would transfer unnecessary
        # data for what is fundamentally a grouping operation.
        stmt = select(AlertFiring.alert_name, AlertFiring.starts_at).where(
            AlertFiring.starts_at >= since
        )
        rows = session.execute(stmt).all()

        if not rows:
            return []

        # --- Step 1: group alert names into time buckets -------------------
        #
        # buckets maps each integer bucket key to the SET of alert names that
        # fired at least once during that bucket's time slot.  Using a set
        # ensures that a single alert firing twice in one 5-minute window is
        # counted only once per bucket, which is the correct unit for
        # measuring "how often do these two alerts appear together?"
        buckets: dict[int, set[str]] = defaultdict(set)
        for row in rows:
            key = _bucket_key(row.starts_at, self._window_minutes)
            buckets[key].add(row.alert_name)

        # --- Step 2: count how many buckets each individual alert appears in
        #
        # This is the denominator in the co-occurrence ratio calculation.
        alert_bucket_counts: Counter[str] = Counter()
        for names_in_bucket in buckets.values():
            for name in names_in_bucket:
                alert_bucket_counts[name] += 1

        # --- Step 3: count co-occurrences per ordered pair -----------------
        #
        # Only process buckets that contain two or more distinct alert names;
        # single-alert buckets cannot produce a co-occurrence.
        pair_counts: Counter[tuple[str, str]] = Counter()
        for names_in_bucket in buckets.values():
            if len(names_in_bucket) < 2:
                continue
            # Sort names so that the pair (A, B) and (B, A) map to the same
            # canonical key and are never double-counted.
            for a, b in combinations(sorted(names_in_bucket), 2):
                pair_counts[(a, b)] += 1

        # --- Step 4: compute ratios and flag pairs above the threshold ------
        issues: list[AlertHygieneIssue] = []

        for (a, b), co_count in pair_counts.items():
            count_a = alert_bucket_counts[a]
            count_b = alert_bucket_counts[b]

            # Use the minimum individual count as the denominator so the ratio
            # reflects how reliably the pair fires together relative to the
            # alert that fires less often.  If A fires in 100 buckets and B in
            # 10 buckets, and they co-fire in 9 buckets, the ratio is 9/10 =
            # 0.90, not 9/100 = 0.09 — the more meaningful signal.
            co_ratio = co_count / min(count_a, count_b)

            if co_ratio < self._co_fire_threshold:
                continue

            issues.append(
                AlertHygieneIssue(
                    # Canonical pair name — alphabetically ordered, separated by
                    # the bidirectional arrow to signal symmetry.
                    alert_name=f"{a} ↔ {b}",
                    issue_type=IssueType.CO_FIRING_CLUSTER,
                    severity=_severity(co_ratio),
                    evidence={
                        "alert_a": a,
                        "alert_b": b,
                        "co_occurrence_count": co_count,
                        "alert_a_bucket_count": count_a,
                        "alert_b_bucket_count": count_b,
                        "co_occurrence_ratio": round(co_ratio, 4),
                        "window_minutes": self._window_minutes,
                        "co_fire_threshold": self._co_fire_threshold,
                        "window_start": since.isoformat(),
                        "window_end": now.isoformat(),
                    },
                    detected_at=now,
                )
            )

        return issues
