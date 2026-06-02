"""Feature engineering for the Isolation Forest anomaly detector.

The rule-based detectors each query the database directly and reason about one
specific failure mode.  The anomaly detector takes a different approach: it
reduces each alert's entire firing history to a small fixed-length vector of
numeric features and lets an unsupervised model decide which vectors are
unusual relative to the rest.  The quality of that model is bounded entirely by
the quality of these features — a feature that does not capture a meaningful
dimension of "alert behaviour" cannot help the model separate healthy alerts
from pathological ones.

Seven features were chosen, each sensitive to a different hygiene failure mode:

* ``firing_rate_per_day`` — raw volume.  Most sensitive to chronic noise: an
  alert firing hundreds of times a day is behaving differently from one firing
  twice a week.
* ``resolution_ratio`` — actionability.  Most sensitive to "always true" rules
  and to alerts the team has stopped resolving; a ratio near zero is the single
  strongest signal of an unactionable alert.
* ``mean_duration_minutes`` — how long firings persist.  Sensitive to alerts
  that flap (very short durations) versus alerts stuck firing for hours.
* ``firing_hour_entropy`` — temporal shape.  Most sensitive to cron-driven or
  scheduled misfires, which cluster at specific hours rather than following
  organic system load.
* ``inter_firing_interval_cv`` — regularity.  Most sensitive to machine-like
  periodic firing, which is characteristic of a rule evaluating a condition
  that is permanently or rhythmically true rather than responding to incidents.
* ``weekly_firing_trend`` — direction.  Most sensitive to threshold drift: a
  positive slope means the alert is firing more over time, indicating the
  system has moved away from the threshold's original baseline.
* ``days_since_last_firing`` — recency.  Sensitive to stale or retired alerts
  that fired historically but have gone quiet, which often indicates a rule
  that is no longer relevant and should be cleaned up.

The features are intentionally interpretable in isolation.  When the model
flags an alert, the raw feature values are surfaced in the finding's evidence
so an engineer can read them directly and form a hypothesis, rather than being
told only that the alert "looks anomalous".
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import numpy as np

from auditor.db.models import AlertFiring

# Canonical, ordered list of the feature names.  The detector uses this to build
# DataFrame columns in a stable order, and the tests assert that exactly these
# seven keys are present.  Defining it once here is the single source of truth.
FEATURE_NAMES: list[str] = [
    "firing_rate_per_day",
    "resolution_ratio",
    "mean_duration_minutes",
    "firing_hour_entropy",
    "inter_firing_interval_cv",
    "weekly_firing_trend",
    "days_since_last_firing",
]


def _as_utc(dt: datetime) -> datetime:
    """Return a timezone-aware UTC datetime.

    SQLite (used in the test suite) stores ``DateTime(timezone=True)`` columns
    as naive ISO strings and returns naive datetimes on read.  Mixing those
    with the timezone-aware window boundaries would raise "can't subtract
    offset-naive and offset-aware datetimes".  Coercing every datetime through
    this helper keeps all arithmetic between aware datetimes.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class AlertFeatureExtractor:
    """Computes the seven-feature vector for a single alert's firing history.

    The extractor is constructed once per analysis run with the window it should
    reason about (``lookback_days`` and ``window_end``), then ``extract`` is
    called once per alert.  Holding the window on the instance keeps the
    per-alert call site clean and guarantees every alert is measured against the
    same window — a prerequisite for the feature vectors to be comparable when
    the model scores them against each other.
    """

    def __init__(
        self,
        lookback_days: int,
        window_end: datetime | None = None,
    ) -> None:
        self._lookback_days = max(1, lookback_days)
        self._window_end = _as_utc(window_end or datetime.now(tz=timezone.utc))
        self._window_start = self._window_end - timedelta(days=self._lookback_days)

    def extract(self, firings: list[AlertFiring]) -> dict[str, float]:
        """Return the seven computed features for one alert's firings.

        Args:
            firings: All AlertFiring rows for a single named alert within the
                lookback window.  May be empty, in which case every feature is
                returned as 0.0 so the model still receives a well-formed row.
        """
        if not firings:
            return {name: 0.0 for name in FEATURE_NAMES}

        starts = sorted(_as_utc(f.starts_at) for f in firings)
        total = len(firings)

        return {
            "firing_rate_per_day": self._firing_rate_per_day(total),
            "resolution_ratio": self._resolution_ratio(firings),
            "mean_duration_minutes": self._mean_duration_minutes(firings),
            "firing_hour_entropy": self._firing_hour_entropy(starts),
            "inter_firing_interval_cv": self._inter_firing_interval_cv(starts),
            "weekly_firing_trend": self._weekly_firing_trend(starts),
            "days_since_last_firing": self._days_since_last_firing(starts),
        }

    # ------------------------------------------------------------------
    # Individual feature calculations
    # ------------------------------------------------------------------

    def _firing_rate_per_day(self, total: int) -> float:
        """Total firings divided by the number of days in the lookback window."""
        return total / self._lookback_days

    def _resolution_ratio(self, firings: list[AlertFiring]) -> float:
        """Proportion of firings that reached a resolved state (non-null ends_at)."""
        resolved = sum(1 for f in firings if f.ends_at is not None)
        return resolved / len(firings)

    def _mean_duration_minutes(self, firings: list[AlertFiring]) -> float:
        """Mean firing duration in minutes, computed over resolved firings only.

        Unresolved firings (``ends_at is None``) have no measurable duration, so
        they are excluded from the mean rather than being treated as duration 0
        or as still-open until "now" — either of those choices would bias the
        feature.  If no firing has resolved, the mean is undefined and 0.0 is
        returned.
        """
        durations = [
            (_as_utc(f.ends_at) - _as_utc(f.starts_at)).total_seconds() / 60.0
            for f in firings
            if f.ends_at is not None
        ]
        if not durations:
            return 0.0
        return float(np.mean(durations))

    def _firing_hour_entropy(self, starts: list[datetime]) -> float:
        """Shannon entropy of the distribution of firings across hours 0–23.

        Low entropy means firings cluster at one or a few specific hours of the
        day; high entropy means they are spread evenly across the clock.  A low
        entropy value often indicates a cron-driven or scheduled process (e.g. a
        backup job that trips an alert every night at 02:00) rather than a
        genuine system condition, which would arrive at organically varied times.

        The math, in plain language: bucket the firings by hour-of-day, convert
        the counts to probabilities (each bucket's share of the total), then sum
        ``-p * log2(p)`` over the non-empty buckets.  Entropy is 0 when every
        firing lands in the same hour (one bucket has probability 1, and
        ``1 * log2(1) == 0``) and reaches its maximum of log2(24) ≈ 4.58 when
        firings are spread uniformly across all 24 hours.
        """
        counts = np.zeros(24, dtype=float)
        for dt in starts:
            counts[dt.hour] += 1.0

        total = counts.sum()
        if total == 0:
            return 0.0

        probabilities = counts / total
        # Keep only non-zero probabilities: 0 * log2(0) is defined as 0 in
        # information theory but would be NaN if computed directly.
        nonzero = probabilities[probabilities > 0]
        return float(-np.sum(nonzero * np.log2(nonzero)))

    def _inter_firing_interval_cv(self, starts: list[datetime]) -> float:
        """Coefficient of variation of the gaps between consecutive firings.

        The coefficient of variation (CV) is the standard deviation divided by
        the mean.  Computed over the time gaps between successive firings, a high
        CV means the alert fires at irregular, bursty intervals (the hallmark of
        a real, incident-driven alert), while a very low CV means it fires like
        clockwork at near-constant intervals.  A very low CV combined with a high
        firing rate is characteristic of a rule that is essentially always true
        and is being re-evaluated on a fixed schedule — a classic noise pattern.

        Requires at least two firings to have an interval; returns 0.0 otherwise,
        and also returns 0.0 when the mean interval is 0 (avoids divide-by-zero).
        """
        if len(starts) < 2:
            return 0.0

        intervals = np.diff([dt.timestamp() for dt in starts])
        mean = float(np.mean(intervals))
        if mean == 0:
            return 0.0
        return float(np.std(intervals) / mean)

    def _weekly_firing_trend(self, starts: list[datetime]) -> float:
        """Slope of a linear regression fit to per-day firing counts.

        Each day in the lookback window is one data point: x is the day index
        (0 at the window start) and y is the number of firings on that day.  The
        slope of the least-squares line through those points captures direction:
        a positive slope means the alert is firing more frequently as time goes
        on, the signature of threshold drift.  A flat or negative slope means it
        is stable or quieting down.
        """
        if self._lookback_days < 2:
            return 0.0

        per_day = np.zeros(self._lookback_days, dtype=float)
        for dt in starts:
            day_index = (dt.date() - self._window_start.date()).days
            if 0 <= day_index < self._lookback_days:
                per_day[day_index] += 1.0

        x = np.arange(self._lookback_days, dtype=float)
        # polyfit degree 1 returns [slope, intercept]; take the slope.
        slope = np.polyfit(x, per_day, 1)[0]
        return float(slope)

    def _days_since_last_firing(self, starts: list[datetime]) -> float:
        """Days between the most recent firing and the end of the lookback window."""
        last = starts[-1]
        return (self._window_end - last).total_seconds() / 86400.0
