"""Tests for AlertFeatureExtractor.

The feature extractor reduces an alert's firing history to a seven-number
vector.  These tests pin down the two features whose math is most easily gotten
wrong — entropy and resolution ratio — at their boundary values, and confirm
the output shape is exactly the seven-key contract the model depends on.

Test cases
----------
- Entropy is 0.0 when every firing occurs in the same hour: the degenerate case
  of a perfectly concentrated distribution, which must yield zero information.
- Resolution ratio is 0.0 when no firing has an ends_at value: the boundary
  that distinguishes a never-resolved (unactionable) alert from a healthy one.
- Exactly seven keys: the structural contract the DataFrame and model rely on.
"""

from datetime import datetime, timedelta, timezone

from auditor.analysis.features import FEATURE_NAMES, AlertFeatureExtractor
from auditor.db.models import AlertFiring

# Window end fixed so days_since_last_firing and the per-day trend are
# deterministic regardless of when the test runs.
WINDOW_END = datetime(2024, 2, 1, tzinfo=timezone.utc)
BASE_TIME = datetime(2024, 1, 15, 3, 0, 0, tzinfo=timezone.utc)


def _firing(offset_hours: int = 0, ends_at: datetime | None = None) -> AlertFiring:
    """Build one AlertFiring offset from BASE_TIME (which is at hour 03:00)."""
    return AlertFiring(
        alert_name="TestAlert",
        labels={},
        annotations={},
        starts_at=BASE_TIME + timedelta(hours=offset_hours),
        ends_at=ends_at,
        state="firing",
        source="prometheus",
    )


def test_entropy_is_zero_when_all_firings_in_same_hour() -> None:
    """Firings all landing in the same hour-of-day must give entropy 0.0.

    Offsets are multiples of 24 hours, so every firing lands on a different day
    but always at 03:00 — a perfectly concentrated hour distribution, which by
    definition carries zero Shannon entropy.
    """
    firings = [_firing(offset_hours=24 * i) for i in range(5)]

    features = AlertFeatureExtractor(lookback_days=30, window_end=WINDOW_END).extract(
        firings
    )

    assert features["firing_hour_entropy"] == 0.0


def test_resolution_ratio_is_zero_when_no_firing_resolved() -> None:
    """An alert whose firings all have ends_at=None must have resolution ratio 0.0."""
    firings = [_firing(offset_hours=i, ends_at=None) for i in range(6)]

    features = AlertFeatureExtractor(lookback_days=30, window_end=WINDOW_END).extract(
        firings
    )

    assert features["resolution_ratio"] == 0.0


def test_extract_returns_exactly_seven_keys() -> None:
    """The feature dict must contain exactly the seven canonical feature keys."""
    firings = [_firing(offset_hours=i) for i in range(3)]

    features = AlertFeatureExtractor(lookback_days=30, window_end=WINDOW_END).extract(
        firings
    )

    assert set(features.keys()) == set(FEATURE_NAMES)
    assert len(features) == 7
