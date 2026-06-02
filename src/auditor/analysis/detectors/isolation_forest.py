"""Unsupervised anomaly detector built on scikit-learn's Isolation Forest.

The three rule-based detectors each encode a specific, well-understood failure
mode as an explicit threshold.  This detector complements them by finding alerts
that are *statistically unusual relative to their peers* without any predefined
rule for what "unusual" means.  It reduces each alert to a seven-feature vector
(see ``auditor.analysis.features``), then trains an Isolation Forest to isolate
the vectors that sit far from the bulk of the distribution.

Isolation Forest was chosen because it is unsupervised (no labelled training
data is required — a hard constraint, since no team has a labelled corpus of
"bad alerts"), it scales well to the tabular, low-dimensional feature space used
here, and its per-feature splits keep the result interpretable: the evidence on
each finding carries the raw feature values that made the alert stand out.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sqlalchemy import select
from sqlalchemy.orm import Session

from auditor.analysis.features import FEATURE_NAMES, AlertFeatureExtractor
from auditor.analysis.schemas import AlertHygieneIssue, IssueType, Severity
from auditor.db.models import AlertFiring

logger = logging.getLogger(__name__)


class InsufficientDataError(Exception):
    """Raised when there is too little firing history to train a useful model.

    This is a domain exception, not a programming error: it signals that the
    analysis ran correctly but declined to produce ML findings because doing so
    would be statistically irresponsible.  The AnalysisEngine catches it and
    logs a warning rather than failing the entire report.
    """


class IsolationForestDetector:
    """Flags alerts whose firing-pattern feature vectors are statistical outliers.

    Parameters
    ----------
    contamination:
        The expected proportion of anomalies in the data (default 0.1, i.e. 10%).
        This is the single most important knob.  Isolation Forest uses it to set
        the score cutoff between inliers and outliers, so it directly determines
        how many alerts are flagged.  Set it too high and normal alerts get
        flagged as anomalous (false positives that erode trust in the tool); set
        it too low and genuine anomalies slip through unflagged (false negatives).
        The default of 0.1 reflects a prior belief that roughly one alert in ten
        in a poorly-maintained system is behaving pathologically.
    n_estimators:
        Number of trees in the forest (default 100).  More trees yield a more
        stable anomaly score at the cost of compute; 100 is the scikit-learn
        default and is ample for the small feature space used here.
    random_state:
        Seed for the forest's randomness (default 42).  Fixing it makes runs
        reproducible — the same data always produces the same findings, which is
        essential for a tool whose output engineers are expected to act on.
    min_records_required:
        Minimum total firing rows in the window before the model will run
        (default 50).  Below this the detector raises InsufficientDataError.
    model_path:
        Filesystem path where the trained model and scaler are persisted via
        joblib (default ``models/isolation_forest.joblib``).
    """

    def __init__(
        self,
        contamination: float = 0.1,
        n_estimators: int = 100,
        random_state: int = 42,
        min_records_required: int = 50,
        model_path: str = "models/isolation_forest.joblib",
    ) -> None:
        self._contamination = contamination
        self._n_estimators = n_estimators
        self._random_state = random_state
        self._min_records_required = min_records_required
        self._model_path = Path(model_path)

    def detect(self, session: Session, since: datetime) -> list[AlertHygieneIssue]:
        """Return one AlertHygieneIssue per alert flagged as anomalous.

        Args:
            session: An active SQLAlchemy session.
            since:   The start of the lookback window (UTC).

        Raises:
            InsufficientDataError: if fewer than ``min_records_required`` firing
                rows exist in the window.
        """
        now = datetime.now(tz=timezone.utc)

        # --- Step 1: data sufficiency check --------------------------------
        #
        # Fetch every firing in the window and group it by alert name.  The gate
        # exists because an Isolation Forest trained on a handful of points tends
        # to overfit to whatever it sees: with too few samples, the notion of
        # "the bulk of the distribution" is meaningless and the model will
        # confidently flag points that are not actually anomalous.  In a
        # portfolio setting where the data is synthetic and sparse, omitting this
        # check would produce findings that are numerically valid but
        # operationally meaningless — worse than producing nothing.
        rows = (
            session.execute(select(AlertFiring).where(AlertFiring.starts_at >= since))
            .scalars()
            .all()
        )

        if len(rows) < self._min_records_required:
            raise InsufficientDataError(
                f"Isolation Forest requires at least {self._min_records_required} "
                f"firing records in the lookback window to produce meaningful "
                f"results, but found only {len(rows)}. The model cannot reliably "
                f"distinguish anomalous from normal patterns with this little "
                f"history; collect more data or use the rule-based detectors."
            )

        firings_by_alert: dict[str, list[AlertFiring]] = {}
        for row in rows:
            firings_by_alert.setdefault(row.alert_name, []).append(row)

        # --- Step 2: feature extraction ------------------------------------
        lookback_days = max(1, (now - since).days)
        extractor = AlertFeatureExtractor(lookback_days=lookback_days, window_end=now)

        alert_names: list[str] = []
        feature_rows: list[dict[str, float]] = []
        for alert_name, firings in firings_by_alert.items():
            alert_names.append(alert_name)
            feature_rows.append(extractor.extract(firings))

        # One row per alert, columns in the canonical FEATURE_NAMES order.
        features_df = pd.DataFrame(feature_rows, columns=FEATURE_NAMES)

        # --- Step 3: preprocessing -----------------------------------------
        #
        # Isolation Forest does not strictly require feature scaling, because its
        # splits are made on individual features independently.  Scaling is
        # applied anyway so that a feature with a large numeric range (such as
        # firing_rate_per_day, which can reach the hundreds) does not dominate
        # the random split-point selection at the expense of a feature with a
        # small range (such as resolution_ratio, bounded to [0, 1]).  After
        # StandardScaler every feature has zero mean and unit variance, so each
        # contributes comparably to how quickly a point can be isolated.
        scaler = StandardScaler()
        x_scaled = scaler.fit_transform(features_df.to_numpy())

        # --- Step 4: model training and scoring ----------------------------
        model = IsolationForest(
            contamination=self._contamination,
            n_estimators=self._n_estimators,
            random_state=self._random_state,
        )
        model.fit(x_scaled)

        # decision_function returns HIGHER values for inliers and LOWER (more
        # negative) values for outliers — the opposite of what "anomaly score"
        # intuitively suggests.  This sign convention is a common source of
        # confusion: here a more negative score means a stronger anomaly.
        scores = model.decision_function(x_scaled)
        # predict returns -1 for anomalies and +1 for inliers.
        predictions = model.predict(x_scaled)

        # --- Step 5: finding construction ----------------------------------
        #
        # Severity is assigned by where each anomaly's score falls in the
        # distribution of all scores: the most negative quartile (strongest
        # anomalies) is HIGH, the least negative quartile is LOW, the middle
        # half is MEDIUM.  Percentiles are computed across every alert's score,
        # not just the flagged ones, so severity reflects the full population.
        q25, q75 = np.percentile(scores, [25, 75])

        issues: list[AlertHygieneIssue] = []
        for i, alert_name in enumerate(alert_names):
            if predictions[i] != -1:
                continue

            score = float(scores[i])
            # Surfacing the raw feature values in evidence is what makes the
            # finding actionable: an SRE can see that firing_hour_entropy is 0.3
            # and resolution_ratio is 0.04 and immediately form a hypothesis
            # ("a nightly cron is tripping an unactionable alert"), rather than
            # being told only that the alert "looks anomalous".
            evidence: dict = {
                name: round(float(features_df.iloc[i][name]), 4)
                for name in FEATURE_NAMES
            }
            evidence["anomaly_score"] = round(score, 4)
            evidence["contamination"] = self._contamination
            evidence["window_start"] = since.isoformat()
            evidence["window_end"] = now.isoformat()

            issues.append(
                AlertHygieneIssue(
                    alert_name=alert_name,
                    issue_type=IssueType.ANOMALOUS_PATTERN,
                    severity=_severity(score, q25, q75),
                    evidence=evidence,
                    detected_at=now,
                )
            )

        # --- Step 6: model persistence -------------------------------------
        #
        # Persisting the fitted model and scaler together serves two purposes in
        # a portfolio context: it enables reproducible scoring runs without
        # retraining (load the artefact and call decision_function on new data),
        # and it demonstrates awareness of the model lifecycle — training and
        # serving are distinct phases, and the scaler must travel with the model
        # because new data has to be transformed with the same fitted statistics.
        self._model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": model, "scaler": scaler}, self._model_path)
        logger.info(
            "Isolation Forest scored %d alerts, flagged %d, model saved to %s",
            len(alert_names),
            len(issues),
            self._model_path,
        )

        return issues


def _severity(score: float, q25: float, q75: float) -> Severity:
    """Map an anomaly score to a severity using score-distribution quartiles.

    More negative scores are stronger anomalies, so the bottom 25% of scores
    (``score <= q25``) are HIGH, the top 25% (``score >= q75``) are LOW, and the
    middle 50% are MEDIUM.
    """
    if score <= q25:
        return Severity.HIGH
    if score >= q75:
        return Severity.LOW
    return Severity.MEDIUM
