"""Proxy evaluation metrics for the unsupervised Isolation Forest detector.

A supervised model is evaluated against ground-truth labels — precision, recall,
F1.  This model has no labels: there is no corpus of alerts annotated as
"genuinely anomalous", and manufacturing one would defeat the point of using an
unsupervised method.  Evaluation therefore relies on *proxy* metrics that
establish whether the model is behaving sensibly and finding structure, rather
than proving it is correct.  These metrics build confidence; they do not
substitute for human review of the individual findings.

Three proxies are provided:

* ``contamination_sensitivity`` — does the flagged-count respond smoothly to the
  contamination parameter?  A well-behaved model should flag proportionally more
  alerts as contamination rises, not jump discontinuously.
* ``feature_importance_by_depth`` — which features is the forest isolating on
  earliest?  Features used near the root are more discriminative.
* ``score_distribution_summary`` — is the score distribution well-separated, with
  a dense cluster of inliers and a thin negative tail of outliers?
"""

from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest

# The contamination levels swept by contamination_sensitivity.  Kept as a module
# constant so the dashboard and README can reference the exact same sequence.
CONTAMINATION_LEVELS: list[float] = [0.05, 0.10, 0.15, 0.20, 0.25]


class ModelEvaluator:
    """Computes proxy quality metrics for an Isolation Forest over a feature set.

    Constructed with the scaled feature matrix and the feature names; it fits its
    own Isolation Forest instances internally so evaluation is self-contained and
    does not depend on the detector having run.
    """

    def __init__(
        self,
        x_scaled: np.ndarray,
        feature_names: list[str],
        n_estimators: int = 100,
        random_state: int = 42,
        contamination: float = 0.1,
    ) -> None:
        self._x = x_scaled
        self._feature_names = feature_names
        self._n_estimators = n_estimators
        self._random_state = random_state
        self._contamination = contamination

    def _fit(self, contamination: float) -> IsolationForest:
        """Fit and return an Isolation Forest at the given contamination level."""
        model = IsolationForest(
            contamination=contamination,
            n_estimators=self._n_estimators,
            random_state=self._random_state,
        )
        model.fit(self._x)
        return model

    def contamination_sensitivity(self) -> dict[float, int]:
        """Return the number of alerts flagged at each contamination level.

        In the absence of labelled data, sweeping contamination and watching how
        many alerts get flagged is a sanity check on model stability.  A
        well-behaved model flags monotonically more alerts as contamination
        increases, and does so smoothly; a large discontinuous jump between
        adjacent levels would suggest the score distribution has a cliff rather
        than a tail, which is a sign the features are not separating cleanly.
        """
        result: dict[float, int] = {}
        for level in CONTAMINATION_LEVELS:
            model = self._fit(level)
            predictions = model.predict(self._x)
            result[level] = int(np.sum(predictions == -1))
        return result

    def feature_importance_by_depth(self) -> dict[str, float]:
        """Return each feature's mean isolation depth, sorted ascending.

        Isolation Forest isolates a point by repeatedly splitting the data on a
        randomly chosen feature; anomalies require fewer splits to isolate, which
        is why they get more negative scores.  Averaging the *depth* at which
        each feature is used to split — across every node of every tree —
        approximates how discriminative that feature is: a feature that the trees
        repeatedly choose near the root (shallow mean depth) is doing more of the
        early separating work, so it is more important.  The dict is sorted
        ascending, so the most important feature appears first.
        """
        depth_sums: dict[str, float] = {name: 0.0 for name in self._feature_names}
        depth_counts: dict[str, int] = {name: 0 for name in self._feature_names}

        model = self._fit(self._contamination)
        for estimator in model.estimators_:
            tree = estimator.tree_
            node_depths = _compute_node_depths(tree.children_left, tree.children_right)
            for node in range(tree.node_count):
                feature_index = tree.feature[node]
                # feature_index < 0 marks a leaf node (no split feature).
                if feature_index < 0:
                    continue
                name = self._feature_names[feature_index]
                depth_sums[name] += node_depths[node]
                depth_counts[name] += 1

        mean_depths: dict[str, float] = {}
        for name in self._feature_names:
            if depth_counts[name] > 0:
                mean_depths[name] = round(depth_sums[name] / depth_counts[name], 3)
            else:
                # A feature never used for any split gets infinity so it sorts
                # last — it contributed nothing to isolation.
                mean_depths[name] = float("inf")

        return dict(sorted(mean_depths.items(), key=lambda kv: kv[1]))

    def score_distribution_summary(self) -> dict[str, float]:
        """Return descriptive statistics of the anomaly scores across all alerts.

        A well-separated distribution — most alerts clustered near zero with a
        few genuinely anomalous alerts sitting far out in the negative tail — is
        a qualitative indicator that the model is finding signal rather than
        noise.  A distribution with no negative tail (everything bunched
        together) suggests the features do not distinguish the alerts; a
        distribution that is uniformly spread suggests the model is flagging
        arbitrarily.  This method reports the shape so a reviewer can judge.
        """
        model = self._fit(self._contamination)
        scores = model.decision_function(self._x)
        return {
            "mean": round(float(np.mean(scores)), 4),
            "std": round(float(np.std(scores)), 4),
            "min": round(float(np.min(scores)), 4),
            "p25": round(float(np.percentile(scores, 25)), 4),
            "p50": round(float(np.percentile(scores, 50)), 4),
            "p75": round(float(np.percentile(scores, 75)), 4),
            "max": round(float(np.max(scores)), 4),
        }


def _compute_node_depths(
    children_left: np.ndarray, children_right: np.ndarray
) -> dict[int, int]:
    """Return a mapping of node index to its depth within a decision tree.

    The root (node 0) has depth 0; each child is one level deeper than its
    parent.  Uses an explicit stack rather than recursion to stay safe on deep
    trees.
    """
    depths: dict[int, int] = {}
    stack: list[tuple[int, int]] = [(0, 0)]
    while stack:
        node, depth = stack.pop()
        depths[node] = depth
        left, right = children_left[node], children_right[node]
        # A value of -1 in the children arrays marks the absence of a child.
        if left != -1:
            stack.append((left, depth + 1))
        if right != -1:
            stack.append((right, depth + 1))
    return depths
