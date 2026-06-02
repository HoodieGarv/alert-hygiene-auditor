"""Recommendation generator — translates analysis findings into human-readable actions.

Each AlertHygieneIssue produced by the analysis engine carries raw numerical
evidence (firing counts, ratios, slice histories).  This module wraps that
evidence in language calibrated for an on-call engineer: a one-sentence
problem summary, a brief root cause explanation, a single concrete directive,
and an ordered remediation checklist.

Template strings are defined as module-level constants so they can be reviewed
and edited independently of the generator logic.  Each constant is annotated
with comments that explain the reasoning behind the specific wording choices —
not just what the template says, but why it says it that way.
"""

from __future__ import annotations

from auditor.analysis.schemas import (
    AlertHygieneIssue,
    AnalysisReport,
    IssueType,
    Severity,
)
from auditor.recommendations.schemas import Priority, Recommendation

# ===========================================================================
# CHRONIC_NOISE templates
# ===========================================================================

# One sentence.  Leads with the alert name (so skimmers can pattern-match
# immediately), then gives the two key numbers side by side: total firings and
# the resolved ratio.  The resolved ratio is expressed as a percentage rather
# than a decimal to make the low value viscerally obvious (1.9% reads worse
# than 0.019).
_CHRONIC_NOISE_PROBLEM_SUMMARY = (
    "{alert_name} fired {total_firings} times over the last {lookback_days} days "
    "with only {resolved_ratio_pct}% of firings reaching a resolved state."
)

# Three sentences.
#   1. Names the two distinct failure modes that produce this pattern, so the
#      reader knows whether to recalibrate or delete before they even look at
#      the PromQL expression.
#   2. Names the systemic consequence (alert fatigue / trust erosion), which is
#      more serious than the individual symptom.  This sentence justifies the
#      IMMEDIATE priority; without it, engineers tend to defer noisy-alert
#      cleanup indefinitely.
#   3. Ties the abstract explanation back to the specific numbers in evidence,
#      so the reader doesn't have to hold two mental contexts simultaneously.
_CHRONIC_NOISE_ROOT_CAUSE = (
    "An alert with a low resolved ratio is either firing on a condition that is "
    "effectively permanent (threshold too low for the current system baseline) or "
    "firing faster than any engineer can investigate each instance (evaluation "
    "interval too short for the remediation time). "
    "In either case the alert trains on-call engineers to ignore alerts from this "
    "source, eroding the signal-to-noise ratio of the entire alerting system in a "
    "way that is difficult to reverse once the habit is established. "
    "The {resolved_ratio_pct}% resolved rate for {alert_name} over {lookback_days} "
    "days is strong evidence that its threshold has drifted from the system "
    "baseline against which it was originally calibrated."
)

# The directive names CHECKING RUNBOOKS as the first step, before any threshold
# change or deletion.  This is the most commonly skipped step in alert cleanup,
# and it creates invisible operational debt: a runbook that says "wait for
# HighCPU to resolve before proceeding to step 4" becomes silently broken if
# HighCPU is deleted without updating the runbook.  The on-call engineer
# following that runbook during a future incident will wait indefinitely for an
# alert that no longer exists.  Making the runbook check explicit in the
# suggested_action (rather than burying it in step 5 of the remediation list)
# ensures it is seen even by readers who skim past the numbered steps.
_CHRONIC_NOISE_SUGGESTED_ACTION = (
    "Before changing or deleting {alert_name}: search all runbooks, wiki pages, "
    "and on-call documentation for references to this alert name and update or "
    "remove them first, then either raise the threshold to the p95 of the "
    "monitored metric over the last 90 days or delete the rule entirely if no "
    "concrete remediation action is documented for it."
)

# Seven steps.  Each step is self-contained — a reader who starts mid-list
# should be able to understand what step N asks without rereading step N-1.
# Steps that reference Prometheus use inline PromQL examples so the engineer
# can copy-paste directly rather than needing to know the query syntax.
_CHRONIC_NOISE_REMEDIATION_STEPS: list[str] = [
    # Step 1: establish scope of the runbook audit BEFORE touching the rule,
    # because modifying the rule without knowing its references leaves hidden
    # breakage in incident documentation.
    "Search your runbook repository, incident wiki, and on-call documentation "
    'for every reference to "{alert_name}". List each document and the specific '
    "step that references the alert — you will need to update these in step 6.",
    # Step 2: check alerting pipeline config in addition to runbooks.  Many
    # teams route specific alert names to specific Slack channels or PagerDuty
    # services; deleting the alert without updating these configs leaves orphaned
    # routing rules that silently fail to match.
    "Check your Alertmanager routing config and any on-call tooling (PagerDuty, "
    'Opsgenie) for routing rules or escalation policies that match "{alert_name}" '
    "by name or label, and note any that would need to be updated.",
    # Step 3: the "does an action exist?" gate.  Alerts with no defined
    # remediation action are purely informational and should be deleted, not
    # recalibrated.  Raising the threshold of an alert that nobody knows how to
    # act on just defers the noise without fixing it.
    'Determine whether a documented remediation action exists for "{alert_name}". '
    'If the only response is "investigate" or "check the dashboard", the alert is '
    "not driving behaviour and should be deleted rather than recalibrated — "
    "proceed directly to step 6.",
    # Step 4: data-driven threshold calibration.  Giving the exact PromQL query
    # removes ambiguity about which metric and which aggregation to use.  90
    # days is long enough to capture weekly seasonality and most one-off spikes.
    "If the alert is worth keeping, establish a data-driven threshold: query the "
    "monitored metric at the 95th percentile over the last 90 days using "
    "`quantile_over_time(0.95, <metric>[90d:1h])`. Use this value as the new "
    "threshold, rounded up to the nearest operationally meaningful unit.",
    # Step 5: the paper trail.  A comment in the rule file is the cheapest
    # form of institutional memory — it survives git history, is co-located
    # with the code, and does not require access to a separate wiki or ticketing
    # system to find.
    "Update the alert rule with the new threshold. Add an inline comment in the "
    "rules file recording the calibration date, the PromQL query used to derive "
    "the threshold, and the engineer who made the change.",
    # Step 6: close the runbook loop before shipping.  Note that step 6 follows
    # steps 4-5 because you need to know the new threshold before you can write
    # the updated runbook text.
    "Update all runbook documents and routing rules identified in steps 1 and 2 "
    "to reflect the new threshold or to remove references to the deleted alert.",
    # Step 7: two-week observation window.  One week is often insufficient
    # because it may not cover the full weekly traffic cycle; two weeks catches
    # weekly-periodic false positives and provides a reasonable confidence
    # interval before the change is considered stable.
    "After deploying the change, monitor the daily firing rate for two full weeks "
    "to confirm {alert_name} now fires only on genuinely anomalous conditions. "
    "If the rate does not drop significantly, the threshold may need a second "
    "round of calibration or the metric itself may not be the right signal.",
]


# ===========================================================================
# CO_FIRING_CLUSTER templates
# ===========================================================================

# Leads with the two alert names (visible in the subject line), states the
# ratio as a percentage for impact, and names the most likely cause concisely.
_CO_FIRING_PROBLEM_SUMMARY = (
    "{alert_a} and {alert_b} fired together in {co_occurrence_ratio_pct}% of "
    "their respective {window_minutes}-minute firing windows over the last "
    "{lookback_days} days, indicating a probable shared upstream cause."
)

# Three sentences.
#   1. States what high co-occurrence implies structurally.
#   2. Names the operational cost (fan-out noise during incidents).
#   3. States the important caveat: correlation ≠ causation, so human review
#      is required.  Omitting this caveat would make the recommendation seem
#      more certain than the evidence justifies, which could lead an engineer
#      to consolidate rules that should in fact remain separate.
_CO_FIRING_ROOT_CAUSE = (
    "When two alert rules fire together in more than {co_occurrence_ratio_pct}% "
    "of time windows, they are almost certainly evaluating different symptoms of "
    "the same underlying failure mode rather than two independent problems. "
    "During incidents this produces alert fan-out: the on-call engineer receives "
    "two pages for a single root cause, adding cognitive load at the worst "
    "possible time and obscuring the causal chain. "
    "Note that temporal correlation is not proof of causation — review both "
    "PromQL expressions before consolidating to confirm they share an upstream "
    "metric or infrastructure dependency."
)

# The directive names the specific pair and the consolidation action.  It does
# not say "consider merging" because hedged language leads to deferred action.
# The parallel-running clause (deploy composite, keep originals for one week)
# is included in the directive rather than buried in the steps because it is
# the most common mistake: engineers delete the originals on the same day they
# deploy the composite, with no overlap to catch edge cases.
_CO_FIRING_SUGGESTED_ACTION = (
    "Write a composite alert rule that captures the root cause shared by "
    "{alert_a} and {alert_b}, run it in parallel with both original rules for "
    "one week to confirm coverage, then delete the originals."
)

_CO_FIRING_REMEDIATION_STEPS: list[str] = [
    # Step 1: side-by-side expression review is the most important diagnostic
    # step.  The co-firing detector flags candidates; a human must confirm that
    # the expressions actually share a dependency before consolidating.
    'Review the PromQL expressions for "{alert_a}" and "{alert_b}" side by side '
    "and identify the shared upstream metric, label, or infrastructure component "
    "that causes both to evaluate as true simultaneously.",
    # Step 2: the Prometheus query confirms the pattern is stable and not a
    # coincidence of a specific incident window.
    "Verify the co-firing pattern in Prometheus over the full lookback window: "
    '`count_over_time(ALERTS{{alertname=~"{alert_a}|{alert_b}"}}[{lookback_days}d])`. '
    "Confirm that the {co_occurrence_count} co-firing buckets are distributed "
    "across multiple independent incidents, not clustered in a single event.",
    # Step 3: root cause identification is the creative step.  The composite
    # rule should fire on the cause, not on the symptoms — otherwise you just
    # replace two noisy rules with one noisy rule.
    "Identify the root cause that triggers both alerts and write a new composite "
    "rule that fires at or near that root cause. The new rule should have a "
    'clearer, cause-oriented name (e.g. "DiskSubsystemDegraded" rather than '
    '"DiskPressureOrSlowIO") and a runbook entry that describes consolidated '
    "remediation steps.",
    # Step 4: parallel running is the safety net.  The one-week overlap catches
    # scenarios where the composite rule has a slightly different expression
    # that misses edge cases the original rules covered.
    'Deploy the composite rule alongside the originals. Add a `deprecated: "true"` '
    "label to both originals to signal their status without breaking existing "
    "Alertmanager routing rules that match by label.",
    "Monitor for one full week.  Confirm that every firing of either original "
    "rule is also matched by the composite rule.  Investigate any gap — it "
    "indicates a scenario the composite expression does not cover.",
    "After one week of successful parallel running, delete both original rules "
    "and update all runbooks and Alertmanager routing config that referenced "
    '"{alert_a}" or "{alert_b}" by name.',
]


# ===========================================================================
# THRESHOLD_DRIFT templates
# ===========================================================================

# Names the pattern (monotonically increasing) and the specific evidence
# (number of consecutive slices).  "Without resolving more frequently" is
# included to distinguish drift from a legitimate traffic increase where both
# firings and resolutions are growing proportionally.
_THRESHOLD_DRIFT_PROBLEM_SUMMARY = (
    "{alert_name} has fired with a strictly increasing rate across "
    "{longest_increasing_run} consecutive {slice_days}-day periods, "
    "suggesting the monitored system has moved away from the baseline "
    "used to set its threshold."
)

# Three sentences.
#   1. Distinguishes drift from chronic noise conceptually.
#   2. Names the real-world mechanism: system growth or evolution causes the
#      metric to move, but alert thresholds are rarely updated to match.
#   3. States the consequence if left unaddressed.
_THRESHOLD_DRIFT_ROOT_CAUSE = (
    "Unlike chronic noise — which is high and roughly stable — a monotonically "
    "increasing firing rate indicates that the gap between the alert threshold "
    "and the actual system state is growing over time, not merely that the "
    "threshold was miscalibrated at the outset. "
    "This pattern typically occurs when a system grows (more nodes, more traffic, "
    "larger datasets) or its workload profile shifts, but the alert threshold is "
    "left at the value it was set to when the system was first instrumented. "
    "If not corrected, {alert_name} will eventually fire continuously, at which "
    "point it becomes indistinguishable from chronic noise and the drift signal "
    "is lost entirely."
)

# The directive is specific about the data source (90-day p95) and includes
# the word "recalibrate" rather than "raise" to leave open the possibility that
# the threshold should be lowered or made relative rather than simply increased.
_THRESHOLD_DRIFT_SUGGESTED_ACTION = (
    "Recalibrate the threshold for {alert_name} against the current p95 of the "
    "monitored metric over the last 90 days, and set a recurring calendar reminder "
    "to repeat this calibration quarterly."
)

_THRESHOLD_DRIFT_REMEDIATION_STEPS: list[str] = [
    # Step 1: visualise the drift before changing anything.  Plotting the daily
    # metric value alongside the current threshold makes the magnitude of the
    # drift immediately apparent and provides evidence for the change review.
    "Query the monitored metric at daily resolution over the last {lookback_days} "
    "days to visualise the baseline shift: "
    "`avg_over_time(<metric>[1d])` evaluated at each day. "
    "Plot this against the current alert threshold to quantify the gap.",
    # Step 2: 90-day p95 is a conservative calibration baseline.  It excludes
    # the top 5% of values (spikes) while capturing the true operating range.
    "Calculate the p95 of the metric over the last 90 days as the new threshold "
    "candidate: `quantile_over_time(0.95, <metric>[90d:1h])`. "
    "Compare this to the current threshold to confirm the magnitude of drift.",
    # Step 3: the absolute-vs-relative threshold question.  If the metric is
    # growing because the system is scaling, a fixed threshold will drift again.
    "Determine whether the growth is proportional to a scaling factor "
    "(e.g. number of nodes, request rate). If so, consider replacing the fixed "
    "threshold with a relative one (e.g. percentage of capacity) that scales "
    "automatically rather than requiring periodic manual recalibration.",
    # Step 4: the paper trail (same reasoning as in the chronic noise steps).
    "Update the alert rule with the new threshold value or expression. Add an "
    "inline comment recording the calibration date, the method used, and the "
    "engineer responsible.",
    # Step 5: the recurrence reminder is the most important step for preventing
    # the same issue from reappearing.  Most drift problems are one-time fixes
    # that recur because no recalibration cadence was established.
    "Create a recurring calendar reminder or team operations checklist item to "
    "recalibrate this threshold every 90 days, or after any significant change "
    "to the system being monitored (new cluster nodes, traffic doubling, etc.).",
]


# ===========================================================================
# ANOMALOUS_PATTERN templates
# ===========================================================================

# Unlike the rule-based summaries, this one must lead with the fact that the
# finding is model-generated and then cite the *specific* feature values that
# made the alert an outlier — generic "this looks unusual" language would give
# the reader nothing to validate against.  The three features cited (rate,
# resolution ratio, hour entropy) are the most human-interpretable of the seven.
_ANOMALY_PROBLEM_SUMMARY = (
    "{alert_name} was flagged as a statistical outlier (anomaly score "
    "{anomaly_score}): it fired {firing_rate_per_day} times/day with a "
    "{resolution_ratio_pct}% resolution ratio and an hour-of-day entropy of "
    "{firing_hour_entropy}, a combination that does not match the behaviour of "
    "its peer alerts."
)

# Three sentences.
#   1. States plainly that this is a model output, not a rule, and what the
#      model actually measures — so the reader calibrates their trust correctly.
#   2. The explicit human-validation requirement.  Unsupervised anomaly
#      detection produces probabilistic suggestions, not determinate diagnoses;
#      acting on a finding without validation risks "fixing" a healthy alert.
#   3. Points the reader at the two features most likely to reveal the cause.
_ANOMALY_ROOT_CAUSE = (
    "This finding was produced by an unsupervised Isolation Forest model rather "
    "than a deterministic rule: it isolates alerts whose firing-pattern feature "
    "vector sits far from the bulk of the population, which can surface subtle "
    "problems that no single predefined threshold captures. "
    "Because the model produces probabilistic suggestions and not determinate "
    "diagnoses, this finding must be validated by a human before any action is "
    "taken — confirm from the feature values that this reflects a genuine "
    "misconfiguration rather than a legitimately unusual but healthy alert. "
    "The most informative features are usually the resolution ratio (a near-zero "
    "value indicates an unactionable alert) and the firing-hour entropy (a low "
    "value indicates a scheduled or cron-driven misfire rather than an organic "
    "system condition)."
)

_ANOMALY_SUGGESTED_ACTION = (
    "Manually review {alert_name}'s firing history against the surfaced feature "
    "values to confirm the anomaly is genuine, then apply whichever rule-based "
    "remediation matches the underlying cause — recalibrate the threshold, "
    "consolidate with a related alert, or retire the rule."
)

_ANOMALY_REMEDIATION_STEPS: list[str] = [
    # Step 1: validate before acting — the defining discipline for ML findings.
    'Inspect the surfaced feature values for "{alert_name}" and decide whether '
    "they describe a genuine problem. A high firing rate with a near-zero "
    "resolution ratio points to chronic noise; a low hour-of-day entropy points "
    "to a scheduled/cron misfire; a positive firing trend points to drift.",
    # Step 2: cross-check against the raw timeline so the model is not trusted
    # blindly — the score is a prompt to investigate, not a verdict.
    "Plot the alert's firings over the lookback window in Prometheus "
    '(`count_over_time(ALERTS{{alertname="{alert_name}"}}[1d])` per day) and '
    "confirm the pattern visually matches what the feature values imply.",
    # Step 3: route to the matching deterministic remediation, because the ML
    # detector identifies *that* something is wrong, not *how* to fix it.
    "Once the underlying cause is confirmed, follow the standard remediation for "
    "that cause (threshold recalibration, rule consolidation, or deletion) and "
    "update any runbooks and Alertmanager routing that reference the alert.",
    # Step 4: feed the verdict back so the model's contamination rate can be
    # tuned over time — closes the loop between model output and human judgment.
    "Record whether the finding was a true or false positive. Tracking this over "
    "several runs is what lets you tune the contamination parameter to the real "
    "anomaly rate of your environment.",
]


# ===========================================================================
# Generator
# ===========================================================================

_PRIORITY_ORDER: dict[Priority, int] = {
    Priority.IMMEDIATE: 0,
    Priority.SHORT_TERM: 1,
    Priority.BACKLOG: 2,
}


class RecommendationGenerator:
    """Translates an AnalysisReport into a prioritised list of Recommendations.

    Each AlertHygieneIssue in the report is mapped to exactly one Recommendation
    using the template constants defined in this module.  Template placeholders
    are filled from the issue's ``evidence`` dict so that the output language
    references the specific numbers that triggered the finding.

    Priority assignment follows the rules documented on the Priority enum:
    CHRONIC_NOISE → always IMMEDIATE; THRESHOLD_DRIFT → always SHORT_TERM;
    CO_FIRING_CLUSTER → SHORT_TERM, escalated to IMMEDIATE when the combined
    firing volume of the pair exceeds 50% of total firings in the window;
    ANOMALOUS_PATTERN → SHORT_TERM when severity is HIGH, otherwise BACKLOG,
    and never IMMEDIATE because model findings require human validation first.
    """

    def __init__(self, report: AnalysisReport) -> None:
        self._report = report
        # Sum total_firings from every CHRONIC_NOISE issue to estimate the
        # total firing volume in the analysis window.  This value is used as
        # the denominator when computing the co-firing cluster priority
        # escalation threshold.  Using CHRONIC_NOISE evidence is a reasonable
        # approximation because chronic-noise alerts are typically the highest-
        # volume alerts in any real environment, and they carry explicit counts.
        self._total_firings_in_window: int = sum(
            issue.evidence.get("total_firings", 0)
            for issue in report.issues_found
            if issue.issue_type == IssueType.CHRONIC_NOISE
        )

    def generate(self) -> list[Recommendation]:
        """Return a list of Recommendations sorted from highest to lowest priority."""
        recs: list[Recommendation] = []
        for issue in self._report.issues_found:
            rec = self._build(issue)
            if rec is not None:
                recs.append(rec)
        return sorted(recs, key=lambda r: _PRIORITY_ORDER[r.priority])

    # ------------------------------------------------------------------
    # Internal builders
    # ------------------------------------------------------------------

    def _build(self, issue: AlertHygieneIssue) -> Recommendation | None:
        if issue.issue_type == IssueType.CHRONIC_NOISE:
            return self._build_chronic_noise(issue)
        if issue.issue_type == IssueType.CO_FIRING_CLUSTER:
            return self._build_co_firing(issue)
        if issue.issue_type == IssueType.THRESHOLD_DRIFT:
            return self._build_threshold_drift(issue)
        if issue.issue_type == IssueType.ANOMALOUS_PATTERN:
            return self._build_anomaly(issue)
        # Unknown issue type — return None so the engine can skip it without
        # raising an exception.  New detectors added in the future will produce
        # no recommendation until a matching builder is added here.
        return None

    def _build_chronic_noise(self, issue: AlertHygieneIssue) -> Recommendation:
        ev = issue.evidence
        ctx: dict = {
            "alert_name": issue.alert_name,
            "total_firings": ev.get("total_firings", 0),
            "resolved_ratio_pct": round(ev.get("resolved_ratio", 0.0) * 100, 1),
            "lookback_days": self._report.lookback_days,
        }
        return Recommendation(
            alert_name=issue.alert_name,
            issue_type=issue.issue_type.value,
            problem_summary=_CHRONIC_NOISE_PROBLEM_SUMMARY.format(**ctx),
            root_cause_explanation=_CHRONIC_NOISE_ROOT_CAUSE.format(**ctx),
            suggested_action=_CHRONIC_NOISE_SUGGESTED_ACTION.format(**ctx),
            remediation_steps=[
                s.format(**ctx) for s in _CHRONIC_NOISE_REMEDIATION_STEPS
            ],
            priority=Priority.IMMEDIATE,
        )

    def _build_co_firing(self, issue: AlertHygieneIssue) -> Recommendation:
        ev = issue.evidence
        ctx: dict = {
            "alert_name": issue.alert_name,
            "alert_a": ev.get("alert_a", ""),
            "alert_b": ev.get("alert_b", ""),
            "co_occurrence_ratio_pct": round(
                ev.get("co_occurrence_ratio", 0.0) * 100, 1
            ),
            "co_occurrence_count": ev.get("co_occurrence_count", 0),
            "window_minutes": ev.get("window_minutes", 5),
            "lookback_days": self._report.lookback_days,
        }
        priority = self._co_firing_priority(issue)
        return Recommendation(
            alert_name=issue.alert_name,
            issue_type=issue.issue_type.value,
            problem_summary=_CO_FIRING_PROBLEM_SUMMARY.format(**ctx),
            root_cause_explanation=_CO_FIRING_ROOT_CAUSE.format(**ctx),
            suggested_action=_CO_FIRING_SUGGESTED_ACTION.format(**ctx),
            remediation_steps=[s.format(**ctx) for s in _CO_FIRING_REMEDIATION_STEPS],
            priority=priority,
        )

    def _build_threshold_drift(self, issue: AlertHygieneIssue) -> Recommendation:
        ev = issue.evidence
        ctx: dict = {
            "alert_name": issue.alert_name,
            "longest_increasing_run": ev.get("longest_increasing_run", 0),
            "slice_days": ev.get("slice_days", 7),
            "lookback_days": self._report.lookback_days,
        }
        return Recommendation(
            alert_name=issue.alert_name,
            issue_type=issue.issue_type.value,
            problem_summary=_THRESHOLD_DRIFT_PROBLEM_SUMMARY.format(**ctx),
            root_cause_explanation=_THRESHOLD_DRIFT_ROOT_CAUSE.format(**ctx),
            suggested_action=_THRESHOLD_DRIFT_SUGGESTED_ACTION.format(**ctx),
            remediation_steps=[
                s.format(**ctx) for s in _THRESHOLD_DRIFT_REMEDIATION_STEPS
            ],
            priority=Priority.SHORT_TERM,
        )

    def _build_anomaly(self, issue: AlertHygieneIssue) -> Recommendation:
        ev = issue.evidence
        ctx: dict = {
            "alert_name": issue.alert_name,
            "anomaly_score": ev.get("anomaly_score", 0.0),
            "firing_rate_per_day": round(ev.get("firing_rate_per_day", 0.0), 2),
            "resolution_ratio_pct": round(ev.get("resolution_ratio", 0.0) * 100, 1),
            "firing_hour_entropy": round(ev.get("firing_hour_entropy", 0.0), 2),
        }
        return Recommendation(
            alert_name=issue.alert_name,
            issue_type=issue.issue_type.value,
            problem_summary=_ANOMALY_PROBLEM_SUMMARY.format(**ctx),
            root_cause_explanation=_ANOMALY_ROOT_CAUSE.format(**ctx),
            suggested_action=_ANOMALY_SUGGESTED_ACTION.format(**ctx),
            remediation_steps=[s.format(**ctx) for s in _ANOMALY_REMEDIATION_STEPS],
            priority=self._anomaly_priority(issue),
        )

    def _anomaly_priority(self, issue: AlertHygieneIssue) -> Priority:
        """Map anomaly severity to priority.

        Anomaly findings are hypotheses requiring human validation, so they are
        never escalated to IMMEDIATE — acting on an unvalidated model output
        within the current shift would be the wrong incentive.  A HIGH-severity
        anomaly (deep in the score tail) is worth a SHORT_TERM look; everything
        else is BACKLOG until a human confirms it.
        """
        if issue.severity == Severity.HIGH:
            return Priority.SHORT_TERM
        return Priority.BACKLOG

    def _co_firing_priority(self, issue: AlertHygieneIssue) -> Priority:
        """Escalate co-firing clusters to IMMEDIATE when they dominate firing volume."""
        ev = issue.evidence
        combined = ev.get("alert_a_bucket_count", 0) + ev.get("alert_b_bucket_count", 0)
        if (
            self._total_firings_in_window > 0
            and combined > self._total_firings_in_window * 0.5
        ):
            return Priority.IMMEDIATE
        return Priority.SHORT_TERM
