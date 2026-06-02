"""Output schemas for the recommendation engine.

A Recommendation is the human-facing translation of an AlertHygieneIssue.
Where an issue describes *what* the detector found (numbers, ratios, raw
evidence), a recommendation describes *what to do about it* in language an
on-call engineer can act on without first understanding the detection algorithm.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class Priority(str, Enum):
    """Urgency classification for a recommendation.

    Priority is assigned based on the combination of issue severity and issue
    type, not on severity alone, because different failure modes carry different
    operational risk regardless of how severe the individual numbers are:

    IMMEDIATE
        Assigned to every CHRONIC_NOISE finding.  A noisy alert desensitises
        on-call engineers over time — the longer it fires without action, the
        more likely real incidents are missed because the team has learned to
        ignore alerts from that source.  This erosion of trust is cumulative
        and difficult to reverse, making noise the highest-urgency category
        even when individual firing counts are modest.

    SHORT_TERM
        Assigned to THRESHOLD_DRIFT findings and most CO_FIRING_CLUSTER
        findings.  Drift is a slow-moving problem: the alert is still providing
        some signal, but that signal is degrading.  Co-firing clusters create
        alert fatigue during incidents but do not (by themselves) cause missed
        detections.  Both warrant attention within the current sprint or
        quarter, but neither requires waking someone up tonight.

        Exception: a co-firing cluster is escalated to IMMEDIATE when the
        combined firing volume of its two member alerts exceeds 50% of all
        alert firings in the analysis window, because at that point the cluster
        is the dominant source of noise and the SHORT_TERM framing understates
        the urgency.

    BACKLOG
        Reserved for low-severity findings that have no immediate operational
        impact — for example, a rule whose firing rate is technically increasing
        but is still very low in absolute terms.
    """

    IMMEDIATE = "IMMEDIATE"
    SHORT_TERM = "SHORT_TERM"
    BACKLOG = "BACKLOG"


class Recommendation(BaseModel):
    """A structured, actionable remediation recommendation for one hygiene issue.

    Fields are sized for human consumption:
    - ``problem_summary`` is one sentence, suitable for a table cell or Slack message.
    - ``root_cause_explanation`` is two to three sentences for engineers who need
      context before acting.
    - ``suggested_action`` is one imperative directive — the single most important
      thing to do.
    - ``remediation_steps`` is an ordered checklist for following through.
    """

    alert_name: str
    issue_type: str
    problem_summary: str
    root_cause_explanation: str
    suggested_action: str
    remediation_steps: list[str]
    priority: Priority
