"""Canonical output schemas for the analysis engine.

Every detector in the system — regardless of its internal algorithm — produces
instances of AlertHygieneIssue.  The engine collects these into an
AnalysisReport.  Defining the output contract in one place ensures that the
dashboard, CLI, and any future API layer all consume the same structure without
each having to know which detector produced a particular finding.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class IssueType(str, Enum):
    """The hygiene failure modes the analysis engine can detect.

    The first three are produced by deterministic rule-based detectors.  The
    fourth, ANOMALOUS_PATTERN, is produced by the unsupervised Isolation Forest
    detector and represents a statistically unusual firing pattern that does not
    fit any single predefined rule — it is a hypothesis for human review rather
    than a determinate diagnosis.
    """

    CHRONIC_NOISE = "CHRONIC_NOISE"
    CO_FIRING_CLUSTER = "CO_FIRING_CLUSTER"
    THRESHOLD_DRIFT = "THRESHOLD_DRIFT"
    ANOMALOUS_PATTERN = "ANOMALOUS_PATTERN"


class Severity(str, Enum):
    """How urgently the issue should be addressed."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AlertHygieneIssue(BaseModel):
    """A single hygiene finding produced by one of the detectors.

    This schema is the canonical output contract of the analysis engine.  All
    detectors (ChronicNoiseDetector, CoFiringDetector, ThresholdDriftDetector,
    and the unsupervised IsolationForestDetector) produce instances of this
    model regardless of their internal logic, so downstream consumers — the
    dashboard, the CLI report renderer, and any API layer — never need to know
    which detector produced a particular finding.

    ``evidence`` is deliberately a free-form dict rather than a typed model so
    that each detector can include the raw metrics most relevant to its
    algorithm without requiring a schema change when detection logic evolves.
    """

    alert_name: str
    issue_type: IssueType
    severity: Severity
    # Raw metrics that triggered the finding — contents vary by detector.
    evidence: dict[str, Any]
    detected_at: datetime


class AnalysisReport(BaseModel):
    """The complete output of one analysis engine run.

    ``lookback_days`` is the configurable time window the analysis covers —
    the number of calendar days of alert firing history that was examined to
    produce the findings.  It is stored on the report rather than derived from
    the issue timestamps so that consumers can immediately distinguish "no
    issues found in 30 days" from "no issues found in 7 days", which are very
    different operational conclusions.  A short lookback may miss low-frequency
    drift; a long lookback may surface issues that have already been resolved.
    """

    generated_at: datetime
    lookback_days: int
    total_alerts_analyzed: int
    issues_found: list[AlertHygieneIssue] = Field(default_factory=list)
    # Arbitrary key/value pairs — detector names, run duration, row counts, etc.
    metadata: dict[str, Any] = Field(default_factory=dict)
