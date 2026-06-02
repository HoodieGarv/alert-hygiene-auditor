"""Integration tests for the recommendation generator and markdown exporter.

These tests run the full generator → exporter pipeline using synthetic
AnalysisReport data.  They are integration-style rather than unit tests
because their value lies in verifying that the three layers — analysis schema,
recommendation schema, and exporter — compose correctly end to end, not in
testing any single function in isolation.

Test cases
----------
- CHRONIC_NOISE → IMMEDIATE priority: verifies that the priority assignment
  rule (chronic noise is always IMMEDIATE) is correctly applied by the
  generator and present in the returned Recommendation object.
- Markdown output contains alert name and "remediation": verifies that the
  markdown exporter produces a file containing the expected content, without
  asserting the exact formatting, which would make the test brittle to
  cosmetic changes in the exporter templates.
"""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from auditor.analysis.schemas import AlertHygieneIssue, AnalysisReport, IssueType, Severity
from auditor.recommendations.exporters import markdown_exporter
from auditor.recommendations.generator import RecommendationGenerator
from auditor.recommendations.schemas import Priority


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _chronic_noise_report(alert_name: str = "HighCPU") -> AnalysisReport:
    """Build a minimal AnalysisReport containing one CHRONIC_NOISE issue."""
    issue = AlertHygieneIssue(
        alert_name=alert_name,
        issue_type=IssueType.CHRONIC_NOISE,
        severity=Severity.HIGH,
        evidence={
            "total_firings": 312,
            "resolved_count": 6,
            "resolved_ratio": 0.019,
            "firing_threshold": 20,
            "resolved_ratio_threshold": 0.30,
            "window_start": "2026-04-28T00:00:00Z",
            "window_end": "2026-05-28T00:00:00Z",
        },
        detected_at=datetime(2026, 5, 28, tzinfo=timezone.utc),
    )
    return AnalysisReport(
        generated_at=datetime(2026, 5, 28, tzinfo=timezone.utc),
        lookback_days=30,
        total_alerts_analyzed=5,
        issues_found=[issue],
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_chronic_noise_issue_produces_immediate_priority() -> None:
    """A CHRONIC_NOISE finding must produce a Recommendation with priority IMMEDIATE.

    Chronic noise is always IMMEDIATE because alert fatigue — the erosion of
    trust in the alerting system — compounds over time and cannot be safely
    deferred.
    """
    report = _chronic_noise_report(alert_name="HighCPU")
    generator = RecommendationGenerator(report)

    recs = generator.generate()

    assert len(recs) == 1
    assert recs[0].priority == Priority.IMMEDIATE
    assert recs[0].alert_name == "HighCPU"
    assert recs[0].issue_type == IssueType.CHRONIC_NOISE.value


def test_markdown_exporter_contains_alert_name_and_remediation_heading(
    tmp_path: Path,
) -> None:
    """The markdown exporter must produce a file that contains the alert name and a remediation section.

    This test does not assert exact formatting to avoid brittleness — cosmetic
    changes to templates should not require test changes.  It asserts only that
    the two most important pieces of content are present: the specific alert
    name (so the engineer knows which rule to act on) and the word "remediation"
    (confirming that action-oriented content was included, not just a problem
    description).
    """
    report = _chronic_noise_report(alert_name="HighCPU")
    generator = RecommendationGenerator(report)
    recs = generator.generate()

    output_file = tmp_path / "audit.md"
    markdown_exporter.export(
        recs,
        output_file,
        generated_at=datetime(2026, 5, 28, tzinfo=timezone.utc),
        lookback_days=30,
        total_alerts_analyzed=5,
    )

    content = output_file.read_text(encoding="utf-8")

    assert "HighCPU" in content
    assert "remediation" in content.lower()
