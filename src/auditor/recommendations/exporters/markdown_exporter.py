"""Markdown serializer for recommendation output.

Markdown output is intended for direct use in GitHub Pull Requests, GitHub
Issues, and team wikis.  The format is chosen to minimise friction between
the audit tool and the places where engineering work is tracked:

- The summary table at the top gives reviewers an at-a-glance view of all
  findings without requiring them to scroll through every section, making it
  suitable as the opening comment on a quarterly alert hygiene PR.
- Remediation steps are formatted as a numbered list rather than prose because
  a numbered list can be followed step by step during an active incident
  without losing your place — prose requires re-reading to track progress.
  GitHub also renders numbered lists with consistent spacing, making them
  visually distinct from the explanatory text above them.
- Section headers use H3 (###) rather than H1/H2 so the report can be embedded
  inside a larger document (e.g. a quarterly engineering review) without
  disrupting the host document's heading hierarchy.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from auditor.recommendations.schemas import Priority, Recommendation

_PRIORITY_BADGE: dict[Priority, str] = {
    Priority.IMMEDIATE: "🔴 IMMEDIATE",
    Priority.SHORT_TERM: "🟡 SHORT_TERM",
    Priority.BACKLOG: "🟢 BACKLOG",
}


def _badge(priority: Priority) -> str:
    return _PRIORITY_BADGE.get(priority, priority.value)


def _render_summary_table(recommendations: list[Recommendation]) -> str:
    """Render the top-level summary table as a Markdown string."""
    lines: list[str] = [
        "| Alert | Issue Type | Priority |",
        "| --- | --- | --- |",
    ]
    for rec in recommendations:
        lines.append(
            f"| {rec.alert_name} | `{rec.issue_type}` | {_badge(rec.priority)} |"
        )
    return "\n".join(lines)


def _render_recommendation(index: int, rec: Recommendation) -> str:
    """Render a single recommendation as a Markdown section."""
    badge = _badge(rec.priority)
    steps = "\n".join(
        f"{i + 1}. {step}" for i, step in enumerate(rec.remediation_steps)
    )
    return (
        f"### {index}. {badge} — {rec.alert_name}\n\n"
        f"**Issue type:** `{rec.issue_type}`\n\n"
        f"#### Problem\n\n"
        f"{rec.problem_summary}\n\n"
        f"#### Root Cause\n\n"
        f"{rec.root_cause_explanation}\n\n"
        f"#### Suggested Action\n\n"
        f"{rec.suggested_action}\n\n"
        f"#### Remediation Steps\n\n"
        f"{steps}\n"
    )


def export(
    recommendations: list[Recommendation],
    output_path: Path | str,
    *,
    generated_at: datetime | None = None,
    lookback_days: int | None = None,
    total_alerts_analyzed: int | None = None,
) -> None:
    """Write recommendations to a Markdown file.

    The output file has three sections:
    1. A header block with generation metadata.
    2. A summary table listing all findings at a glance.
    3. A detailed section per recommendation, in priority order.

    The output directory is created automatically if it does not exist.

    Args:
        recommendations:       The list of Recommendation objects to render.
        output_path:           Destination file path (created or overwritten).
        generated_at:          Optional timestamp for the report header.
        lookback_days:         Optional lookback window to include in the header.
        total_alerts_analyzed: Optional count of alerts examined in the header.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    ts = (generated_at or datetime.utcnow()).strftime("%Y-%m-%dT%H:%M:%SZ")
    issue_count = len(recommendations)

    # --- Header block ---------------------------------------------------
    header_lines: list[str] = [
        "# Alert Hygiene Audit Report\n",
        f"**Generated:** {ts}  ",
    ]
    if lookback_days is not None:
        header_lines.append(f"**Lookback window:** {lookback_days} days  ")
    if total_alerts_analyzed is not None:
        header_lines.append(f"**Alerts analysed:** {total_alerts_analyzed}  ")
    header_lines.append(f"**Issues found:** {issue_count}")

    header = "\n".join(header_lines)

    # --- Summary table --------------------------------------------------
    if recommendations:
        summary = "## Summary\n\n" + _render_summary_table(recommendations)
    else:
        summary = "## Summary\n\nNo issues found in the analysis window."

    # --- Detailed findings ----------------------------------------------
    findings_sections: list[str] = []
    for i, rec in enumerate(recommendations, start=1):
        findings_sections.append(_render_recommendation(i, rec))

    findings = "## Findings\n\n" + "\n---\n\n".join(findings_sections) if findings_sections else ""

    # --- Assemble and write ---------------------------------------------
    parts = [header, "---", summary]
    if findings:
        parts += ["---", findings]

    document = "\n\n".join(parts) + "\n"

    path.write_text(document, encoding="utf-8")
