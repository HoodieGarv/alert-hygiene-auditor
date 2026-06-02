"""JSON serializer for recommendation output.

JSON output is intended for downstream programmatic consumption rather than
direct human reading.  Examples of downstream integrations this format enables:

- A GitHub Actions workflow that reads the JSON on each weekly run and
  automatically opens a GitHub Issue for each IMMEDIATE recommendation, with
  the remediation steps pre-formatted as a task list in the issue body.
- A Slack bot that parses the JSON at the start of each on-call rotation and
  posts the top three recommendations (by priority) to the team channel,
  giving the incoming engineer a standing agenda item for the week.
- A compliance script that checks whether any IMMEDIATE recommendations have
  remained unaddressed across two or more consecutive weekly runs and escalates
  them to the engineering manager.

The file is written with two-space indentation so it remains legible when
opened directly in a text editor, but is compact enough to be stored in a git
repository without creating large diffs.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from auditor.recommendations.schemas import Recommendation


def export(
    recommendations: list[Recommendation],
    output_path: Path | str,
) -> None:
    """Write recommendations to a JSON file.

    The output is a top-level object with a ``generated_at`` timestamp and a
    ``recommendations`` array.  Each element in the array is a flat dict
    corresponding to one Recommendation, with enum values serialized as their
    string names (e.g. ``"IMMEDIATE"`` rather than ``{"value": "IMMEDIATE"}``).

    The output directory is created automatically if it does not exist, so
    callers do not need to mkdir before calling this function.

    Args:
        recommendations: The list of Recommendation objects to serialize.
        output_path:      Destination file path (created or overwritten).
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Build a plain dict per recommendation.  model_dump() is called without
    # mode="json" so that enum fields are returned as their .value strings
    # rather than as Enum instances, which would require a custom JSON encoder.
    payload: dict = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "count": len(recommendations),
        "recommendations": [
            rec.model_dump()
            for rec in recommendations
        ],
    }

    with path.open("w", encoding="utf-8") as fh:
        # indent=2 keeps the file human-skimmable without being extravagant
        # in size.  ensure_ascii=False preserves the ↔ character used in
        # co-firing cluster alert names without escaping it to ↔.
        json.dump(payload, fh, indent=2, ensure_ascii=False, default=str)
