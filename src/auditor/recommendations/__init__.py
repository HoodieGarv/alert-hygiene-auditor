"""Recommendation engine — translates analysis findings into actionable output.

Public API:

    from auditor.recommendations import RecommendationGenerator
    from auditor.recommendations import json_exporter, markdown_exporter

    generator = RecommendationGenerator(report)
    recs = generator.generate()

    json_exporter.export(recs, "reports/audit.json")
    markdown_exporter.export(recs, "reports/audit.md", lookback_days=30)
"""

from auditor.recommendations.generator import RecommendationGenerator
from auditor.recommendations.exporters import json_exporter, markdown_exporter

__all__ = ["RecommendationGenerator", "json_exporter", "markdown_exporter"]
