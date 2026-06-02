"""Analysis engine — detects hygiene issues in historical alert firing data.

Submodules
----------
schemas   : Pydantic models for AlertHygieneIssue and AnalysisReport.
engine    : AnalysisEngine orchestrator that runs all detectors and returns a report.
detectors : Individual detector implementations (chronic_noise, co_firing, threshold_drift).
"""
