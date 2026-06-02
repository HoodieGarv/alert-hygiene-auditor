"""Alert hygiene detectors — one module per failure mode.

Each detector accepts a SQLAlchemy Session and a lookback window, queries the
alert_firings table, and returns a list of AlertHygieneIssue instances.

Detectors
---------
chronic_noise     : Identifies rules that fire continuously without resolution.
co_firing         : Identifies pairs of rules whose firings are strongly correlated.
threshold_drift   : Identifies rules whose firing rate has increased monotonically.
"""
