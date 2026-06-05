# Alert Hygiene Auditor

Analyze Prometheus alert history to find the rules that should be rewritten — not silenced.

[![CI](https://github.com/HoodieGarv/alert-hygiene-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/HoodieGarv/alert-hygiene-auditor/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Problem Statement

Alert noise in production environments is almost always a symptom of poor instrumentation hygiene, not a display problem. When a rule fires continuously without prompting any human action, the underlying cause is that the rule was written against the wrong signal, the wrong threshold, or at the wrong layer of the stack — not that it needs a longer silence window or a smarter routing policy. Yet the majority of alerting tooling addresses noise at runtime: inhibition rules, silence windows, and aggregation layers that filter the symptom while leaving the broken rule untouched. Alert Hygiene Auditor takes a different approach. It analyzes alert history to surface the specific rules that should be rewritten, consolidated, or retired, putting the remediation work back where it belongs — in the instrumentation.

---

## How It Works

The auditor runs as a pipeline. During ingestion, it polls the Prometheus `/api/v1/rules` and `/api/v1/query_range` endpoints together with the Alertmanager `/api/v2/alerts` endpoint, normalizes the raw payloads into a common schema, and persists the resulting `AlertFiring` rows to PostgreSQL. Ingestion is incremental: each run records its high-water mark, so subsequent runs fetch only the data that has arrived since the last successful pass.

The analysis engine then queries the stored data through three independent detectors. The chronic noise detector counts total firings and resolved-state transitions per alert over the lookback window; a rule with a high firing count and a low resolved ratio is flagged because the evidence suggests the team has implicitly accepted the condition as permanent. The co-firing detector divides the timeline into fixed-width buckets and counts how often each pair of alerts fires within the same bucket; a pair with a high co-occurrence ratio is flagged because correlated rules typically share a root cause that a single, better-targeted rule would cover. The threshold drift detector slices the lookback window into equal segments and checks whether firing counts increase monotonically across slices; a rule that fires more in each successive segment is flagged because the monitored system has drifted away from the baseline the rule was calibrated against.

Each detector emits `AlertHygieneIssue` records that the recommendation engine translates into prioritized, human-readable `Recommendation` objects. The priority assignment is deliberate: chronic noise is always `IMMEDIATE` because alert fatigue compounds and cannot be safely deferred; threshold drift is always `SHORT_TERM` because the rule is still meaningful but needs recalibration; co-firing pairs default to `SHORT_TERM` but escalate to `IMMEDIATE` when the pair's combined activity accounts for more than half of total alert volume in the window, indicating systemic rather than incidental correlation.

Recommendations are exported as structured JSON (for downstream automation) and as a formatted Markdown report (for filing directly as a GitHub Issue or attaching to an incident review). The Streamlit dashboard provides an interactive summary with a traffic-light severity chart, a findings table, and per-recommendation detail panels with numbered remediation steps.

---

## Architecture

```mermaid
graph LR
    P[Prometheus API] --> ING[Ingestion Layer]
    AM[Alertmanager API] --> ING
    ING --> DB[(PostgreSQL)]
    DB --> AE[Analysis Engine]
    AE --> |AlertHygieneIssues| REC[Recommendation Engine]
    REC --> JSON[JSON Export]
    REC --> MD[Markdown Export]
    REC --> DASH[Streamlit Dashboard]
```

**Ingestion Layer** (`src/auditor/ingest/`) — `prometheus_client.py` and `alertmanager_client.py` each wrap an `httpx` session and expose a single typed method that returns parsed Pydantic models. `normalizer.py` converts those models into `AlertFiring` ORM rows, grouping consecutive matrix timestamps into firing windows with a two-step tolerance for scrape jitter. `runner.py` orchestrates a full pass and writes an `IngestionRun` audit record regardless of success or failure.

**Storage** (`src/auditor/db/`) — Two tables. `alert_firings` stores one row per resolved firing event with a natural-key deduplication check on `(alert_name, starts_at)`. `ingestion_runs` stores one row per ingestion attempt, providing the high-water mark for incremental fetches and a history of errors.

**Analysis Engine** (`src/auditor/analysis/`) — `engine.py` instantiates all four detectors (three rule-based plus the Isolation Forest anomaly detector), collects their output, deduplicates on `(alert_name, issue_type)` to suppress duplicate findings from overlapping windows, and returns a single `AnalysisReport`. The ML detector is wrapped in a try/except so that on sparse data it degrades gracefully — logging a warning instead of failing the whole run.

**Recommendation Engine** (`src/auditor/recommendations/`) — `generator.py` maps each `AlertHygieneIssue` to a `Recommendation` using issue-type-specific template strings that reference evidence values from the issue. Priority assignment rules are expressed as pure functions with no side effects, making them straightforward to test in isolation.

**Dashboard** (`src/auditor/dashboard/app.py`) — A single Streamlit file that renders summary metrics, a Plotly bar chart with traffic-light severity colors, a filterable findings dataframe, expandable per-recommendation detail panels, and a one-click download button for the Markdown report.

---

## Dashboard

**Severity Overview**
![Traffic-light severity chart showing alert counts by severity tier](docs/screenshots/severity_chart.png)

**Findings Table**
![Filterable findings table with sortable columns for rule, severity, and count](docs/screenshots/findings_table.png)

**Recommendation Detail**
![Detail panel showing remediation steps for a selected finding](docs/screenshots/recommendation_detail.png)

---

## Design Decisions

**PostgreSQL over SQLite for production.** The co-firing detector requires counting co-occurrences across pairs of alerts, and the threshold drift detector requires ordered aggregation over time slices. Both queries use window-function patterns that SQLite handles only partially. PostgreSQL's `LATERAL` join, partial index support, and reliable `TIMESTAMP WITH TIME ZONE` semantics make it the correct choice for a tool intended to query months of alert history. SQLite is used exclusively in the test suite, where the queries are simple enough for it to be correct and where eliminating an external dependency is worth the trade-off.

**Three focused detectors rather than a monolithic analyzer.** Each failure mode has a different statistical signature: chronic noise is a ratio, co-firing is a correlation, and threshold drift is a monotonic trend. Implementing them as independent classes with a shared interface means each can be tuned, replaced, or disabled without touching the others. The analysis engine is a thin orchestrator that knows nothing about the detectors' internals.

**Markdown export for GitHub Issues.** The primary consumer of a hygiene audit is the team that owns the alert rules. Markdown is the lingua franca of GitHub Issues and pull request descriptions, so exporting to Markdown means the output can be pasted directly into a tracking ticket without transformation. The priority emoji badges (🔴 IMMEDIATE, 🟡 SHORT\_TERM, 🟢 BACKLOG) are intentional: they survive plain-text rendering and give reviewers an immediate triage signal when scanning a long issue list.

---

## Anomaly Detection Module

The three rule-based detectors capture well-understood failure modes by encoding them as explicit thresholds, but alert hygiene problems can also manifest as subtle pattern irregularities that no predefined rule anticipates — an alert that fires at statistically unusual intervals, or whose hour-of-day distribution betrays a misconfigured cron target rather than a genuine system condition. To surface these, the project adds a fourth detector built on a scikit-learn Isolation Forest. Isolation Forest was chosen because it is unsupervised, which is a hard requirement here since no team maintains a labeled corpus of "bad alerts" to train against; because it is interpretable at the feature level, so every finding can be explained by the concrete feature values that produced it; and because it is well-suited to tabular data described by a small number of engineered features, which is exactly the shape of this problem.

Each alert's firing history is reduced to seven engineered features. **`firing_rate_per_day`** is the total firing count divided by the days in the window, capturing raw volume and most sensitive to chronic noise. **`resolution_ratio`** is the proportion of firings that ever resolved, capturing actionability and serving as the single strongest signal of an unactionable alert. **`mean_duration_minutes`** is the average time a firing stays open, distinguishing alerts that flap from alerts that stick. **`firing_hour_entropy`** is the Shannon entropy of firings across the 24 hours of the day, where a low value betrays a scheduled or cron-driven misfire rather than organic system load. **`inter_firing_interval_cv`** is the coefficient of variation of the gaps between consecutive firings, where a very low value indicates the machine-like periodicity characteristic of an always-true rule. **`weekly_firing_trend`** is the slope of a linear fit to per-day firing counts, where a positive value is the signature of threshold drift. **`days_since_last_firing`** is the recency of the most recent firing, flagging stale or retired rules that fired historically but have since gone quiet.

### Model Performance

Because the model is unsupervised, evaluation relies on proxy metrics rather than precision and recall. The figures below were produced by `ModelEvaluator` over a representative ten-alert feature set containing two deliberately pathological alerts.

**Contamination sensitivity** — the number of alerts flagged as the contamination parameter is swept. The count rises smoothly and monotonically, the expected behavior of a model whose score distribution has a clean tail rather than a cliff:

| Contamination | Alerts flagged |
|---|---|
| 0.05 | 1 |
| 0.10 | 1 |
| 0.15 | 2 |
| 0.20 | 2 |
| 0.25 | 3 |

**Feature importance by mean isolation path length** — the average depth at which each feature is used to split across all trees, sorted ascending. A shallower depth means the forest isolates on that feature earlier, so it is more discriminative:

| Rank | Feature | Mean path length |
|---|---|---|
| 1 | `weekly_firing_trend` | 1.604 |
| 2 | `inter_firing_interval_cv` | 1.646 |
| 3 | `days_since_last_firing` | 1.723 |
| 4 | `firing_rate_per_day` | 1.778 |
| 5 | `mean_duration_minutes` | 1.782 |
| 6 | `resolution_ratio` | 1.789 |
| 7 | `firing_hour_entropy` | 1.860 |

The top two features are the most informative. `weekly_firing_trend` sits shallowest, meaning the forest separates alerts first on whether their firing rate is climbing over time — the clearest single divider between a drifting alert and a stable one in this dataset. `inter_firing_interval_cv` ranks second, meaning the regularity of firing intervals is the next strongest separator, which is what isolates the perfectly-periodic firing of an always-true or cron-driven rule from the bursty, irregular firing of a genuine incident-driven alert.

**Anomaly score distribution** — descriptive statistics of the per-alert anomaly scores. The dense cluster of positive scores with a single value pulled out into the negative tail (`min` = −0.084, well below the 25th percentile of 0.110) is the qualitative signature of a model that is finding signal rather than spreading its scores uniformly:

| Statistic | Value |
|---|---|
| mean | 0.1093 |
| std | 0.0791 |
| min | −0.0836 |
| 25th percentile | 0.1096 |
| median | 0.1444 |
| 75th percentile | 0.1530 |
| max | 0.1833 |

These proxy metrics establish plausibility, not correctness. Without ground-truth labels there is no way to compute a true false-positive rate, and a model can produce a well-separated score distribution while still flagging the wrong alerts. The findings this module produces should therefore be treated as hypotheses for human review rather than determinate diagnoses — which is why every anomaly recommendation is capped below `IMMEDIATE` priority and its explanatory text states explicitly that the finding is model-generated and requires validation before any action is taken.

### Configuration

The detector exposes four constructor parameters. **`contamination`** (default `0.1`) is the expected proportion of anomalies in the data; it sets the score cutoff between inliers and outliers, so raising it flags more alerts (risking false positives that erode trust in the tool) and lowering it flags fewer (risking missed anomalies). **`n_estimators`** (default `100`) is the number of trees in the forest; more trees yield a more stable anomaly score at higher compute cost, and 100 is ample for this small feature space. **`random_state`** (default `42`) seeds the forest's randomness so that runs are reproducible — the same data always yields the same findings, which is essential for output that engineers are expected to act on. **`min_records_required`** (default `50`) is the minimum number of firing records in the window before the model will run at all; below this threshold the detector raises `InsufficientDataError`, because an Isolation Forest trained on too few points overfits and produces findings that are numerically valid but operationally meaningless.

---

## Running Locally

**Prerequisites:** Docker Desktop, Python 3.11+, and a terminal.

```bash
# 1. Clone and enter the repository
git clone https://github.com/HoodieGarv/alert-hygiene-auditor.git
cd alert-hygiene-auditor

# 2. Start the infrastructure (Prometheus, Alertmanager, node-exporter, PostgreSQL)
cd docker && docker compose up -d && cd ..

# 3. Install the package in editable mode
pip install -e ".[dev]"
```

Copy `config/settings.yaml` and point it at your running services:

```yaml
prometheus_url: "http://localhost:9090"
alertmanager_url: "http://localhost:9093"
database_url: "postgresql://auditor:auditor_dev_only@localhost:5432/auditor"
lookback_days: 30
```

Run the ingestion pass to populate the database, then analyze the stored data:

```bash
python -m auditor.ingest.runner      # fetch and persist alert firings
python -m auditor.analysis.engine    # run detectors, print report
```

Start the dashboard:

```bash
streamlit run src/auditor/dashboard/app.py
```

Open `http://localhost:8501` in your browser.

---

## Running Tests

```bash
pytest -v --tb=short --cov=src/auditor --cov-report=term-missing
```

The suite uses SQLite in-memory databases throughout — no running services required. Tests are organized by layer: `test_chronic_noise_detector.py`, `test_co_firing_detector.py`, and `test_threshold_drift_detector.py` each exercise a single detector with controlled fixture data; `test_recommendation_generator.py` runs the full generator → exporter pipeline on synthetic `AnalysisReport` input.

---

## Documentation

- [Architecture Decisions](docs/architecture-decisions.md)

---

## License

[MIT](LICENSE)
