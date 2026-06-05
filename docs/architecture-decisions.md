# Architecture Decisions

The records below were extracted from the README's former "What This Project
Demonstrates" section. Each original paragraph was a skills/competency claim
rather than a stated engineering decision, so the underlying engineering
choice has been inferred. Every entry is marked with an inline `inferred`
comment so the author can verify accuracy before publishing.

## Layered pipeline composition over a monolithic processor <!-- inferred: verify accuracy -->
**Context:** An alert hygiene auditor must handle partial failures (a fetch
that dies halfway through), re-runs against overlapping windows, and produce
an audit trail even when the main data write errors. A single
function/script would couple HTTP I/O, normalization, statistics, and
reporting, making each phase impossible to test in isolation and impossible
to recover from mid-pipeline.

**Decision:** Decompose the auditor into independent layers — ingestion →
storage → analysis → recommendations → presentation — each with its own
schema boundary. Add incremental-ingestion high-water marks at the storage
layer, natural-key deduplication on writes, and an `IngestionRun` audit
record written in a separate session so it persists even when the data
session rolls back.

**Consequences:** More boundary code (Pydantic models, ORM tables, separate
sessions) and more SQL round-trips than a monolithic design. In exchange,
each layer is unit-testable in isolation, partial runs are recoverable
without manual cleanup, and re-runs against overlapping windows are
idempotent.

## Modern typed Python stack with formatting and lint enforced in CI <!-- inferred: verify accuracy -->
**Context:** A project that presents itself as "production-ready" loses
credibility when its code uses pre-Pydantic-v2 / pre-SQLAlchemy-2.0 idioms,
hides aggregation logic inside raw SQL strings the type checker cannot see,
or relies on a verbal style agreement that PRs routinely violate.

**Decision:** Adopt SQLAlchemy 2.0's `Mapped` / `mapped_column` style,
Pydantic v2 with explicit `field_validator` calls, `pydantic-settings` for
YAML config layered with environment-variable overrides, `httpx` clients
inside context managers, and SQLAlchemy Core expressions for aggregation
queries rather than raw SQL. Require every public class and function to
carry a docstring and every module to have a module docstring. Gate every
pull request on `ruff check .` and `black --check .` in CI; ruff failure
short-circuits the job and black failure blocks the merge.

**Consequences:** Higher friction on every PR — contributors must run
formatters locally and absorb the newer idioms rather than the older
equivalents they may already know. In exchange, the codebase carries a
baseline style/lint floor that survives review fatigue, aggregation queries
are type-checked, and configuration is declarative with both env and YAML
input paths.

## Detectors anchored to specific SRE failure modes, not generic statistics <!-- inferred: verify accuracy -->
**Context:** Many "alert quality" tools score every rule with a generic
anomaly model or a frequency ranking, producing findings that are
statistically defensible but operationally meaningless — "this rule fires
more than average" gives an on-call engineer no action to take. Engineers
do not act on findings that do not map to a remediation they already
recognize.

**Decision:** Encode each detector around a named, well-understood SRE
failure mode — ratio-based chronic noise, time-bucket co-firing, monotonic
threshold drift — with a corresponding priority rule that reflects the real
cost of inaction. `CHRONIC_NOISE` is always `IMMEDIATE` because alert
fatigue compounds and cannot be safely deferred; `THRESHOLD_DRIFT` is
`SHORT_TERM` because the rule is still meaningful but needs recalibration;
`CO_FIRING_CLUSTER` defaults to `SHORT_TERM` but escalates to `IMMEDIATE`
only when the pair dominates total firing volume in the window.

**Consequences:** Detector boundaries are more opinionated and less generic
than a "score every alert" approach; adding a new failure mode requires a
new detector class with its own schema and template, not a hyperparameter
change. In exchange, every finding maps to a remediation an SRE recognizes,
and the recommendation priority directly reflects operational urgency rather
than statistical extremity.
