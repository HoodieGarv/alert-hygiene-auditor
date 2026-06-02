"""HTTP client for the Prometheus API."""

from __future__ import annotations

import math
from datetime import datetime
from typing import Any

import httpx


class PrometheusClient:
    """Client for two Prometheus HTTP API endpoints.

    /api/v1/rules
        Returns the current set of alerting rule definitions — their PromQL
        expressions, label sets, annotations, evaluation health, and the list
        of alert instances that are *currently* active.  This endpoint gives a
        complete inventory of what rules exist and their present evaluation
        state.  It does not contain any historical data: rules that fired
        yesterday and are now resolved will not appear.

    /api/v1/query_range (querying the synthetic ``ALERTS`` metric)
        ``ALERTS`` is a special time series that Prometheus writes on every
        evaluation cycle to record the state of every alerting rule at that
        instant.  Querying it over a time range with ``query_range`` produces a
        matrix of samples showing exactly when each alert label set was in the
        ``firing`` state.  This is the primary source of historical firing
        data used by the auditor's noise and drift analyses.

    Both endpoints are necessary: ``/rules`` supplies the full rule inventory
    and metadata (useful for detecting rules that *never* fire), while
    ``query_range`` supplies the actual firing record (necessary for counting
    firing frequency, detecting co-firing patterns, and measuring threshold
    drift over time).
    """

    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self._client = httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout)

    def fetch_rules(self) -> list[dict[str, Any]]:
        """Return all alerting rule groups from ``/api/v1/rules``.

        Response envelope shape::

            {
              "status": "success",
              "data": {
                "groups": [
                  {
                    "name": "<group_name>",
                    "rules": [
                      {
                        "type": "alerting",
                        "name": "<alert_name>",
                        "query": "<promql_expr>",
                        "duration": <for_seconds>,
                        "labels": {...},
                        "annotations": {...},
                        "alerts": [          # currently active instances
                          {"labels": {...}, "annotations": {...},
                           "state": "firing|pending",
                           "activeAt": "<rfc3339>", "value": "1"}
                        ],
                        "health": "ok|err|unknown",
                        "lastError": "",
                        "lastEvaluation": "<rfc3339>",
                        "evaluationTime": 0.001
                      }
                    ]
                  }
                ]
              }
            }

        Returns the ``groups`` list directly, unwrapping the outer envelope.
        """
        response = self._client.get("/api/v1/rules", params={"type": "alert"})
        response.raise_for_status()
        # Unwrap the standard Prometheus success envelope {"status":"success","data":{...}}
        return response.json()["data"]["groups"]  # type: ignore[no-any-return]

    def fetch_alert_history(
        self,
        start: datetime,
        end: datetime,
        step: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return ``ALERTS`` time-series data over [start, end].

        Response envelope shape::

            {
              "status": "success",
              "data": {
                "resultType": "matrix",
                "result": [
                  {
                    "metric": {
                      "__name__": "ALERTS",
                      "alertname": "<name>",
                      "alertstate": "firing",
                      "<label_key>": "<label_value>",
                      ...
                    },
                    "values": [
                      [<unix_timestamp_float>, "1"],
                      ...
                    ]
                  }
                ]
              }
            }

        Each element in ``result`` represents one unique combination of alert
        labels.  The ``values`` list contains one ``[timestamp, "1"]`` pair per
        evaluation cycle where that label set was in the queried state.  Gaps
        between consecutive timestamps indicate the alert resolved and re-fired.

        If ``step`` is omitted, it is computed automatically to keep the number
        of data points under 10,000 — Prometheus rejects queries that produce
        more than ~11,000 steps with a 400 error.  The step is clamped to a
        minimum of 15s (the default evaluation interval) so short windows still
        capture every evaluation cycle.
        """
        if step is None:
            range_seconds = (end - start).total_seconds()
            step_seconds = max(15, math.ceil(range_seconds / 10_000))
            step = f"{step_seconds}s"

        response = self._client.get(
            "/api/v1/query_range",
            params={
                "query": 'ALERTS{alertstate="firing"}',
                # Prometheus accepts Unix epoch floats for start and end.
                "start": start.timestamp(),
                "end": end.timestamp(),
                "step": step,
            },
        )
        response.raise_for_status()
        # Unwrap: {"status":"success","data":{"resultType":"matrix","result":[...]}}
        return response.json()["data"]["result"]  # type: ignore[no-any-return]

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> PrometheusClient:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
