"""HTTP client for the Alertmanager REST API v2."""

from __future__ import annotations

from typing import Any

import httpx


class AlertmanagerClient:
    """Client for the Alertmanager ``/api/v2/alerts`` endpoint.

    Prometheus and Alertmanager hold complementary but distinct views of the
    same alert lifecycle.

    **What Prometheus knows**: Prometheus evaluates every alerting rule on a
    fixed interval.  When a PromQL expression returns a non-empty result for at
    least the configured ``for`` duration, Prometheus records a firing event and
    sends the alert to Alertmanager.  Prometheus does not know whether the alert
    was acknowledged, silenced, or routed to a useful notification channel.

    **What Alertmanager knows**: Alertmanager receives the raw alert stream from
    Prometheus and applies grouping, de-duplication, silencing, and inhibition
    before routing alerts to receivers.  Its API exposes the full history of
    what happened to each alert *after* Prometheus fired it — including whether
    it was suppressed by a silence rule and which receiver saw it.

    Querying both sources together gives a more complete picture than either
    alone.  Prometheus provides the ground truth about rule evaluation
    (``did this condition occur?``), while Alertmanager provides the operational
    context (``did anyone actually see it, and was it actionable?``).  The
    distinction matters for hygiene analysis: a chronically firing alert that is
    always silenced is a different problem from one that floods on-call rotations.
    """

    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self._client = httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout)

    def fetch_alerts(
        self,
        active: bool = False,
        silenced: bool = True,
        inhibited: bool = True,
    ) -> list[dict[str, Any]]:
        """Return alerts from ``/api/v2/alerts``.

        Response shape (a bare JSON array, not wrapped in an envelope)::

            [
              {
                "labels":      {"alertname": "<name>", "<key>": "<value>", ...},
                "annotations": {"summary": "...", "description": "...", ...},
                "startsAt":    "<rfc3339>",
                "endsAt":      "<rfc3339>",
                "status": {
                  "state":       "active | suppressed | unprocessed",
                  "silencedBy":  ["<silence_id>", ...],   # empty if not silenced
                  "inhibitedBy": ["<source_alert_name>", ...]
                },
                "receivers": [{"name": "<receiver_name>"}],
                "fingerprint": "<hex_string>"   # hash of the label set
              },
              ...
            ]

        By default both silenced and inhibited alerts are requested so that the
        auditor can distinguish true noise (alert reached a receiver) from
        suppressed noise (alert was silenced before reaching a receiver), which
        are different hygiene failure modes requiring different remediation.

        Args:
            active:   Include only currently active (non-resolved) alerts.
            silenced: Include alerts that matched a silence rule.
            inhibited: Include alerts that were inhibited by another alert.
        """
        response = self._client.get(
            "/api/v2/alerts",
            params={
                "active": str(active).lower(),
                "silenced": str(silenced).lower(),
                "inhibited": str(inhibited).lower(),
            },
        )
        response.raise_for_status()
        # Unlike Prometheus, Alertmanager returns a bare JSON array with no envelope.
        return response.json()  # type: ignore[no-any-return]

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> AlertmanagerClient:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
