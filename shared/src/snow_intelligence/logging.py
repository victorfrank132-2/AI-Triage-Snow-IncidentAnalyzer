"""JSON logging and EMF metrics with low-cardinality dimensions."""

from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any


def configure_logging(service_name: str) -> logging.Logger:
    logger = logging.getLogger(service_name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def log_event(logger: logging.Logger, event: str, **fields: Any) -> None:
    safe_fields = {key: value for key, value in fields.items() if "secret" not in key.lower()}
    logger.info(
        json.dumps(
            {"timestamp_ms": int(time.time() * 1000), "event": event, **safe_fields}, default=str
        )
    )


def emit_metric(
    logger: logging.Logger,
    *,
    service: str,
    metric_name: str,
    value: float,
    execution_id: str | None = None,
    stage: str | None = None,
) -> None:
    """Emit CloudWatch Embedded Metric Format without high-cardinality dimensions."""
    payload: dict[str, Any] = {
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [
                {
                    "Namespace": "ServiceNowIncidentIntelligence",
                    "Dimensions": [["Service", "Stage"]],
                    "Metrics": [{"Name": metric_name, "Unit": "Count"}],
                }
            ],
        },
        "Service": service,
        "Stage": stage or "unknown",
        metric_name: value,
    }
    if execution_id:
        payload["execution_id"] = execution_id
    logger.info(json.dumps(payload))
