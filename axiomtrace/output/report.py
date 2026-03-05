"""Report output formatters."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from axiomtrace.core.engine import ScanReport


def to_dict(report: ScanReport) -> dict[str, Any]:
    """Convert a ScanReport to a serializable dictionary."""
    return {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_artifacts": len(report.artifacts),
            "total_findings": len(report.results),
            "errors": len(report.errors),
        },
        "findings": [
            {
                "source": r.artifact.source,
                "signature": r.matched_signature.id,
                "severity": r.severity.value,
                "confidence": r.confidence,
                "details": r.details,
            }
            for r in report.results
        ],
        "errors": report.errors,
    }


def to_json(report: ScanReport, indent: int = 2) -> str:
    """Render a ScanReport as formatted JSON."""
    return json.dumps(to_dict(report), indent=indent)
