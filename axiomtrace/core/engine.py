"""Core orchestration engine.

Coordinates collector execution, feeds results into parsers, and
aggregates final validation reports.
"""

import logging
from dataclasses import dataclass, field

from axiomtrace.collectors.base import BaseCollector, Artifact
from axiomtrace.parsers.base import BaseParser, ValidationResult

log = logging.getLogger(__name__)


@dataclass
class ScanReport:
    """Aggregated results of a full integrity scan."""

    artifacts: list[Artifact] = field(default_factory=list)
    results: list[ValidationResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class AxiomEngine:
    """Main orchestrator that drives the scan pipeline."""

    def __init__(self) -> None:
        self._collectors: list[BaseCollector] = []
        self._parsers: list[BaseParser] = []

    def register_collector(self, collector: BaseCollector) -> None:
        self._collectors.append(collector)

    def register_parser(self, parser: BaseParser) -> None:
        self._parsers.append(parser)

    def run(self) -> ScanReport:
        report = ScanReport()

        # Phase 1: Collection
        for collector in self._collectors:
            if not collector.validate_environment():
                log.warning(
                    "Skipping %s: environment validation failed", collector.name
                )
                report.errors.append(
                    f"Collector '{collector.name}' skipped - prerequisites not met"
                )
                continue

            log.info("Running collector: %s", collector.name)
            try:
                artifacts = collector.collect()
                report.artifacts.extend(artifacts)
            except Exception as exc:
                log.error("Collector %s failed: %s", collector.name, exc)
                report.errors.append(f"Collector '{collector.name}' failed: {exc}")

        # Phase 2: Analysis
        for parser in self._parsers:
            log.info("Running parser: %s", type(parser).__name__)
            try:
                results = parser.analyze(report.artifacts)
                report.results.extend(results)
            except Exception as exc:
                log.error("Parser %s failed: %s", type(parser).__name__, exc)
                report.errors.append(
                    f"Parser '{type(parser).__name__}' failed: {exc}"
                )

        return report
