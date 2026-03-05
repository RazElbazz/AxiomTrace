"""Base parser interface.

Parsers contain the analysis *logic* - they take collected artifacts
and match them against signatures to produce validation results.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from axiomtrace.collectors.base import Artifact, ArtifactSeverity
from axiomtrace.signatures.base import Signature


@dataclass
class ValidationResult:
    """The outcome of matching an artifact against a signature."""

    artifact: Artifact
    matched_signature: Signature
    confidence: float  # 0.0 - 1.0
    severity: ArtifactSeverity
    details: str


class BaseParser(ABC):
    """Abstract base for all parsers."""

    @abstractmethod
    def analyze(self, artifacts: list[Artifact]) -> list[ValidationResult]:
        """Analyze collected artifacts and return validation results."""
