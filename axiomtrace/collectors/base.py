"""Abstract base classes for the collector system."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ArtifactSeverity(Enum):
    """Classification level for discovered artifacts."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Artifact:
    """A single forensic artifact discovered during collection."""

    source: str
    category: str
    description: str
    severity: ArtifactSeverity = ArtifactSeverity.INFO
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: dict[str, Any] = field(default_factory=dict)
    raw_data: bytes | None = None


class BaseCollector(ABC):
    """Abstract base class for all artifact collectors.

    Every collector must implement `collect()` which gathers raw data,
    and `validate()` which checks whether the collector can run on the
    current system.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of this collector."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Brief description of what this collector gathers."""

    @abstractmethod
    def validate_environment(self) -> bool:
        """Check whether this collector can run in the current environment.

        Returns True if all prerequisites (permissions, OS, files) are met.
        """

    @abstractmethod
    def collect(self) -> list[Artifact]:
        """Execute the collection and return discovered artifacts."""


class SystemCollector(BaseCollector):
    """Base class for OS-level artifact collectors (USN, Prefetch, etc.)."""

    @property
    def category(self) -> str:
        return "system"


class SpecializedCollector(BaseCollector):
    """Base class for application-specific artifact collectors."""

    @property
    @abstractmethod
    def target_application(self) -> str:
        """The application this collector targets."""
