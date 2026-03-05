"""USN (Update Sequence Number) Journal collector.

Reads the NTFS USN Journal to discover file creation, deletion, and
modification events that may indicate artifact tampering.
"""

from axiomtrace.collectors.base import Artifact, SystemCollector


class UsnJournalCollector(SystemCollector):

    @property
    def name(self) -> str:
        return "USN Journal Collector"

    @property
    def description(self) -> str:
        return "Collects NTFS USN Journal entries for file-system activity analysis"

    def validate_environment(self) -> bool:
        # TODO: Check for NTFS volume and required privileges
        return False

    def collect(self) -> list[Artifact]:
        # TODO: Implement USN Journal reading via Windows API
        raise NotImplementedError
