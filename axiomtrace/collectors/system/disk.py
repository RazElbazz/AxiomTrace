"""Disk artifact collector.

Scans disk-level metadata including MFT records, alternate data streams,
and filesystem timestamps for evidence of artifact manipulation.
"""

from axiomtrace.collectors.base import Artifact, SystemCollector


class DiskCollector(SystemCollector):

    @property
    def name(self) -> str:
        return "Disk Artifact Collector"

    @property
    def description(self) -> str:
        return "Collects disk-level metadata and filesystem artifacts"

    def validate_environment(self) -> bool:
        # TODO: Verify raw disk read access
        return False

    def collect(self) -> list[Artifact]:
        # TODO: Read MFT, ADS, and timestamp data
        raise NotImplementedError
