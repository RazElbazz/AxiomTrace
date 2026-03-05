"""Minecraft mod directory scanner.

Enumerates and fingerprints files in Minecraft mod directories to
identify unauthorized modifications, known cheat clients, or
tampered mod files.
"""

from __future__ import annotations

from axiomtrace.collectors.base import Artifact, SpecializedCollector


class ModScannerCollector(SpecializedCollector):

    @property
    def name(self) -> str:
        return "Minecraft Mod Scanner"

    @property
    def target_application(self) -> str:
        return "Minecraft: Java Edition"

    @property
    def description(self) -> str:
        return "Scans Minecraft mod directories for unauthorized modifications"

    def validate_environment(self) -> bool:
        # TODO: Locate .minecraft directory
        return False

    def collect(self) -> list[Artifact]:
        # TODO: Walk mod dirs, hash JARs, compare against signatures
        raise NotImplementedError
