"""Collector and parser registry.

Central place that knows about all available collectors and parsers.
The CLI uses this to discover what can be run.
"""

from __future__ import annotations

from axiomtrace.collectors.base import BaseCollector
from axiomtrace.collectors.system.usn_journal import UsnJournalCollector
from axiomtrace.collectors.system.prefetch import PrefetchCollector
from axiomtrace.collectors.system.memory.explorer import ExplorerMemoryCollector
from axiomtrace.collectors.system.disk import DiskCollector
from axiomtrace.collectors.specialized.minecraft.mod_scanner import ModScannerCollector
from axiomtrace.collectors.specialized.minecraft.macro_detector import MacroDetectorCollector
from axiomtrace.collectors.specialized.minecraft.process_inspector import ProcessInspectorCollector

SYSTEM_COLLECTORS: list[type[BaseCollector]] = [
    UsnJournalCollector,
    PrefetchCollector,
    ExplorerMemoryCollector,
    DiskCollector,
]

MINECRAFT_COLLECTORS: list[type[BaseCollector]] = [
    ModScannerCollector,
    MacroDetectorCollector,
    ProcessInspectorCollector,
]

ALL_COLLECTORS: list[type[BaseCollector]] = SYSTEM_COLLECTORS + MINECRAFT_COLLECTORS

# Collector groups for CLI --profile selection
PROFILES: dict[str, list[type[BaseCollector]]] = {
    "full": ALL_COLLECTORS,
    "system": SYSTEM_COLLECTORS,
    "minecraft": MINECRAFT_COLLECTORS,
}
