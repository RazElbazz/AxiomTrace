"""Process memory collectors.

Each module targets a specific process and extracts forensic artifacts
from its memory using pattern matching.
"""

from axiomtrace.collectors.system.memory.explorer import ExplorerMemoryCollector

__all__ = ["ExplorerMemoryCollector"]
