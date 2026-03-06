"""Process memory collectors.

Each module targets a specific process and extracts forensic artifacts
from its memory using pattern matching.
"""

from axiomtrace.collectors.system.memory.bfe import BfeMemoryCollector
from axiomtrace.collectors.system.memory.explorer import ExplorerMemoryCollector
from axiomtrace.collectors.system.memory.search_indexer import SearchIndexerMemoryCollector

__all__ = ["BfeMemoryCollector", "ExplorerMemoryCollector", "SearchIndexerMemoryCollector"]
