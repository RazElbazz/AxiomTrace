"""SearchIndexer.exe memory collector.

Scans SearchIndexer.exe process memory for:
  - file: URIs (indexed file references)
"""

from __future__ import annotations

import logging
import re
from typing import List

from axiomtrace.collectors.base import Artifact, SystemCollector
from axiomtrace.utils.memory import MemoryRegion, ProcessMemoryReader
from axiomtrace.utils.process import enable_debug_privilege, find_processes_by_name

log = logging.getLogger(__name__)

TARGET_PROCESS = "SearchIndexer.exe"

# --- file: patterns (ASCII + UTF-16LE) ---
_FILE_URI_ASCII_RE = re.compile(rb'file:([^\x00"\'<>\s]{3,})')
_FILE_URI_WIDE_RE = re.compile(
    rb"f\x00i\x00l\x00e\x00:\x00((?:[ -~]\x00){3,})"
)
_FILE_NEEDLE = b"file:"
_FILE_WIDE_NEEDLE = "file:".encode("utf-16-le")

_SCANS: list[tuple[list[bytes], object, bool]] = []  # populated after functions


def _extract_file_uris(region: MemoryRegion, pid: int, seen: set[str]) -> List[Artifact]:
    """Extract file: URIs (ASCII + UTF-16LE)."""
    artifacts: List[Artifact] = []
    data = region.data

    for match in _FILE_URI_ASCII_RE.finditer(data):
        try:
            uri_path = match.group(1).decode("ascii", errors="replace")
        except Exception:
            continue
        _add_file_uri(artifacts, uri_path, match.group().decode("ascii", errors="replace"), seen)

    for match in _FILE_URI_WIDE_RE.finditer(data):
        try:
            uri_path = match.group(1).decode("utf-16-le", errors="replace")
        except Exception:
            continue
        _add_file_uri(artifacts, uri_path, match.group().decode("utf-16-le", errors="replace"), seen)

    return artifacts


def _add_file_uri(
    artifacts: List[Artifact],
    uri_path: str,
    raw: str,
    seen: set[str],
) -> None:
    normalized = uri_path.lower()
    if normalized in seen:
        return
    seen.add(normalized)

    # Convert forward slashes to backslashes for path display
    file_path = uri_path.replace("/", "\\")
    # Strip leading slashes (file:///C:/... -> C:\...)
    while file_path.startswith("\\"):
        file_path = file_path[1:]

    artifacts.append(
        Artifact(
            source="SearchIndexer.exe:file:",
            category="file_access",
            description=f"Indexed file: {file_path}",
            metadata={
                "name": file_path.rsplit("\\", 1)[-1] if "\\" in file_path else file_path,
                "path": file_path,
                "raw": raw,
            },
        )
    )


_SCANS = [
    ([_FILE_NEEDLE, _FILE_WIDE_NEEDLE], _extract_file_uris, False),
]


class SearchIndexerMemoryCollector(SystemCollector):

    @property
    def name(self) -> str:
        return "SearchIndexer Memory Collector"

    @property
    def description(self) -> str:
        return "Scans SearchIndexer.exe memory for indexed file references"

    def validate_environment(self) -> bool:
        if not enable_debug_privilege():
            log.warning("Could not enable SeDebugPrivilege")
            return False
        procs = find_processes_by_name(TARGET_PROCESS)
        if not procs:
            log.warning("No %s processes found", TARGET_PROCESS)
            return False
        return True

    def collect(self) -> list[Artifact]:
        artifacts: list[Artifact] = []
        procs = find_processes_by_name(TARGET_PROCESS)

        for proc in procs:
            try:
                reader = ProcessMemoryReader(proc.pid)
                if not reader.open():
                    continue

                try:
                    seen_sets: list[set[str]] = [set() for _ in _SCANS]

                    for region in reader.iter_regions_pipelined(skip_images=False):
                        for idx, (needles, extractor, _) in enumerate(_SCANS):
                            if any(n in region.data for n in needles):
                                found = extractor(region, proc.pid, seen_sets[idx])
                                if found:
                                    artifacts.extend(found)

                finally:
                    reader.close()

            except Exception as exc:
                log.debug("Failed to read %s PID %d: %s", TARGET_PROCESS, proc.pid, exc)

        return artifacts


if __name__ == "__main__":
    import json
    import sys
    import time

    from axiomtrace.utils.logging import setup_logging

    setup_logging(logging.DEBUG)

    log_file = open("temp.log", "w", encoding="utf-8")
    _orig_print = print

    def print(*args, **kwargs):  # type: ignore[misc]
        kwargs.setdefault("file", log_file)
        _orig_print(*args, **kwargs)
        log_file.flush()
        _orig_print(*args, file=sys.stdout)

    t_start = time.perf_counter()

    if not enable_debug_privilege():
        print("Failed to enable SeDebugPrivilege. Are you running as admin?")
        raise SystemExit(1)

    procs = find_processes_by_name(TARGET_PROCESS)
    print(f"Found {len(procs)} {TARGET_PROCESS} process(es)")

    labels = ["file:"]
    all_artifacts: list[Artifact] = []

    for proc in procs:
        reader = ProcessMemoryReader(proc.pid)
        if not reader.open():
            print(f"  PID {proc.pid}: cannot open")
            continue
        try:
            seen_sets: list[set[str]] = [set() for _ in _SCANS]
            regions_scanned = 0

            all_found: list[list[Artifact]] = [[] for _ in _SCANS]

            for region in reader.iter_regions_pipelined(skip_images=False):
                regions_scanned += 1
                for idx, (needles, extractor, _) in enumerate(_SCANS):
                    if any(n in region.data for n in needles):
                        found = extractor(region, proc.pid, seen_sets[idx])
                        if found:
                            all_found[idx].extend(found)

            elapsed = time.perf_counter() - t_start
            print(f"Scanned {regions_scanned} regions in {elapsed:.2f}s\n")

            for idx, label in enumerate(labels):
                if not all_found[idx]:
                    continue
                print(f"--- {TARGET_PROCESS}:{label} ({len(all_found[idx])} results) ---")
                for a in all_found[idx]:
                    key = a.metadata.get("name") or ""
                    print(f"  {TARGET_PROCESS}:{label} == {key}")
                print()
                all_artifacts.extend(all_found[idx])

        finally:
            reader.close()

    # Write all artifacts as JSON
    json_out = []
    for a in all_artifacts:
        json_out.append({
            "source": a.source,
            "category": a.category,
            "description": a.description,
            "metadata": a.metadata,
        })
    with open("temp.json", "w", encoding="utf-8") as f:
        json.dump(json_out, f, indent=2, ensure_ascii=False)
    print(f"Wrote {len(json_out)} artifacts to temp.json")

    log_file.close()
