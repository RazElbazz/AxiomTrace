"""BFE (Base Filtering Engine) memory collector.

Scans the svchost.exe process hosting the BFE service for Windows Firewall
filter entries. These reveal which applications triggered firewall prompts.

Patterns searched:
  - "TCP Query user" / "UDP Query user" filter entries
"""

from __future__ import annotations

import logging
import re
from typing import List

from axiomtrace.collectors.base import Artifact, SystemCollector
from axiomtrace.utils.memory import MemoryRegion, ProcessMemoryReader
from axiomtrace.utils.process import enable_debug_privilege, get_service_pid

log = logging.getLogger(__name__)

SERVICE_NAME = "BFE"

# --- Firewall filter patterns (ASCII + UTF-16LE) ---
# Format: "TCP Query User{GUID}C:\path\to\app.exe" (no separators, UTF-16LE)
_FILTER_ASCII_RE = re.compile(
    rb"((?:TCP|UDP) Query User)(\{[0-9A-Fa-f\-]+\})([A-Za-z]:[^\x00\r\n]{3,})"
)
_FILTER_WIDE_RE = re.compile(
    rb"((?:T\x00C\x00P\x00|U\x00D\x00P\x00) \x00Q\x00u\x00e\x00r\x00y\x00 \x00"
    rb"U\x00s\x00e\x00r\x00)"
    rb"(\{\x00(?:[ -~]\x00){36}\}\x00)"
    rb"([A-Za-z]\x00:\x00(?:[ -~]\x00){3,})"
)

_NEEDLE_TCP = b"TCP Query User"
_NEEDLE_UDP = b"UDP Query User"
_NEEDLE_TCP_WIDE = "TCP Query User".encode("utf-16-le")
_NEEDLE_UDP_WIDE = "UDP Query User".encode("utf-16-le")


def _extract_filters(region: MemoryRegion, pid: int, seen: set[str]) -> List[Artifact]:
    """Extract TCP/UDP Query user firewall filter entries."""
    artifacts: List[Artifact] = []
    data = region.data

    for match in _FILTER_ASCII_RE.finditer(data):
        try:
            protocol = match.group(1).decode("ascii", errors="replace")
            guid = match.group(2).decode("ascii", errors="replace")
            app_path = match.group(3).decode("ascii", errors="replace")
            raw = match.group().decode("ascii", errors="replace")
        except Exception:
            continue
        _add_filter(artifacts, protocol, guid, app_path, raw, seen)

    for match in _FILTER_WIDE_RE.finditer(data):
        try:
            protocol = match.group(1).decode("utf-16-le", errors="replace")
            guid = match.group(2).decode("utf-16-le", errors="replace")
            app_path = match.group(3).decode("utf-16-le", errors="replace")
            raw = match.group().decode("utf-16-le", errors="replace")
        except Exception:
            continue
        _add_filter(artifacts, protocol, guid, app_path, raw, seen)

    return artifacts


def _add_filter(
    artifacts: List[Artifact],
    protocol: str,
    guid: str,
    app_path: str,
    raw: str,
    seen: set[str],
) -> None:
    normalized = f"{protocol}:{app_path}".lower()
    if normalized in seen:
        return
    seen.add(normalized)

    name = app_path.rsplit("\\", 1)[-1] if "\\" in app_path else app_path

    artifacts.append(
        Artifact(
            source="BFE:firewall_filter",
            category="network_activity",
            description=f"{protocol}: {app_path}",
            metadata={
                "name": name,
                "path": app_path,
                "raw": raw,
            },
        )
    )


_SCANS: list[tuple[list[bytes], object, bool]] = [
    (
        [_NEEDLE_TCP, _NEEDLE_UDP, _NEEDLE_TCP_WIDE, _NEEDLE_UDP_WIDE],
        _extract_filters,
        False,
    ),
]


class BfeMemoryCollector(SystemCollector):

    @property
    def name(self) -> str:
        return "BFE Memory Collector"

    @property
    def description(self) -> str:
        return "Scans BFE service memory for firewall filter entries (TCP/UDP Query user)"

    def validate_environment(self) -> bool:
        if not enable_debug_privilege():
            log.warning("Could not enable SeDebugPrivilege")
            return False
        pid = get_service_pid(SERVICE_NAME)
        if pid is None:
            log.warning("BFE service not running")
            return False
        return True

    def collect(self) -> list[Artifact]:
        artifacts: list[Artifact] = []
        pid = get_service_pid(SERVICE_NAME)
        if pid is None:
            return artifacts

        try:
            reader = ProcessMemoryReader(pid)
            if not reader.open():
                return artifacts

            try:
                seen_sets: list[set[str]] = [set() for _ in _SCANS]

                for region in reader.iter_regions_pipelined(skip_images=False):
                    for idx, (needles, extractor, _) in enumerate(_SCANS):
                        if any(n in region.data for n in needles):
                            found = extractor(region, pid, seen_sets[idx])
                            if found:
                                artifacts.extend(found)

            finally:
                reader.close()

        except Exception as exc:
            log.debug("Failed to read BFE (PID %d): %s", pid, exc)

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

    pid = get_service_pid(SERVICE_NAME)
    if pid is None:
        print("BFE service not running")
        raise SystemExit(1)

    print(f"BFE service PID: {pid}")

    labels = ["firewall_filter"]
    all_artifacts: list[Artifact] = []

    reader = ProcessMemoryReader(pid)
    if not reader.open():
        print(f"  PID {pid}: cannot open")
        raise SystemExit(1)

    try:
        seen_sets: list[set[str]] = [set() for _ in _SCANS]
        regions_scanned = 0
        all_found: list[list[Artifact]] = [[] for _ in _SCANS]

        for region in reader.iter_regions_pipelined(skip_images=False):
            regions_scanned += 1

            # Diagnostic: dump raw context around any needle hit
            for needle in [_NEEDLE_TCP, _NEEDLE_UDP, _NEEDLE_TCP_WIDE, _NEEDLE_UDP_WIDE]:
                pos = 0
                while True:
                    idx2 = region.data.find(needle, pos)
                    if idx2 == -1:
                        break
                    # Grab 200 bytes around the hit
                    start = max(0, idx2 - 20)
                    end = min(len(region.data), idx2 + 200)
                    chunk = region.data[start:end]
                    addr = hex(region.base_address + idx2)
                    # Try ASCII decode
                    try:
                        text = chunk.decode("ascii", errors="replace")
                    except Exception:
                        text = repr(chunk[:100])
                    # Also try UTF-16LE
                    try:
                        wide_text = chunk.decode("utf-16-le", errors="replace")
                    except Exception:
                        wide_text = ""
                    print(f"\n  [HIT at {addr}] needle={needle[:20]}")
                    print(f"    ASCII: {text!r}")
                    if wide_text:
                        print(f"    WIDE:  {wide_text!r}")
                    pos = idx2 + len(needle)

            for idx, (needles, extractor, _) in enumerate(_SCANS):
                if any(n in region.data for n in needles):
                    found = extractor(region, pid, seen_sets[idx])
                    if found:
                        all_found[idx].extend(found)

        elapsed = time.perf_counter() - t_start
        print(f"Scanned {regions_scanned} regions in {elapsed:.2f}s\n")

        for idx, label in enumerate(labels):
            if not all_found[idx]:
                continue
            print(f"--- BFE:{label} ({len(all_found[idx])} results) ---")
            for a in all_found[idx]:
                print(f"  BFE:{label} == {a.description}")
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
