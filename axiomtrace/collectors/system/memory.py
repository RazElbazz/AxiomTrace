"""PcaClient memory collector.

Scans explorer.exe process memory for PcaClient TRACE log entries
to discover executable paths of previously run programs.

The PcaClient data in explorer.exe memory is ASCII text in CSV format:
    TRACE,0000,PID,PcaClient,Action,ExePath,Status[,Extra...]
"""

from __future__ import annotations

import logging
import re

from axiomtrace.collectors.base import Artifact, ArtifactSeverity, SystemCollector
from axiomtrace.utils.memory import ProcessMemoryReader
from axiomtrace.utils.process import enable_debug_privilege, find_processes_by_name

log = logging.getLogger(__name__)

TARGET_PROCESS = "explorer.exe"

# Markers to identify PcaClient data in memory
PCACLIENT_MARKERS = [b"PcaClient", b"pcaclient", b"PCACLIENT", b"pca_client"]

# Regex to match TRACE log lines in ASCII memory data
# Format: TRACE,0000,PID,PcaClient,Action,ExePath,Status[,Extra...]
_TRACE_LINE_RE = re.compile(
    rb"TRACE,\d{4},\d+,PcaClient,[^,\r\n]+,([^\r\n]+)"
)


class PcaClientMemoryCollector(SystemCollector):

    @property
    def name(self) -> str:
        return "PcaClient Memory Collector"

    @property
    def description(self) -> str:
        return "Extracts executed program paths from explorer.exe PcaClient memory"

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
                    regions = reader.read_regions()

                    # Fast pass: check raw bytes for any PcaClient marker
                    found = False
                    for needle in PCACLIENT_MARKERS:
                        if reader.regions_contain(regions, needle):
                            found = True
                            break
                    if not found:
                        continue

                    log.info(
                        "Found PcaClient markers in %s PID %d",
                        TARGET_PROCESS,
                        proc.pid,
                    )

                    # Extract TRACE lines from ASCII data in memory
                    seen: set[str] = set()
                    for region in regions:
                        for match in _TRACE_LINE_RE.finditer(region.data):
                            try:
                                full_line = match.group().decode("ascii", errors="replace")
                                tail = match.group(1).decode("ascii", errors="replace")
                            except Exception:
                                continue

                            # tail = "ExePath,Status[,Extra...]"
                            parts = tail.split(",")
                            exe_path = parts[0].strip()
                            status = parts[1].strip() if len(parts) > 1 else ""

                            # Parse action from the full line
                            line_parts = full_line.split(",")
                            action = line_parts[4] if len(line_parts) > 4 else ""
                            trace_pid = line_parts[2] if len(line_parts) > 2 else ""

                            normalized = exe_path.lower()
                            if normalized in seen:
                                continue
                            seen.add(normalized)

                            artifacts.append(
                                Artifact(
                                    source=f"PcaClient ({TARGET_PROCESS} PID {proc.pid})",
                                    category="execution_history",
                                    description=f"Program execution trace: {exe_path}",
                                    severity=ArtifactSeverity.INFO,
                                    metadata={
                                        "exe_path": exe_path,
                                        "action": action,
                                        "status": status,
                                        "trace_pid": trace_pid,
                                        "explorer_pid": proc.pid,
                                        "memory_address": hex(
                                            region.base_address + match.start()
                                        ),
                                    },
                                )
                            )

                    log.info(
                        "Collected %d unique executable paths from PID %d",
                        len(seen),
                        proc.pid,
                    )

                finally:
                    reader.close()

            except Exception as exc:
                log.debug(
                    "Failed to read %s PID %d: %s", TARGET_PROCESS, proc.pid, exc
                )

        return artifacts


if __name__ == "__main__":
    from axiomtrace.utils.logging import setup_logging
    from axiomtrace.utils.memory import ProcessMemoryReader

    setup_logging(logging.DEBUG)

    if not enable_debug_privilege():
        print("Failed to enable SeDebugPrivilege. Are you running as admin?")
        raise SystemExit(1)

    procs = find_processes_by_name(TARGET_PROCESS)
    print(f"Found {len(procs)} {TARGET_PROCESS} process(es)")

    for proc in procs:
        reader = ProcessMemoryReader(proc.pid)
        if not reader.open():
            print(f"  PID {proc.pid}: cannot open")
            continue
        try:
            regions = reader.read_regions()
            print(f"  PID {proc.pid}: {len(regions)} regions read")

            # Search for PcaClient markers and dump surrounding ASCII text
            for needle in PCACLIENT_MARKERS:
                for region in regions:
                    idx = region.data.find(needle)
                    while idx != -1:
                        # Find the start/end of the text block around the hit
                        start = max(0, idx - 500)
                        end = min(len(region.data), idx + len(needle) + 4000)
                        chunk = region.data[start:end]

                        # Decode as ASCII (the PcaClient data is plain ASCII)
                        text = chunk.decode("ascii", errors="replace")

                        print(f"\n--- Hit at {hex(region.base_address + idx)} (needle: {needle!r}) ---")
                        # Print each non-empty line
                        for line in text.splitlines():
                            stripped = line.strip()
                            if stripped and "TRACE" in stripped:
                                print(stripped)
                        print("---")

                        idx = region.data.find(needle, idx + len(needle))

            # Also run the TRACE regex to show parsed results
            print(f"\n{'='*60}")
            print(f"Parsed TRACE entries from PID {proc.pid}:")
            print(f"{'='*60}")
            seen: set[str] = set()
            for region in regions:
                for match in _TRACE_LINE_RE.finditer(region.data):
                    try:
                        line = match.group().decode("ascii", errors="replace")
                    except Exception:
                        continue
                    if line.lower() in seen:
                        continue
                    seen.add(line.lower())
                    print(line)
            print(f"\nTotal unique TRACE entries: {len(seen)}")

        finally:
            reader.close()
