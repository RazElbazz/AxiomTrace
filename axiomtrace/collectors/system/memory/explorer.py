"""Explorer.exe memory collector.

Scans explorer.exe process memory for:
  - PcaClient TRACE entries (execution history)
  - file:/// URIs (recently accessed files)
  - {"displayText" JSON blobs (shell activity / recent items)
  - \\Users\\...\\*.exe / *.jar paths (user executables)
"""

from __future__ import annotations

import logging
import re
from typing import List

from axiomtrace.collectors.base import Artifact, SystemCollector
from axiomtrace.utils.memory import MemoryRegion, ProcessMemoryReader
from axiomtrace.utils.process import enable_debug_privilege, find_processes_by_name

log = logging.getLogger(__name__)

TARGET_PROCESS = "explorer.exe"

# --- PcaClient patterns (ASCII) ---
_TRACE_LINE_RE = re.compile(
    rb"TRACE,\d{4},\d+,PcaClient,[^,\r\n]+,([^\r\n]+)"
)

# --- file:/// patterns (ASCII + UTF-16LE) ---
_FILE_URI_ASCII_RE = re.compile(rb'file:///([^\x00"\'<>\s]{3,})')
_FILE_URI_WIDE_RE = re.compile(
    rb"f\x00i\x00l\x00e\x00:\x00/\x00/\x00/\x00((?:[ -~]\x00){3,})"
)

# --- User exe/jar patterns (ASCII + UTF-16LE) ---
_USER_EXE_ASCII_RE = re.compile(
    rb"[A-Za-z]:\\[Uu]sers\\[^\x00\r\n]{2,}\.[Ee][Xx][Ee]"
    rb"|[A-Za-z]:\\[Uu]sers\\[^\x00\r\n]{2,}\.[Jj][Aa][Rr]"
)
_USER_EXE_WIDE_RE = re.compile(
    rb"[A-Za-z]\x00:\x00\\\x00[Uu]\x00s\x00e\x00r\x00s\x00\\\x00"
    rb"(?:[ -~]\x00){2,}\.\x00[Ee]\x00[Xx]\x00[Ee]\x00"
    rb"|[A-Za-z]\x00:\x00\\\x00[Uu]\x00s\x00e\x00r\x00s\x00\\\x00"
    rb"(?:[ -~]\x00){2,}\.\x00[Jj]\x00[Aa]\x00[Rr]\x00"
)

# --- {"displayText" JSON blobs ---
_DISPLAY_TEXT_NEEDLE = b'{"displayText"'
_DISPLAY_TEXT_WIDE_NEEDLE = '{"displayText"'.encode("utf-16-le")
# Field extractors for the raw blob (ASCII)
_DT_FIELD_RES = {
    "displayText": re.compile(rb'"displayText"\s*:\s*"([^"]*)"'),
    "appDisplayName": re.compile(rb'"appDisplayName"\s*:\s*"([^"]*)"'),
    "description": re.compile(rb'"description"\s*:\s*"([^"]*)"'),
    "contentUri": re.compile(rb'"contentUri"\s*:\s*"([^"]*)"'),
    "backgroundColor": re.compile(rb'"backgroundColor"\s*:\s*"([^"]*)"'),
    "activationUri": re.compile(rb'"activationUri"\s*:\s*"([^"]*)"'),
}

# Wide needle for file:/// (UTF-16LE)
_FILE_URI_WIDE_NEEDLE = "file:///".encode("utf-16-le")


def _extract_pcaclient(region: MemoryRegion, pid: int, seen: set[str]) -> List[Artifact]:
    """Extract PcaClient TRACE execution entries."""
    artifacts: List[Artifact] = []
    for match in _TRACE_LINE_RE.finditer(region.data):
        try:
            full_line = match.group().decode("ascii", errors="replace")
            tail = match.group(1).decode("ascii", errors="replace")
        except Exception:
            continue

        parts = tail.split(",")
        exe_path = parts[0].strip()
        status = parts[1].strip() if len(parts) > 1 else ""

        line_parts = full_line.split(",")
        action = line_parts[4] if len(line_parts) > 4 else ""
        trace_pid = line_parts[2] if len(line_parts) > 2 else ""

        dedup_key = f"{exe_path.lower()}:{trace_pid}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        artifacts.append(
            Artifact(
                source=f"explorer.exe:PcaClient",
                category="execution_history",
                description=f"Program execution trace: {exe_path}",
                metadata={
                    "name": exe_path,
                    "path": exe_path,
                    "raw": full_line,
                },
            )
        )
    return artifacts


def _extract_recent_files(region: MemoryRegion, pid: int, seen: set[str]) -> List[Artifact]:
    """Extract file:/// URIs (ASCII + UTF-16LE) with optional displayText."""
    artifacts: List[Artifact] = []
    data = region.data

    # ASCII file:/// URIs
    for match in _FILE_URI_ASCII_RE.finditer(data):
        try:
            uri_path = match.group(1).decode("ascii", errors="replace")
        except Exception:
            continue
        _add_file_uri(artifacts, uri_path, seen)

    # UTF-16LE file:/// URIs
    for match in _FILE_URI_WIDE_RE.finditer(data):
        try:
            uri_path = match.group(1).decode("utf-16-le", errors="replace")
        except Exception:
            continue
        _add_file_uri(artifacts, uri_path, seen)

    return artifacts


def _add_file_uri(
    artifacts: List[Artifact],
    uri_path: str,
    seen: set[str],
) -> None:
    normalized = uri_path.lower()
    if normalized in seen:
        return
    seen.add(normalized)

    file_path = uri_path.replace("/", "\\")
    raw_uri = f"file:///{uri_path}"

    artifacts.append(
        Artifact(
            source="explorer.exe:file:///",
            category="file_access",
            description=f"Recently accessed file: {file_path}",
            metadata={
                "name": file_path.rsplit("\\", 1)[-1] if "\\" in file_path else file_path,
                "path": file_path,
                "raw": raw_uri,
            },
        )
    )


def _extract_user_exes(region: MemoryRegion, pid: int, seen: set[str]) -> List[Artifact]:
    """Extract \\Users\\...\\*.exe / *.jar paths."""
    artifacts: List[Artifact] = []

    for match in _USER_EXE_ASCII_RE.finditer(region.data):
        try:
            path = match.group().decode("ascii", errors="replace")
        except Exception:
            continue
        _add_user_exe(artifacts, path, seen)

    for match in _USER_EXE_WIDE_RE.finditer(region.data):
        try:
            path = match.group().decode("utf-16-le", errors="replace")
        except Exception:
            continue
        _add_user_exe(artifacts, path, seen)

    return artifacts


def _add_user_exe(
    artifacts: List[Artifact],
    path: str,
    seen: set[str],
) -> None:
    normalized = path.strip().lower()
    if normalized in seen:
        return
    seen.add(normalized)
    artifacts.append(
        Artifact(
            source="explorer.exe:\\Users\\",
            category="execution_history",
            description=f"User executable path: {path}",
            metadata={
                "name": path.rsplit("\\", 1)[-1] if "\\" in path else path,
                "path": path,
                "raw": path,
            },
        )
    )


def _find_json_end(data: bytes, start: int) -> int:
    """Find the closing '}' of a JSON object starting at data[start] == '{'."""
    depth = 0
    i = start
    end = min(start + 2048, len(data))
    while i < end:
        ch = data[i]
        if ch == ord(b'"'):
            # skip string contents
            i += 1
            while i < end and data[i] != ord(b'"'):
                if data[i] == ord(b'\\'):
                    i += 1  # skip escaped char
                i += 1
        elif ch == ord(b'{'):
            depth += 1
        elif ch == ord(b'}'):
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _extract_display_text(region: MemoryRegion, pid: int, seen: set[str]) -> List[Artifact]:
    """Extract {"displayText" JSON blobs (shell activity / recent items)."""
    artifacts: List[Artifact] = []
    data = region.data

    # Search for ASCII needle positions
    needle = b'{"displayText"'
    pos = 0
    while True:
        idx = data.find(needle, pos)
        if idx == -1:
            break
        end = _find_json_end(data, idx)
        if end == -1:
            pos = idx + len(needle)
            continue
        raw = data[idx:end + 1]
        _add_display_text_blob(artifacts, raw, seen)
        pos = end + 1

    return artifacts


def _add_display_text_blob(
    artifacts: List[Artifact],
    raw: bytes,
    seen: set[str],
) -> None:
    # Parse fields from the raw JSON blob
    fields: dict[str, str] = {}
    for name, pattern in _DT_FIELD_RES.items():
        m = pattern.search(raw)
        if m:
            fields[name] = m.group(1).decode("utf-8", errors="replace")

    display_text = fields.get("displayText", "")
    if not display_text:
        return

    normalized = display_text.strip().lower()
    if normalized in seen:
        return
    seen.add(normalized)

    raw_str = raw.decode("utf-8", errors="replace")

    artifacts.append(
        Artifact(
            source="explorer.exe:displayText",
            category="file_access",
            description=f"Recent item: {display_text}",
            metadata={
                "name": display_text,
                "path": fields.get("description", ""),
                "raw": raw_str,
            },
        )
    )


# Needles for fast pre-filtering, their extractors, and whether they stop after first hit
# (needles, extractor, single_block)
# Multiple needles per scan — any match triggers the extractor
_SCANS: list[tuple[list[bytes], object, bool]] = [
    ([b"PcaClient"], _extract_pcaclient, True),
    ([b"file:///", _FILE_URI_WIDE_NEEDLE], _extract_recent_files, False),
    ([_DISPLAY_TEXT_NEEDLE, _DISPLAY_TEXT_WIDE_NEEDLE], _extract_display_text, False),
    ([b"\\Users\\", "\\Users\\".encode("utf-16-le")], _extract_user_exes, False),
]


class ExplorerMemoryCollector(SystemCollector):

    @property
    def name(self) -> str:
        return "Explorer Memory Collector"

    @property
    def description(self) -> str:
        return "Scans explorer.exe memory for execution traces, recent files, and user executables"

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
                                    log.info(
                                        "[scan %d] +%d artifacts in PID %d at %s",
                                        idx, len(found), proc.pid,
                                        hex(region.base_address),
                                    )
                                    artifacts.extend(found)

                    labels = ["PcaClient", "file:///", "displayText", "\\Users\\"]
                    for i, label in enumerate(labels):
                        log.info("[%s] %d unique entries from PID %d", label, len(seen_sets[i]), proc.pid)

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

    labels = ["PcaClient", "file:///", "displayText", "\\Users\\"]
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
                    key = a.metadata.get("exe_path") or a.metadata.get("name") or a.metadata.get("file_path") or ""
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
