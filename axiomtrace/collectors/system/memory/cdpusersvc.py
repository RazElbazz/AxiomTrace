"""CDPUserSvc (Connected Devices Platform) memory collector.

Scans the CDPUserSvc service memory for activity cache entries.
This service manages the ActivitiesCache and reveals recently used
applications and files.

Patterns searched:
  - {"displayText" JSON blobs containing .exe references
  - ,"activationUri" entries
  - platform entries containing .exe
  - x_exe_path entries containing .com
  - @{"displayText" entries
"""

from __future__ import annotations

import logging
import re
import subprocess
from typing import List

from axiomtrace.collectors.base import Artifact, SystemCollector
from axiomtrace.utils.memory import MemoryRegion, ProcessMemoryReader
from axiomtrace.utils.process import enable_debug_privilege, get_service_pid

log = logging.getLogger(__name__)

SERVICE_PREFIX = "CDPUserSvc"


def _find_cdpusersvc_name() -> str | None:
    """Find the full CDPUserSvc service name (has dynamic suffix like CDPUserSvc_cfeee)."""
    try:
        out = subprocess.check_output(
            ["tasklist", "/svc", "/fo", "csv"],
            encoding="utf-8", errors="replace",
            stderr=subprocess.DEVNULL,
        )
        for line in out.splitlines():
            upper = line.upper()
            if SERVICE_PREFIX.upper() in upper:
                # CSV format: "svchost.exe","9376","CDPUserSvc_cfeee"
                parts = line.strip().strip('"').split('","')
                if len(parts) >= 3:
                    return parts[2].strip('"')
    except Exception as exc:
        log.debug("Failed to find CDPUserSvc: %s", exc)
    return None


# --- Pattern needles ---
_NEEDLE_DISPLAY_TEXT = b'{"displayText"'
_NEEDLE_ACTIVATION_URI = b',"activationUri"'
_NEEDLE_PLATFORM = b'"platform"'
_NEEDLE_EXE_PATH = b'"x_exe_path"'
_NEEDLE_AT_DISPLAY = b'@{"displayText"'

# Wide variants
_NEEDLE_DISPLAY_TEXT_WIDE = '{"displayText"'.encode("utf-16-le")
_NEEDLE_ACTIVATION_URI_WIDE = ',"activationUri"'.encode("utf-16-le")
_NEEDLE_PLATFORM_WIDE = '"platform"'.encode("utf-16-le")
_NEEDLE_EXE_PATH_WIDE = '"x_exe_path"'.encode("utf-16-le")

# --- Field extractors ---
_FIELD_RES = {
    "displayText": re.compile(rb'"displayText"\s*:\s*"([^"]*)"'),
    "activationUri": re.compile(rb'"activationUri"\s*:\s*"([^"]*)"'),
    "appDisplayName": re.compile(rb'"appDisplayName"\s*:\s*"([^"]*)"'),
    "description": re.compile(rb'"description"\s*:\s*"([^"]*)"'),
    "platform": re.compile(rb'"platform"\s*:\s*"([^"]*)"'),
    "x_exe_path": re.compile(rb'"x_exe_path"\s*:\s*"([^"]*)"'),
}


def _find_json_end(data: bytes, start: int) -> int:
    """Find the closing '}' of a JSON object starting at data[start] == '{'."""
    depth = 0
    i = start
    end = min(start + 4096, len(data))
    while i < end:
        ch = data[i]
        if ch == ord(b'"'):
            i += 1
            while i < end and data[i] != ord(b'"'):
                if data[i] == ord(b'\\'):
                    i += 1
                i += 1
        elif ch == ord(b'{'):
            depth += 1
        elif ch == ord(b'}'):
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _extract_activity_blobs(region: MemoryRegion, pid: int, seen: set[str]) -> List[Artifact]:
    """Extract JSON blobs containing activity cache entries."""
    artifacts: List[Artifact] = []
    data = region.data

    # Find all { that start a displayText blob or other activity JSON
    for needle in [b'{"displayText"', b'@{"displayText"']:
        pos = 0
        while True:
            idx = data.find(needle, pos)
            if idx == -1:
                break
            # Skip the @ prefix if present
            json_start = idx + 1 if data[idx:idx + 1] == b'@' else idx
            end = _find_json_end(data, json_start)
            if end == -1:
                pos = idx + len(needle)
                continue
            raw = data[json_start:end + 1]
            _add_activity_blob(artifacts, raw, seen)
            pos = end + 1

    # Also scan for standalone activationUri, platform, x_exe_path entries
    # These may be in larger JSON objects - grab surrounding context
    for pattern_needle, field_name in [
        (b'"x_exe_path"', "x_exe_path"),
        (b'"platform"', "platform"),
    ]:
        pos = 0
        while True:
            idx = data.find(pattern_needle, pos)
            if idx == -1:
                break
            # Find the enclosing { ... } block
            # Search backwards for {
            brace_start = idx
            for lookback in range(min(idx, 2048)):
                if data[idx - lookback - 1] == ord(b'{'):
                    brace_start = idx - lookback - 1
                    break
            if brace_start < idx:
                end = _find_json_end(data, brace_start)
                if end != -1:
                    raw = data[brace_start:end + 1]
                    _add_activity_blob(artifacts, raw, seen)
            pos = idx + len(pattern_needle)

    return artifacts


def _add_activity_blob(
    artifacts: List[Artifact],
    raw: bytes,
    seen: set[str],
) -> None:
    fields: dict[str, str] = {}
    for name, pattern in _FIELD_RES.items():
        m = pattern.search(raw)
        if m:
            fields[name] = m.group(1).decode("utf-8", errors="replace")

    # Need at least one identifying field
    display_text = fields.get("displayText", "")
    exe_path = fields.get("x_exe_path", "")
    platform = fields.get("platform", "")
    description = fields.get("description", "")

    # Build a unique key from available fields
    key = display_text or exe_path or platform or description
    if not key:
        return

    normalized = key.strip().lower()
    if normalized in seen:
        return
    seen.add(normalized)

    raw_str = raw.decode("utf-8", errors="replace")

    # Determine the best name and path
    name = display_text or exe_path.rsplit("\\", 1)[-1] if exe_path and "\\" in exe_path else display_text or exe_path
    path = description or exe_path

    artifacts.append(
        Artifact(
            source="CDPUserSvc:activity",
            category="file_access",
            description=f"Activity: {key}",
            metadata={
                "name": name,
                "path": path,
                "raw": raw_str,
            },
        )
    )


_SCANS: list[tuple[list[bytes], object, bool]] = [
    (
        [
            _NEEDLE_DISPLAY_TEXT, _NEEDLE_DISPLAY_TEXT_WIDE,
            _NEEDLE_ACTIVATION_URI, _NEEDLE_ACTIVATION_URI_WIDE,
            _NEEDLE_PLATFORM, _NEEDLE_PLATFORM_WIDE,
            _NEEDLE_EXE_PATH, _NEEDLE_EXE_PATH_WIDE,
            _NEEDLE_AT_DISPLAY,
        ],
        _extract_activity_blobs,
        False,
    ),
]


class CdpUserSvcMemoryCollector(SystemCollector):

    @property
    def name(self) -> str:
        return "CDPUserSvc Memory Collector"

    @property
    def description(self) -> str:
        return "Scans CDPUserSvc service memory for activity cache entries"

    def validate_environment(self) -> bool:
        if not enable_debug_privilege():
            log.warning("Could not enable SeDebugPrivilege")
            return False
        svc_name = _find_cdpusersvc_name()
        if not svc_name:
            log.warning("CDPUserSvc service not found")
            return False
        pid = get_service_pid(svc_name)
        if pid is None:
            log.warning("CDPUserSvc service not running")
            return False
        return True

    def collect(self) -> list[Artifact]:
        artifacts: list[Artifact] = []
        svc_name = _find_cdpusersvc_name()
        if not svc_name:
            return artifacts
        pid = get_service_pid(svc_name)
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
            log.debug("Failed to read CDPUserSvc (PID %d): %s", pid, exc)

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

    svc_name = _find_cdpusersvc_name()
    if not svc_name:
        print("CDPUserSvc service not found")
        raise SystemExit(1)

    pid = get_service_pid(svc_name)
    if pid is None:
        print(f"{svc_name} service not running")
        raise SystemExit(1)

    print(f"{svc_name} PID: {pid}")

    labels = ["activity"]
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
            print(f"--- CDPUserSvc:{label} ({len(all_found[idx])} results) ---")
            for a in all_found[idx]:
                key = a.metadata.get("name") or ""
                print(f"  CDPUserSvc:{label} == {key}")
            print()
            all_artifacts.extend(all_found[idx])

    finally:
        reader.close()

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
