"""Process memory reader and string extractor.

Provides a reusable utility for opening a process by PID, reading its
committed memory regions, and extracting readable strings. Any collector
that needs to inspect process memory should use this module.
"""

from __future__ import annotations

import ctypes
import logging
import re
from dataclasses import dataclass
from typing import Optional

from axiomtrace.utils.winapi import (
    MEMORY_BASIC_INFORMATION,
    MBI_SIZE,
    MEM_COMMIT,
    PAGE_GUARD,
    PAGE_NOACCESS,
    PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
    CloseHandle,
    OpenProcess,
    ReadProcessMemory,
    VirtualQueryEx,
)

log = logging.getLogger(__name__)

# Pre-compiled patterns for string extraction
_ASCII_STRINGS_RE = re.compile(rb"[ -~]{4,}")
_WIDE_STRINGS_RE = re.compile(rb"(?:[ -~]\x00){4,}")

# Default cap to avoid reading enormous regions in one go (64 MB)
MAX_REGION_SIZE = 64 * 1024 * 1024


@dataclass
class MemoryRegion:
    """A single committed memory region of a process."""

    base_address: int
    size: int
    protect: int
    data: bytes


@dataclass
class ExtractedString:
    """A string found in process memory."""

    value: str
    address: int
    encoding: str  # "ascii" or "utf-16-le"


class ProcessMemoryReader:
    """Opens a process and reads its memory regions.

    Usage::

        reader = ProcessMemoryReader(pid)
        if reader.open():
            try:
                regions = reader.read_regions()
                strings = reader.extract_strings(regions)
            finally:
                reader.close()

    Or as a context manager::

        with ProcessMemoryReader(pid) as reader:
            strings = reader.extract_strings(reader.read_regions())
    """

    def __init__(self, pid: int) -> None:
        self.pid = pid
        self._handle: Optional[int] = None

    def open(self) -> bool:
        """Open the target process for reading. Returns True on success."""
        handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, self.pid
        )
        if not handle:
            err = ctypes.get_last_error()
            log.debug("Cannot open process %d (error %d)", self.pid, err)
            return False
        self._handle = handle
        return True

    def close(self) -> None:
        """Close the process handle."""
        if self._handle:
            CloseHandle(self._handle)
            self._handle = None

    def __enter__(self) -> ProcessMemoryReader:
        if not self.open():
            raise OSError(f"Cannot open process {self.pid} for reading")
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def read_regions(self, max_region_size: int = MAX_REGION_SIZE) -> list[MemoryRegion]:
        """Enumerate and read all committed, accessible memory regions."""
        if not self._handle:
            raise RuntimeError("Process not opened. Call open() first.")

        regions: list[MemoryRegion] = []
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()

        while VirtualQueryEx(self._handle, address, ctypes.byref(mbi), MBI_SIZE):
            if (
                mbi.State == MEM_COMMIT
                and mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD) == 0
                and mbi.RegionSize <= max_region_size
            ):
                buf = (ctypes.c_char * mbi.RegionSize)()
                bytes_read = ctypes.c_size_t(0)

                region_base = mbi.BaseAddress or 0
                if ReadProcessMemory(
                    self._handle,
                    region_base,
                    buf,
                    mbi.RegionSize,
                    ctypes.byref(bytes_read),
                ):
                    regions.append(
                        MemoryRegion(
                            base_address=region_base,
                            size=bytes_read.value,
                            protect=mbi.Protect,
                            data=bytes(buf[: bytes_read.value]),
                        )
                    )

            # Advance to next region
            base = mbi.BaseAddress or 0
            address = base + mbi.RegionSize
            if address <= base:
                break  # overflow guard

        log.debug("Read %d memory regions from PID %d", len(regions), self.pid)
        return regions

    @staticmethod
    def regions_contain(regions: list[MemoryRegion], needle: bytes) -> bool:
        """Fast check: does any region contain the given byte sequence?"""
        for region in regions:
            if needle in region.data:
                return True
        return False

    @staticmethod
    def extract_strings(
        regions: list[MemoryRegion],
        min_length: int = 4,
    ) -> list[ExtractedString]:
        """Extract ASCII and UTF-16LE strings from memory regions.

        Args:
            regions: Memory regions to scan.
            min_length: Minimum character length for a string to be included.
        """
        results: list[ExtractedString] = []

        ascii_pat = re.compile(rb"[ -~]{%d,}" % min_length)
        wide_pat = re.compile(rb"(?:[ -~]\x00){%d,}" % min_length)

        for region in regions:
            # ASCII strings
            for match in ascii_pat.finditer(region.data):
                results.append(
                    ExtractedString(
                        value=match.group().decode("ascii"),
                        address=region.base_address + match.start(),
                        encoding="ascii",
                    )
                )

            # UTF-16LE (wide) strings
            for match in wide_pat.finditer(region.data):
                try:
                    decoded = match.group().decode("utf-16-le")
                except UnicodeDecodeError:
                    continue
                results.append(
                    ExtractedString(
                        value=decoded,
                        address=region.base_address + match.start(),
                        encoding="utf-16-le",
                    )
                )

        return results

    @staticmethod
    def filter_strings(
        strings: list[ExtractedString],
        pattern: str,
        case_sensitive: bool = False,
    ) -> list[ExtractedString]:
        """Filter extracted strings by a regex pattern.

        Args:
            strings: Strings to filter.
            pattern: Regex pattern to match against string values.
            case_sensitive: Whether the match is case-sensitive.
        """
        flags = 0 if case_sensitive else re.IGNORECASE
        compiled = re.compile(pattern, flags)
        return [s for s in strings if compiled.search(s.value)]
