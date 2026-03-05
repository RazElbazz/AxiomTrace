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
from typing import Iterator, Optional

from axiomtrace.utils.winapi import (
    MEMORY_BASIC_INFORMATION,
    MBI_SIZE,
    MEM_COMMIT,
    MEM_IMAGE,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
    PAGE_GUARD,
    PAGE_NOACCESS,
    PAGE_READWRITE,
    PAGE_WRITECOPY,
    PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
    CloseHandle,
    OpenProcess,
    ReadProcessMemory,
    VirtualQueryEx,
)

# Writable page protections — heap/stack data lives here
_WRITABLE_PAGES = (PAGE_READWRITE | PAGE_WRITECOPY |
                   PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

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

    def iter_regions(
        self,
        max_region_size: int = MAX_REGION_SIZE,
        min_region_size: int = 0,
    ) -> Iterator[MemoryRegion]:
        """Lazily yield committed, accessible memory regions one at a time.

        Uses a pre-allocated reusable buffer to minimize allocations.

        Args:
            max_region_size: Skip regions larger than this.
            min_region_size: Skip regions smaller than this.
        """
        if not self._handle:
            raise RuntimeError("Process not opened. Call open() first.")

        address = 0
        mbi = MEMORY_BASIC_INFORMATION()
        bytes_read = ctypes.c_size_t(0)

        # Pre-allocate a reusable buffer (grown if needed)
        buf_size = 1024 * 1024  # 1 MB initial
        buf = (ctypes.c_char * buf_size)()

        while VirtualQueryEx(self._handle, address, ctypes.byref(mbi), MBI_SIZE):
            if (
                mbi.State == MEM_COMMIT
                and mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD) == 0
                and mbi.RegionSize <= max_region_size
                and mbi.RegionSize >= min_region_size
            ):
                # Grow buffer if needed
                if mbi.RegionSize > buf_size:
                    buf_size = mbi.RegionSize
                    buf = (ctypes.c_char * buf_size)()

                region_base = mbi.BaseAddress or 0
                if ReadProcessMemory(
                    self._handle,
                    region_base,
                    buf,
                    mbi.RegionSize,
                    ctypes.byref(bytes_read),
                ):
                    yield MemoryRegion(
                        base_address=region_base,
                        size=bytes_read.value,
                        protect=mbi.Protect,
                        data=bytes(buf[: bytes_read.value]),
                    )

            base = mbi.BaseAddress or 0
            address = base + mbi.RegionSize
            if address <= base:
                break

    def iter_regions_pipelined(
        self,
        prefetch: int = 4,
        skip_images: bool = True,
    ) -> Iterator[MemoryRegion]:
        """Yield regions with prefetched reads for overlapped I/O + scanning.

        A background thread reads ahead while the caller processes regions.
        ReadProcessMemory releases the GIL, so reading and scanning overlap.

        Args:
            prefetch: How many regions to read ahead (queue depth).
            skip_images: Skip MEM_IMAGE regions (DLL/EXE code sections).
        """
        if not self._handle:
            raise RuntimeError("Process not opened. Call open() first.")

        from queue import Queue
        from threading import Thread

        queue: Queue[Optional[MemoryRegion]] = Queue(maxsize=prefetch)
        handle = self._handle

        def _reader() -> None:
            address = 0
            mbi = MEMORY_BASIC_INFORMATION()
            bytes_read = ctypes.c_size_t(0)
            buf_size = 1024 * 1024
            buf = (ctypes.c_char * buf_size)()

            while VirtualQueryEx(handle, address, ctypes.byref(mbi), MBI_SIZE):
                if (
                    mbi.State == MEM_COMMIT
                    and mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD) == 0
                    and mbi.RegionSize <= MAX_REGION_SIZE
                    and (not skip_images or mbi.Type != MEM_IMAGE)
                ):
                    if mbi.RegionSize > buf_size:
                        buf_size = mbi.RegionSize
                        buf = (ctypes.c_char * buf_size)()

                    region_base = mbi.BaseAddress or 0
                    if ReadProcessMemory(
                        handle, region_base, buf, mbi.RegionSize,
                        ctypes.byref(bytes_read),
                    ):
                        queue.put(MemoryRegion(
                            base_address=region_base,
                            size=bytes_read.value,
                            protect=mbi.Protect,
                            data=bytes(buf[: bytes_read.value]),
                        ))

                base = mbi.BaseAddress or 0
                address = base + mbi.RegionSize
                if address <= base:
                    break

            queue.put(None)  # sentinel

        thread = Thread(target=_reader, daemon=True)
        thread.start()

        while True:
            region = queue.get()
            if region is None:
                break
            yield region

        thread.join()

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
