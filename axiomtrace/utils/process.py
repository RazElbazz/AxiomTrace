"""Process and service discovery helpers."""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import logging
from dataclasses import dataclass
from typing import Optional

from axiomtrace.utils.winapi import (
    LUID,
    PROCESSENTRY32,
    SERVICE_STATUS_PROCESS,
    TOKEN_PRIVILEGES,
    LUID_AND_ATTRIBUTES,
    TH32CS_SNAPPROCESS,
    SC_MANAGER_CONNECT,
    SERVICE_QUERY_STATUS,
    TOKEN_ADJUST_PRIVILEGES,
    TOKEN_QUERY,
    SE_PRIVILEGE_ENABLED,
    SE_DEBUG_NAME,
    CreateToolhelp32Snapshot,
    Process32First,
    Process32Next,
    CloseHandle,
    GetCurrentProcess,
    OpenProcessToken,
    LookupPrivilegeValueW,
    AdjustTokenPrivileges,
    OpenSCManagerW,
    OpenServiceW,
    QueryServiceStatusEx,
    CloseServiceHandle,
)

log = logging.getLogger(__name__)

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def enable_debug_privilege() -> bool:
    """Enable SeDebugPrivilege for the current process.

    Required to open system processes like svchost.exe for memory reading.
    Must be running as Administrator for this to succeed.
    """
    token = wt.HANDLE()
    if not OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(token),
    ):
        log.error("OpenProcessToken failed (error %d)", ctypes.get_last_error())
        return False

    try:
        luid = LUID()
        if not LookupPrivilegeValueW(None, SE_DEBUG_NAME, ctypes.byref(luid)):
            log.error("LookupPrivilegeValue failed (error %d)", ctypes.get_last_error())
            return False

        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0] = LUID_AND_ATTRIBUTES(luid, SE_PRIVILEGE_ENABLED)

        if not AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None):
            log.error("AdjustTokenPrivileges failed (error %d)", ctypes.get_last_error())
            return False

        # AdjustTokenPrivileges can "succeed" but still set ERROR_NOT_ALL_ASSIGNED
        err = ctypes.get_last_error()
        if err == 1300:  # ERROR_NOT_ALL_ASSIGNED
            log.error("SeDebugPrivilege not available - are you running as admin?")
            return False

        log.debug("SeDebugPrivilege enabled successfully")
        return True
    finally:
        CloseHandle(token)


@dataclass
class ProcessInfo:
    """Basic information about a running process."""

    pid: int
    name: str
    parent_pid: int


def enumerate_processes() -> list[ProcessInfo]:
    """Return a list of all running processes via Toolhelp32 snapshot."""
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        log.error("CreateToolhelp32Snapshot failed")
        return []

    processes: list[ProcessInfo] = []
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

    try:
        if not Process32First(snap, ctypes.byref(entry)):
            return []

        while True:
            processes.append(
                ProcessInfo(
                    pid=entry.th32ProcessID,
                    name=entry.szExeFile.decode("utf-8", errors="replace").lower(),
                    parent_pid=entry.th32ParentProcessID,
                )
            )
            if not Process32Next(snap, ctypes.byref(entry)):
                break
    finally:
        CloseHandle(snap)

    return processes


def find_processes_by_name(name: str) -> list[ProcessInfo]:
    """Find all processes matching the given executable name (case-insensitive)."""
    target = name.lower()
    return [p for p in enumerate_processes() if p.name == target]


def get_service_pid(service_name: str) -> Optional[int]:
    """Get the PID of the process hosting a Windows service.

    Returns None if the service is not found or not running.
    """
    sc_manager = OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
    if not sc_manager:
        log.error("Failed to open Service Control Manager")
        return None

    try:
        service = OpenServiceW(sc_manager, service_name, SERVICE_QUERY_STATUS)
        if not service:
            log.debug("Service '%s' not found", service_name)
            return None

        try:
            status = SERVICE_STATUS_PROCESS()
            bytes_needed = wt.DWORD(0)

            # SC_STATUS_PROCESS_INFO = 0
            if not QueryServiceStatusEx(
                service,
                0,
                ctypes.byref(status),
                ctypes.sizeof(status),
                ctypes.byref(bytes_needed),
            ):
                log.error("QueryServiceStatusEx failed for '%s'", service_name)
                return None

            if status.dwProcessId == 0:
                log.debug("Service '%s' is not running (PID=0)", service_name)
                return None

            return status.dwProcessId
        finally:
            CloseServiceHandle(service)
    finally:
        CloseServiceHandle(sc_manager)
