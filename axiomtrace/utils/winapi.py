"""Windows API constants and ctypes structures for process memory access."""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
from ctypes import Structure, POINTER, sizeof

# --- Access rights ---
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
TH32CS_SNAPPROCESS = 0x00000002
SC_MANAGER_CONNECT = 0x0001
SC_MANAGER_ENUMERATE_SERVICE = 0x0004
SERVICE_QUERY_STATUS = 0x0004
SERVICE_QUERY_CONFIG = 0x0001

# --- Token / privilege constants ---
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002
SE_DEBUG_NAME = "SeDebugPrivilege"

# --- Memory region constants ---
MEM_COMMIT = 0x1000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80


class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


class PROCESSENTRY32(Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_char * 260),
    ]


class LUID(Structure):
    _fields_ = [
        ("LowPart", wt.DWORD),
        ("HighPart", wt.LONG),
    ]


class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", wt.DWORD),
    ]


class TOKEN_PRIVILEGES(Structure):
    _fields_ = [
        ("PrivilegeCount", wt.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]


class SERVICE_STATUS_PROCESS(Structure):
    _fields_ = [
        ("dwServiceType", wt.DWORD),
        ("dwCurrentState", wt.DWORD),
        ("dwControlsAccepted", wt.DWORD),
        ("dwWin32ExitCode", wt.DWORD),
        ("dwServiceSpecificExitCode", wt.DWORD),
        ("dwCheckPoint", wt.DWORD),
        ("dwWaitHint", wt.DWORD),
        ("dwProcessId", wt.DWORD),
        ("dwServiceFlags", wt.DWORD),
    ]


# --- Kernel32 functions ---
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
OpenProcess.restype = wt.HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wt.HANDLE]
CloseHandle.restype = wt.BOOL

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [
    wt.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    POINTER(ctypes.c_size_t),
]
ReadProcessMemory.restype = wt.BOOL

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [
    wt.HANDLE,
    ctypes.c_void_p,
    POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
VirtualQueryEx.restype = ctypes.c_size_t

CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
CreateToolhelp32Snapshot.restype = wt.HANDLE

Process32First = kernel32.Process32First
Process32First.argtypes = [wt.HANDLE, POINTER(PROCESSENTRY32)]
Process32First.restype = wt.BOOL

Process32Next = kernel32.Process32Next
Process32Next.argtypes = [wt.HANDLE, POINTER(PROCESSENTRY32)]
Process32Next.restype = wt.BOOL

GetCurrentProcess = kernel32.GetCurrentProcess
GetCurrentProcess.argtypes = []
GetCurrentProcess.restype = wt.HANDLE

# --- Advapi32 functions ---
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)  # type: ignore[attr-defined]

OpenProcessToken = advapi32.OpenProcessToken
OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, POINTER(wt.HANDLE)]
OpenProcessToken.restype = wt.BOOL

LookupPrivilegeValueW = advapi32.LookupPrivilegeValueW
LookupPrivilegeValueW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, POINTER(LUID)]
LookupPrivilegeValueW.restype = wt.BOOL

AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges
AdjustTokenPrivileges.argtypes = [
    wt.HANDLE,
    wt.BOOL,
    POINTER(TOKEN_PRIVILEGES),
    wt.DWORD,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
AdjustTokenPrivileges.restype = wt.BOOL

OpenSCManagerW = advapi32.OpenSCManagerW
OpenSCManagerW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, wt.DWORD]
OpenSCManagerW.restype = wt.HANDLE

OpenServiceW = advapi32.OpenServiceW
OpenServiceW.argtypes = [wt.HANDLE, wt.LPCWSTR, wt.DWORD]
OpenServiceW.restype = wt.HANDLE

QueryServiceStatusEx = advapi32.QueryServiceStatusEx
QueryServiceStatusEx.argtypes = [
    wt.HANDLE,
    wt.DWORD,
    ctypes.c_void_p,
    wt.DWORD,
    POINTER(wt.DWORD),
]
QueryServiceStatusEx.restype = wt.BOOL

CloseServiceHandle = advapi32.CloseServiceHandle
CloseServiceHandle.argtypes = [wt.HANDLE]
CloseServiceHandle.restype = wt.BOOL

MBI_SIZE = sizeof(MEMORY_BASIC_INFORMATION)
