"""
Anti-Debug Detection - Detect if the process is being debugged

This module detects common debuggers and analysis tools.
Can be imported and used as a standalone check or integrated.

Usage:
    from anti_tamper.anti_debug import detect_debugger
    if detect_debugger():
        print("Debugger detected!")
"""
import sys
import os
import ctypes
import struct
import platform
from ctypes import wintypes


def check_windows_debugger() -> bool:
    """Windows-specific debugger detection using NtQueryInformationProcess"""
    try:
        ntdll = ctypes.windll.ntdll

        class PROCESS_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("ExitStatus", wintypes.LONG),
                ("PebBaseAddress", ctypes.c_void_p),
                ("AffinityMask", ctypes.c_void_p),
                ("BasePriority", wintypes.LONG),
                ("UniqueProcessId", ctypes.c_void_p),
                ("InheritedFromUniqueProcessId", ctypes.c_void_p),
            ]

        pbi = PROCESS_BASIC_INFORMATION()
        status = ntdll.NtQueryInformationProcess(
            ctypes.wintypes.HANDLE(-1),  # NtCurrentProcess
            0,  # ProcessBasicInformation
            ctypes.byref(pbi),
            ctypes.sizeof(pbi),
            None
        )

        if status == 0 and pbi.PebBaseAddress:
            # Read BeingDebugged flag from PEB
            peb_offset = 0x2  # BeingDebugged is at offset 2 in PEB
            debugged = ctypes.c_ubyte()
            ctypes.windll.kernel32.ReadProcessMemory(
                ctypes.wintypes.HANDLE(-1),
                ctypes.c_void_p(pbi.PebBaseAddress + peb_offset),
                ctypes.byref(debugged),
                ctypes.sizeof(debugged),
                None
            )
            return debugged.value != 0

        # Fallback: IsDebuggerPresent
        return ctypes.windll.kernel32.IsDebuggerPresent() != 0

    except Exception:
        return False


def check_remote_debugger() -> bool:
    """Check for remote debugger presence via NtGlobalFlag"""
    try:
        ntdll = ctypes.windll.ntdll

        class PROCESS_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("ExitStatus", wintypes.LONG),
                ("PebBaseAddress", ctypes.c_void_p),
                ("AffinityMask", ctypes.c_void_p),
                ("BasePriority", wintypes.LONG),
                ("UniqueProcessId", ctypes.c_void_p),
                ("InheritedFromUniqueProcessId", ctypes.c_void_p),
            ]

        pbi = PROCESS_BASIC_INFORMATION()
        status = ntdll.NtQueryInformationProcess(
            ctypes.wintypes.HANDLE(-1),
            0,
            ctypes.byref(pbi),
            ctypes.sizeof(pbi),
            None
        )

        if status == 0 and pbi.PebBaseAddress:
            # NtGlobalFlag is at offset 0x68 in x64, 0x5C in x86
            flag_offset = 0x68 if struct.calcsize("P") == 8 else 0x5C
            flag = ctypes.c_ulong()
            ctypes.windll.kernel32.ReadProcessMemory(
                ctypes.wintypes.HANDLE(-1),
                ctypes.c_void_p(pbi.PebBaseAddress + flag_offset),
                ctypes.byref(flag),
                ctypes.sizeof(flag),
                None
            )
            # FLG_HEAP_ENABLE_TAIL_CHECK (0x10) | FLG_HEAP_ENABLE_FREE_CHECK (0x20) |
            # FLG_HEAP_VALIDATE_PARAMETERS (0x40)
            return (flag.value & 0x70) != 0

    except Exception:
        return False

    return False


def check_environment() -> bool:
    """Check environment variables for debugger/analysis tool indicators"""
    suspicious_vars = [
        "PROCESS_VM_TOOL", "PYTHONDEBUG", "JAVA_TOOL_OPTIONS",
        "COR_ENABLE_PROFILING", "COR_PROFILER", "MONO_ENV_OPTIONS",
        "DOTNET_ENVIRONMENT", "ASPNETCORE_ENVIRONMENT"
    ]
    for var in suspicious_vars:
        if os.environ.get(var, ""):
            return True
    return False


def check_process_list() -> bool:
    """Check for known debugger/analysis processes"""
    debugger_processes = [
        "x64dbg", "x32dbg", "ollydbg", "ida64", "ida",
        "windbg", "gdb", "ghidra", "dnspy", "de4dot",
        "httpdebug", "fiddler", "burpsuite", "wireshark",
        "processhacker", "procexp", "procmon", "cheatengine",
        "reclass", "hxd", "imhex", "010editor", "petools",
        "scylla", "x64dbg.exe", "ollydbg.exe", "ida.exe",
        "ida64.exe", "windbg.exe", "gdb.exe"
    ]

    try:
        import psutil
        for proc in psutil.process_iter(["name"]):
            try:
                pname = proc.info["name"].lower()
                for dbg in debugger_processes:
                    if dbg in pname:
                        return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except ImportError:
        pass  # psutil not available, skip this check

    return False


def detect_debugger() -> bool:
    """Run all anti-debug checks. Returns True if any trigger."""
    checks = []

    if platform.system() == "Windows":
        checks.append(("IsDebuggerPresent", check_windows_debugger()))
        checks.append(("NtGlobalFlag", check_remote_debugger()))

    checks.append(("Environment", check_environment()))
    checks.append(("ProcessList", check_process_list()))

    triggered = [name for name, result in checks if result]

    if triggered:
        print(f"[AntiDebug] Detection triggered: {', '.join(triggered)}")
        return True

    return False


if __name__ == "__main__":
    if detect_debugger():
        print("⚠ Debugger detected!")
        sys.exit(1)
    else:
        print("✓ No debugger detected")
