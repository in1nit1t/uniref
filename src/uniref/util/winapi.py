import win32process
from typing import *
from functools import wraps
from platform import architecture

from ctypes import windll
from uniref.define.struct import *
from uniref.define.constant import *


def _register_api(unexpected_return: object):
    def wrapper(func):
        @wraps(func)
        def inner(*args, **kwargs):
            api_name = func.__name__
            ret = eval(f"windll.kernel32.{api_name}(*args, **kwargs)")
            if ret == unexpected_return:
                raise SystemError(f"[{api_name}] error code: {WinApi.GetLastError()}")
            return ret
        return inner
    return wrapper


def _register_api_without_check(func):
    @wraps(func)
    def inner(*args, **kwargs):
        api_name = func.__name__
        return eval(f"windll.kernel32.{api_name}(*args, **kwargs)")
    return inner


class WinApi:
    _kernel32 = windll.kernel32
    _kernel32.CloseHandle.restype = c_bool
    _kernel32.Process32First.restype = c_bool
    _kernel32.Process32Next.restype = c_bool
    _kernel32.Module32First.restype = c_bool
    _kernel32.Module32Next.restype = c_bool
    _kernel32.ReadProcessMemory.restype = c_bool
    _kernel32.ReadProcessMemory.argtypes = [c_void_p, c_void_p, c_void_p, c_size_t, c_void_p]
    _kernel32.WriteProcessMemory.restype = c_bool
    _kernel32.WriteProcessMemory.argtypes = [c_void_p, c_void_p, c_void_p, c_size_t, c_void_p]
    _kernel32.GetProcAddress.restype = c_void_p
    _kernel32.GetProcAddress.argtypes = [c_void_p, c_char_p]
    _kernel32.GetModuleHandleA.restype = c_void_p
    _kernel32.CreateRemoteThread.argtypes = [c_void_p, c_void_p, c_size_t, c_void_p, c_void_p, c_uint32, c_void_p]
    _kernel32.VirtualQueryEx.restype = c_uint64
    _kernel32.VirtualQueryEx.argtypes = [c_void_p, c_void_p, c_void_p, c_uint32]
    _kernel32.VirtualProtectEx.restype = c_bool
    _kernel32.VirtualProtectEx.argtypes = [c_void_p, c_void_p, c_size_t, c_uint32, c_void_p]
    _kernel32.VirtualAllocEx.restype = c_void_p
    _kernel32.VirtualAllocEx.argtypes = [c_void_p, c_void_p, c_uint64, c_uint32, c_uint32]
    _kernel32.VirtualFreeEx.restype = c_bool
    _kernel32.VirtualFreeEx.argtypes = [c_void_p, c_void_p, c_uint64, c_uint32]

    _is_x86_32 = "32" in architecture()[0]
    _readable_blacklist = (PAGE_NOACCESS, PAGE_EXECUTE, PAGE_NOCACHE, PAGE_GUARD)
    _writeable_whitelist = (PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_WRITECOMBINE)

    @staticmethod
    def GetLastError() -> int:
        return windll.kernel32.GetLastError()

    @staticmethod
    @_register_api(unexpected_return=0)
    def GetCurrentProcess() -> int:
        ...

    @staticmethod
    @_register_api(unexpected_return=0)
    def GetCurrentProcessId() -> int:
        ...

    @staticmethod
    @_register_api(unexpected_return=None)
    def GetModuleHandleA(lpModuleName: bytes) -> int:
        ...

    @staticmethod
    @_register_api(unexpected_return=0)
    def IsWow64Process(hProcess: int, Wow64Process: object) -> int:
        ...

    @staticmethod
    @_register_api(unexpected_return=0)
    def TlsSetValue(dwTlsIndex: int, lpTlsValue: int) -> int:
        ...

    @staticmethod
    @_register_api(unexpected_return=0)
    def OpenProcess(dwDesiredAccess: int, bInheritHandle: bool, dwProcessId: int) -> int:
        ...

    @staticmethod
    @_register_api(unexpected_return=0)
    def VirtualQueryEx(hProcess: int, lpAddress: int, lpBuffer: object, dwLength: int) -> int:
        ...

    @staticmethod
    @_register_api(unexpected_return=False)
    def VirtualProtectEx(hProcess: int, lpAddress: int, dwSize: int, flNewProtect: int, lpflOldProtect: object) -> bool:
        ...

    @staticmethod
    @_register_api(unexpected_return=None)
    def VirtualAllocEx(hProcess: int, lpAddress: int, dwSize: int, flAllocationType: int, flProtect: int) -> int:
        ...

    @staticmethod
    @_register_api(unexpected_return=False)
    def VirtualFreeEx(hProcess: int, lpAddress: int, dwSize: int, dwFreeType: int) -> bool:
        ...

    @staticmethod
    @_register_api(unexpected_return=0)
    def CreateRemoteThread(hProcess: int, lpThreadAttributes: int, dwStackSize: int, lpStartAddress: int, lpParameter: int, dwCreationFlags: int, lpThreadId: object) -> int:
        ...

    @staticmethod
    @_register_api(unexpected_return=-1)
    def WaitForSingleObject(hHandle: int, dwMilliseconds: int) -> int:
        ...

    @staticmethod
    @_register_api(unexpected_return=None)
    def GetProcAddress(hModule: int, lpProcName: bytes) -> int:
        ...

    @staticmethod
    @_register_api(unexpected_return=INVALID_HANDLE_VALUE)
    def CreateToolhelp32Snapshot(dwFlags: int, th32ProcessID: int) -> int:
        ...

    @staticmethod
    @_register_api(unexpected_return=False)
    def CloseHandle(hObject: int) -> bool:
        ...

    @staticmethod
    @_register_api_without_check
    def Process32First(hSnapshot: int, lppe: object) -> bool:
        ...

    @staticmethod
    @_register_api_without_check
    def Process32Next(hSnapshot: int, lppe: object) -> bool:
        ...

    @staticmethod
    @_register_api_without_check
    def Module32First(hSnapshot: int, lpme: object) -> bool:
        ...

    @staticmethod
    @_register_api_without_check
    def Module32Next(hSnapshot: int, lpme: object) -> bool:
        ...

    @staticmethod
    @_register_api(unexpected_return=False)
    def ReadProcessMemory(hProcess: int, lpBaseAddress: int, lpBuffer: object, nSize: int, lpNumberOfBytesRead: object) -> bool:
        ...

    @staticmethod
    @_register_api(unexpected_return=False)
    def WriteProcessMemory(hProcess: int, lpBaseAddress: int, lpBuffer: bytes, nSize: int, lpNumberOfBytesWritten: object) -> bool:
        ...

    @staticmethod
    def GetPidByName(process_name: str) -> List[int]:
        pid = []
        process_name = process_name.encode()

        pe = PROCESSENTRY32()
        pe.dwSize = sizeof(pe)
        h_process_snapshot = WinApi.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        ret = WinApi.Process32First(h_process_snapshot, byref(pe))
        while ret:
            if process_name == pe.szExeFile:
                pid.append(pe.th32ProcessID)
            ret = WinApi.Process32Next(h_process_snapshot, byref(pe))
        WinApi.CloseHandle(h_process_snapshot)
        return pid

    @staticmethod
    def GetRemoteModules(h_process: int) -> List[int]:
        bit_long = WinApi.ProcessBitLong(h_process)
        flag = LIST_MODULES_32BIT if bit_long == 32 else LIST_MODULES_64BIT
        return win32process.EnumProcessModulesEx(h_process, flag)

    @staticmethod
    def GetRemoteModuleHandle(h_process: int, module_name: str) -> int:
        modules = WinApi.GetRemoteModules(h_process)
        for module in modules:
            file_name = win32process.GetModuleFileNameEx(h_process, module)
            if file_name and file_name.endswith(module_name):
                return module
        return 0

    @staticmethod
    def ProcessBitLong(hProcess: int) -> int:
        if WinApi._is_x86_32:
            return 32

        flag = c_bool()
        WinApi.IsWow64Process(hProcess, byref(flag))
        return 32 if flag.value else 64

    @staticmethod
    def VAReadableSize(hProcess: int, address: int) -> int:
        if WinApi._is_x86_32:
            mbi = MEMORY_BASIC_INFORMATION32()
        else:
            mbi = MEMORY_BASIC_INFORMATION64()
        WinApi.VirtualQueryEx(hProcess, address, byref(mbi), sizeof(mbi))
        protect = mbi.Protect
        if protect:
            if not any([protect & flag for flag in WinApi._readable_blacklist]):
                return mbi.RegionSize
        return 0

    @staticmethod
    def VAWriteableSize(hProcess: int, address: int) -> int:
        if WinApi._is_x86_32:
            mbi = MEMORY_BASIC_INFORMATION32()
        else:
            mbi = MEMORY_BASIC_INFORMATION64()
        WinApi.VirtualQueryEx(hProcess, address, byref(mbi), sizeof(mbi))
        protect = mbi.Protect
        if protect:
            if any([protect & flag for flag in WinApi._writeable_whitelist]):
                return mbi.RegionSize
        return 0
