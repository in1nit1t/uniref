import os
import struct
from typing import *
from pathlib import Path
from functools import wraps

from uniref.define.struct import *
from uniref.define.constant import *
from uniref.util.winapi import WinApi
from uniref.util.injector import WinInjector


def _require_process_open(func):
    @wraps(func)
    def inner(*args, **kwargs):
        args[0]._open_process()
        return func(*args, **kwargs)
    return inner


class _PyMemoryScanner:

    def __init__(self, pid: int) -> None:
        self._process_id = pid

        self._bit_long = 0
        self._h_process = 0

    def __del__(self):
        if self._h_process:
            WinApi.CloseHandle(self._h_process)
        self._h_process = 0

    def _open_process(self):
        if not self._h_process:
            h_process = WinApi.OpenProcess(PROCESS_ALL_ACCESS, False, self._process_id)
            self._bit_long = WinApi.ProcessBitLong(h_process)
            self._h_process = h_process

    def _readable(self, protect: int) -> bool:
        flags = (PAGE_NOACCESS, PAGE_EXECUTE, PAGE_NOCACHE, PAGE_GUARD)
        return not any([protect & flag for flag in flags])

    @_require_process_open
    def _match(self, pattern: bytes, va_start: int, va_end: int) -> List[int]:
        found = []
        address = va_start
        mbi = MEMORY_BASIC_INFORMATION64()
        while address <= va_end:
            try:
                WinApi.VirtualQueryEx(self._h_process, address, byref(mbi), sizeof(mbi))
            except SystemError:
                address += PAGE_SIZE
                continue
            region_size = mbi.RegionSize
            if region_size == 0:
                address += PAGE_SIZE
                continue
            if not mbi.Protect or not self._readable(mbi.Protect):
                address += region_size
                continue

            n_read = c_int(0)
            buffer = (c_char * region_size)()
            try:
                status = WinApi.ReadProcessMemory(self._h_process, address, buffer, region_size, byref(n_read))
            except:
                status = False
            if status and n_read.value:
                pos = 0
                bytes_read = buffer.raw
                pattern_len = len(pattern)
                while True:
                    idx = bytes_read.find(pattern)
                    if idx == -1:
                        break
                    pos += idx + pattern_len
                    found.append(address + pos - pattern_len)
                    bytes_read = bytes_read[pos:]
            address += region_size
        return found

    def scan_uint64(self, value: int, va_start: int = 0, va_end: int = -1) -> List[int]:
        if va_end <= 0:
            va_end = 0xffffffff if self._bit_long == 32 else 0x7fffffffffff
        if va_start > va_end:
            raise ValueError("va_start > va_end")
        return self._match(struct.pack("Q", value), va_start, va_end)


class CMemoryScanner:

    def __init__(self, pid: int, bit_long: int) -> None:
        self._process_id = pid
        self._bit_long = bit_long
        self._injector = WinInjector()
        self._init_proc()
    
    def _init_proc(self):
        _util = cdll.LoadLibrary(str(Path(os.path.abspath(__file__)).parent.parent / "bin/win/util64.dll"))

        self._SearchChar = _util.SearchChar
        self._SearchChar.argtypes = [c_uint32, c_byte, c_bool, c_uint64, c_uint64, c_void_p]
        self._SearchChar.restype = c_uint64

        self._SearchUChar = _util.SearchUChar
        self._SearchUChar.argtypes = [c_uint32, c_ubyte, c_bool, c_uint64, c_uint64, c_void_p]
        self._SearchUChar.restype = c_uint64

        self._SearchInt16 = _util.SearchInt16
        self._SearchInt16.argtypes = [c_uint32, c_int16, c_bool, c_uint64, c_uint64, c_void_p]
        self._SearchInt16.restype = c_uint64

        self._SearchUInt16 = _util.SearchUInt16
        self._SearchUInt16.argtypes = [c_uint32, c_uint16, c_bool, c_uint64, c_uint64, c_void_p]
        self._SearchUInt16.restype = c_uint64

        self._SearchInt32 = _util.SearchInt32
        self._SearchInt32.argtypes = [c_uint32, c_int32, c_bool, c_uint64, c_uint64, c_void_p]
        self._SearchInt32.restype = c_uint64

        self._SearchUInt32 = _util.SearchUInt32
        self._SearchUInt32.argtypes = [c_uint32, c_uint32, c_bool, c_uint64, c_uint64, c_void_p]
        self._SearchUInt32.restype = c_uint64

        self._SearchInt64 = _util.SearchInt64
        self._SearchInt64.argtypes = [c_uint32, c_int64, c_bool, c_uint64, c_uint64, c_void_p]
        self._SearchInt64.restype = c_uint64

        self._SearchUInt64 = _util.SearchUInt64
        self._SearchUInt64.argtypes = [c_uint32, c_uint64, c_bool, c_uint64, c_uint64, c_void_p]
        self._SearchUInt64.restype = c_uint64

        self._SearchFloat = _util.SearchFloat
        self._SearchFloat.argtypes = [c_uint32, c_float, c_bool, c_uint64, c_uint64, c_void_p]
        self._SearchFloat.restype = c_uint64

        self._SearchDouble = _util.SearchDouble
        self._SearchDouble.argtypes = [c_uint32, c_double, c_bool, c_uint64, c_uint64, c_void_p]
        self._SearchDouble.restype = c_uint64

        self._ResFree = _util.ResFree
        self._ResFree.argtypes = [c_void_p]

        self._util = _util

    def _res_free(self, ptr: int):
        self._ResFree(ptr)

    def _do_scan(self, elem_type: int, target: Any, writeable: bool, va_start: int = 0, va_end: int = -1):
        if va_end <= 0:
            va_end = 0xffffffff if self._bit_long == 32 else 0x7fffffffffff
        if va_start < 0:
            raise ValueError("va_start < 0")
        if va_start > va_end:
            raise ValueError("va_start > va_end")

        if elem_type == TYPE_CHAR:
            scan_func = self._SearchChar
        elif elem_type == TYPE_UCHAR:
            scan_func = self._SearchUChar
        elif elem_type == TYPE_INT16:
            scan_func = self._SearchInt16
        elif elem_type == TYPE_UINT16:
            scan_func = self._SearchUInt16
        elif elem_type == TYPE_INT32:
            scan_func = self._SearchInt32
        elif elem_type == TYPE_UINT32:
            scan_func = self._SearchUInt32
        elif elem_type == TYPE_INT64:
            scan_func = self._SearchInt64
        elif elem_type == TYPE_UINT64:
            scan_func = self._SearchUInt64
        elif elem_type == TYPE_FLOAT:
            scan_func = self._SearchFloat
        elif elem_type == TYPE_DOUBLE:
            scan_func = self._SearchDouble
        else:
            raise ValueError("Element type unsupported")
        res = c_void_p()
        cnt = scan_func(self._process_id, target, writeable, va_start, va_end, byref(res))
        if cnt:
            found = self._injector.mem_read_pointer_array(res.value, cnt)
            self._res_free(res.value)
            return found
        return []

    def scan_char(self, target: int, writeable: bool, va_start: int = 0, va_end: int = -1):
        return self._do_scan(TYPE_CHAR, target, writeable, va_start, va_end)

    def scan_uchar(self, target: int, writeable: bool, va_start: int = 0, va_end: int = -1):
        return self._do_scan(TYPE_UCHAR, target, writeable, va_start, va_end)

    def scan_int16(self, target: int, writeable: bool, va_start: int = 0, va_end: int = -1):
        return self._do_scan(TYPE_INT16, target, writeable, va_start, va_end)

    def scan_uint16(self, target: int, writeable: bool, va_start: int = 0, va_end: int = -1):
        return self._do_scan(TYPE_UINT16, target, writeable, va_start, va_end)

    def scan_int32(self, target: int, writeable: bool, va_start: int = 0, va_end: int = -1):
        return self._do_scan(TYPE_INT32, target, writeable, va_start, va_end)

    def scan_uint32(self, target: int, writeable: bool, va_start: int = 0, va_end: int = -1):
        return self._do_scan(TYPE_UINT32, target, writeable, va_start, va_end)

    def scan_int64(self, target: int, writeable: bool, va_start: int = 0, va_end: int = -1):
        return self._do_scan(TYPE_INT64, target, writeable, va_start, va_end)

    def scan_uint64(self, target: int, writeable: bool, va_start: int = 0, va_end: int = -1):
        return self._do_scan(TYPE_UINT64, target, writeable, va_start, va_end)

    def scan_pointer(self, target: int, writeable: bool, va_start: int = 0, va_end: int = -1):
        if self._bit_long == 32:
            return self.scan_uint32(target, writeable, va_start, va_end)
        else:
            return self.scan_uint64(target, writeable, va_start, va_end)
