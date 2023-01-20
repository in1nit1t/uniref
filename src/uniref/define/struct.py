from ctypes import *


class PROCESSENTRY32(Structure):
    _fields_ = [
        ("dwSize", c_ulong),
        ("cntUsage", c_ulong),
        ("th32ProcessID", c_ulong),
        ("th32DefaultHeapID", c_void_p),
        ("th32ModuleID", c_ulong),
        ("cntThreads", c_ulong),
        ("th32ParentProcessID", c_ulong),
        ("pcPriClassBase", c_ulong),
        ("dwFlags", c_ulong),
        ("szExeFile", c_char * 260)
    ]


class MODULEENTRY32(Structure):
    _fields_ = [
        ("dwSize", c_ulong),
        ("th32ModuleID", c_ulong),
        ("th32ProcessID", c_ulong),
        ("GlblcntUsage", c_ulong),
        ("ProccntUsage", c_ulong),
        ("modBaseAddr", c_char_p),
        ("modBaseSize", c_ulong),
        ("hModule", c_void_p),
        ("szModule", c_char * 256),
        ("szExePath", c_char * 260),
    ]


class MEMORY_BASIC_INFORMATION32(Structure):
    _fields_ = [
        ("BaseAddress", c_uint32),
        ("AllocationBase", c_uint32),
        ("AllocationProtect", c_uint32),
        ("RegionSize", c_uint32),
        ("State", c_uint32),
        ("Protect", c_uint32),
        ("Type", c_uint32),
    ]


class MEMORY_BASIC_INFORMATION64(Structure):
    _fields_ = [
        ("BaseAddress", c_ulonglong),
        ("AllocationBase", c_ulonglong),
        ("AllocationProtect", c_ulong),
        ("__alignment1", c_ulong),
        ("RegionSize", c_ulonglong),
        ("State", c_ulong),
        ("Protect", c_ulong),
        ("Type", c_ulong),
        ("__alignment2", c_ulong),
    ]


class CUSTOM_DOMAIN_ARRAY32(Structure):
    _fields_ = [
        ("cnt", c_uint32),
        ("domains", c_uint32 * 1023)
    ]


class CUSTOM_DOMAIN_ARRAY64(Structure):
    _fields_ = [
        ("cnt", c_uint32),
        ("domains", c_uint64 * 511)
    ]
