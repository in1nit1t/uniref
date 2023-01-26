import os
import struct
from pathlib import Path
from functools import wraps
from subprocess import Popen, PIPE

from uniref.define.patch import NativePatch
from uniref.define.struct import *
from uniref.define.types import *
from uniref.mono.assets import *
from uniref.util.winapi import WinApi
from uniref.util.compiler import X86Compiler
from uniref.util.injector.interface import Injector


def _register_mem_read(size: int, fmt: str):
    def wrapper(func):
        @wraps(func)
        def inner(*args, **kwargs):
            address = args[1] if len(args) > 1 else kwargs.get("address")
            if not isinstance(address, int):
                raise TypeError("address should be int")
            raw = args[0]._mem_read(address, size)
            return struct.unpack(fmt, raw)[0]
        return inner
    return wrapper


def _register_mem_write(clazz: type, fmt: str):
    def wrapper(func):
        @wraps(func)
        def inner(*args, **kwargs):
            address = args[1] if len(args) > 1 else kwargs.get("address")
            if not isinstance(address, int):
                raise TypeError("address should be int")
            value = args[2] if len(args) > 2 else kwargs.get("value")
            if not isinstance(value, clazz):
                raise TypeError(f"value should be {clazz.__name__}")
            raw = struct.pack(fmt, value)
            return args[0]._mem_write(address, raw) == len(raw)
        return inner
    return wrapper


class WinInjector(Injector):
    """ Process injector for ``Windows``. """

    def __init__(self, exe_filename: str = '', process_id: int = 0) -> None:
        if process_id:
            h_process = WinApi.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        else:
            if exe_filename:
                process_id = WinApi.GetPidByName(exe_filename)
                if not process_id:
                    raise Exception(f"Process with filename [{exe_filename}] not found")
                if len(process_id) != 1:
                    raise Exception(f"Too many processes with the same file name, use process id instead")
                process_id = process_id[0]
                h_process = WinApi.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
            else:
                process_id = WinApi.GetCurrentProcessId()
                h_process = WinApi.GetCurrentProcess()

        self._h_process = h_process
        self._process_id = process_id
        self._bit_long = WinApi.ProcessBitLong(h_process)
        self._code_compiler = X86Compiler(bit_long=self._bit_long)

        self._get_proc_address = self._get_kernel32_proc_address("GetProcAddress")

    def __del__(self):
        if self._h_process:
            WinApi.CloseHandle(self._h_process)
        self._h_process = 0

    @property
    def bit_long(self) -> int:
        return self._bit_long

    @property
    def process_id(self) -> int:
        return self._process_id

    @property
    def code_compiler(self):
        return self._code_compiler

    @property
    def process_handle(self) -> int:
        return self._h_process

    def _mem_read(self, address: int, count: int) -> bytes:
        if WinApi.VAReadableSize(self._h_process, address):
            n_read = c_int(0)
            buffer = (c_char * count)()
            WinApi.ReadProcessMemory(self._h_process, address, buffer, count, byref(n_read))
            return buffer.raw
        raise MemoryError(f"Address {hex(address)} not readable")

    def _mem_write(self, address: int, buffer: bytes) -> int:
        if WinApi.VAWriteableSize(self._h_process, address):
            n_write = c_int(0)
            WinApi.WriteProcessMemory(self._h_process, address, buffer, len(buffer), byref(n_write))
            return n_write.value
        raise MemoryError(f"Address {hex(address)} not writeable")

    def _get_kernel32_proc_address(self, proc_name: str):
        exe_path = str(Path(os.path.abspath(__file__)).parent.parent.parent / f"bin/win/getproc{self._bit_long}.exe")
        p = Popen(f"{exe_path} {proc_name}", shell=True, stdout=PIPE)
        output = p.stdout.read()
        p.wait()
        if isinstance(output, bytes):
            output = output.decode(errors="ignore")
        proc_address = int(output, 16)
        if proc_address <= 0:
            raise SystemError(f"Can't get address of {proc_name}")
        return proc_address

    def _create_remote_thread(self, address: int) -> None:
        h_thread = WinApi.CreateRemoteThread(self._h_process, 0, 0, address, 0, 0, 0)
        WinApi.WaitForSingleObject(h_thread, INFINITE)
        WinApi.CloseHandle(h_thread)

    def mem_alloc(self,
                  alloc_address: int = 0,
                  alloc_size: int = PAGE_SIZE,
                  alloc_type: int = MEM_COMMIT | MEM_RESERVE,
                  protection: str = "rwx"
                  ) -> int:
        """ Allocate memory. """
        protection = protection_map.get(protection, PAGE_EXECUTE_READWRITE)
        return WinApi.VirtualAllocEx(self._h_process, alloc_address, alloc_size, alloc_type, protection)

    def mem_free(self, address: int, free_size: int = 0, free_type: int = MEM_RELEASE) -> None:
        """ Free allocated memory. """
        WinApi.VirtualFreeEx(self._h_process, address, free_size, free_type)

    def mem_set_protect(self, address: int, length: int, new_protect: str = "rwx") -> str:
        """ Set memory protection. """
        old = c_uint32()
        protection = protection_map.get(new_protect, PAGE_EXECUTE_READWRITE)
        WinApi.VirtualProtectEx(self._h_process, address, length, protection, byref(old))
        return protection_rev_map.get(old.value, "rwx")

    @_register_mem_read(size=1, fmt='?')
    def mem_read_bool(self, address: int) -> bool:
        ...

    @_register_mem_read(size=1, fmt='b')
    def mem_read_char(self, address: int) -> int:
        ...

    @_register_mem_read(size=1, fmt='B')
    def mem_read_uchar(self, address: int) -> int:
        ...

    @_register_mem_read(size=2, fmt='h')
    def mem_read_int16(self, address: int) -> int:
        ...

    @_register_mem_read(size=2, fmt='H')
    def mem_read_uint16(self, address: int) -> int:
        ...

    @_register_mem_read(size=4, fmt='i')
    def mem_read_int32(self, address: int) -> int:
        ...

    @_register_mem_read(size=4, fmt='I')
    def mem_read_uint32(self, address: int) -> int:
        ...

    @_register_mem_read(size=8, fmt='q')
    def mem_read_int64(self, address: int) -> int:
        ...

    @_register_mem_read(size=8, fmt='Q')
    def mem_read_uint64(self, address: int) -> int:
        ...

    @_register_mem_read(size=4, fmt='f')
    def mem_read_float(self, address: int) -> float:
        ...

    @_register_mem_read(size=8, fmt='d')
    def mem_read_double(self, address: int) -> float:
        ...

    def mem_read_pointer(self, address: int) -> int:
        if not isinstance(address, int):
            raise TypeError("address should be int")
        if self._bit_long == 32:
            return self.mem_read_uint32(address)
        else:
            return self.mem_read_uint64(address)

    def mem_read_c_string(self, address: int) -> str:
        if not isinstance(address, int):
            raise TypeError("address should be int")

        string = b''
        while True:
            char = self._mem_read(address + len(string), 1)
            if char == b'\x00':
                break
            string += char
        return string.decode()

    @_register_mem_write(clazz=bool, fmt='?')
    def mem_write_bool(self, address: int, value: bool) -> bool:
        ...

    @_register_mem_write(clazz=int, fmt='b')
    def mem_write_char(self, address: int, value: int) -> bool:
        ...

    @_register_mem_write(clazz=int, fmt='B')
    def mem_write_uchar(self, address: int, value: int) -> bool:
        ...

    @_register_mem_write(clazz=int, fmt='h')
    def mem_write_int16(self, address: int, value: int) -> bool:
        ...

    @_register_mem_write(clazz=int, fmt='H')
    def mem_write_uint16(self, address: int, value: int) -> bool:
        ...

    @_register_mem_write(clazz=int, fmt='i')
    def mem_write_int32(self, address: int, value: int) -> bool:
        ...

    @_register_mem_write(clazz=int, fmt='I')
    def mem_write_uint32(self, address: int, value: int) -> bool:
        ...

    @_register_mem_write(clazz=int, fmt='q')
    def mem_write_int64(self, address: int, value: int) -> bool:
        ...

    @_register_mem_write(clazz=int, fmt='Q')
    def mem_write_uint64(self, address: int, value: int) -> bool:
        ...

    @_register_mem_write(clazz=float, fmt='f')
    def mem_write_float(self, address: int, value: float) -> bool:
        ...

    @_register_mem_write(clazz=float, fmt='d')
    def mem_write_double(self, address: int, value: float) -> bool:
        ...

    def mem_write_pointer(self, address: int, value: int) -> int:
        if not isinstance(address, int):
            raise TypeError("address should be int")
        if not isinstance(value, int):
            raise TypeError("value should be int")
        if self._bit_long == 32:
            return self.mem_write_uint32(address, value)
        else:
            return self.mem_write_uint64(address, value)

    def mem_write_c_string(self, address: int, value: str) -> bool:
        if not isinstance(address, int):
            raise TypeError("address should be int")
        if not isinstance(value, str):
            raise TypeError("value should be str")
        if len(value) == 0:
            to_write = b'\x00'
        else:
            to_write = value.encode(errors="ignore") + b'\x00'
        return self.mem_write_bytes(address, to_write) == len(value) + 1

    def code_execute(self, code: str or bytes, target_address: int = 0) -> int:
        if not isinstance(code, (str, bytes)):
            raise TypeError("code should be str or bytes")
        if not isinstance(target_address, int):
            raise TypeError("target_address should be int")
        if isinstance(code, str):
            code = self.code_compile(code, target_address)

        address = target_address if target_address else self.mem_alloc(alloc_size=len(code))
        self._code_patch_internal(code, address)
        self._create_remote_thread(address)
        return address

    def get_module_base(self, module_name: str) -> int:
        if not isinstance(module_name, str):
            raise TypeError("module_name should be str")
        return WinApi.GetRemoteModuleHandle(self._h_process, module_name)

    def get_proc_address(self, module_base: int, proc_name: str) -> int:
        """ Get module exported function address in the injected process. """
        if not isinstance(module_base, int):
            raise TypeError("module_base should be int")
        if not isinstance(proc_name, str):
            raise TypeError("proc_name should be str")
        if module_base <= 0:
            raise ValueError("module_base should be positive")
        if len(proc_name) > 255:
            raise ValueError("proc_name too long")

        page_start = self.mem_alloc()
        return_address = page_start + 0x300
        proc_name_address = page_start + 0x200
        if self._bit_long == 32:
            code = f"push {hex(proc_name_address)}           \n" \
                   f"push {hex(module_base)}                 \n" \
                   f"mov eax, {hex(self._get_proc_address)}  \n" \
                   f"call eax                                \n" \
                   f"mov ecx, {hex(return_address)}          \n" \
                   f"mov dword ptr [ecx], eax                \n" \
                   f"ret"
        else:
            code = f"sub rsp, 28h                            \n" \
                   f"mov rcx, {hex(module_base)}             \n" \
                   f"mov rdx, {hex(proc_name_address)}       \n" \
                   f"mov rax, {hex(self._get_proc_address)}  \n" \
                   f"call rax                                \n" \
                   f"mov r12, {hex(return_address)}          \n" \
                   f"mov qword ptr [r12], rax                \n" \
                   f"add rsp, 28h                            \n" \
                   f"ret"

        self._mem_write(proc_name_address, proc_name.encode(errors="ignore") + b'\x00')
        self.code_execute(code, page_start)
        proc_address = self.mem_read_pointer(return_address)
        self.mem_free(page_start)
        return proc_address

    def call_native_function(self, func_address: int, args: Tuple[int], ret_type: int, call_type: int) -> Any:
        if not isinstance(func_address, int):
            raise TypeError("func_address should be int")
        if not isinstance(args, tuple):
            raise TypeError("args should be a tuple of int")
        if not isinstance(ret_type, int):
            raise TypeError("ret_type should be int")
        if not isinstance(call_type, int):
            raise TypeError("call_type should be int")
        if func_address <= 0:
            raise ValueError("func_address should be positive")
        if ret_type not in range(TYPE_CS_STRING + 1):
            raise ValueError(f"Unsupported return type")
        if call_type not in range(CALL_TYPE_FASTCALL + 1):
            raise ValueError(f"Unsupported call convention")

        page_start = self.mem_alloc()
        return_address = page_start + 0x300

        if self._bit_long == 32:
            code = "push ebp\n mov ebp, esp\n"

            if call_type == CALL_TYPE_THISCALL:
                if len(args) < 1:
                    raise ValueError("thiscall needs [this] pointer")
                code += f"mov ecx, {hex(args[0])}      \n"
                args = args[1:]

            if call_type == CALL_TYPE_FASTCALL:
                argc = len(args)
                if argc:
                    code += f"mov ecx, {hex(args[0])}"
                if argc >= 2:
                    code += f"mov edx, {hex(args[1])}"
                args = args[2:]

            for arg in args[::-1]:
                code += f"push {hex(arg)}              \n"

            code += f"mov eax, {hex(func_address)}     \n" \
                    f"call eax                         \n" \
                    f"mov ecx, {hex(return_address)}   \n" \
                    f"mov dword ptr [ecx], eax         \n" \
                    f"leave\n ret"
        else:
            frame_size = 0x28 + ((len(args[4:]) + 1) // 2) * 0x10
            code = f"sub rsp, {hex(frame_size)}        \n"

            regs = ["rcx", "rdx", "r8", "r9"]
            for idx, arg in enumerate(args[:4]):
                code += f"mov {regs[idx]}, {hex(arg)}  \n"

            args = args[4:]
            for i in range(len(args)):
                code += f"mov qword ptr [rsp+{hex(0x20+i*8)}], {hex(args[i])}  \n"

            code += f"mov rax, {hex(func_address)}     \n" \
                    f"call rax                         \n" \
                    f"mov r12, {hex(return_address)}   \n" \
                    f"mov qword ptr [r12], rax         \n" \
                    f"add rsp, {hex(frame_size)}       \n" \
                    f"ret"

        code = self.code_compile(code)
        n_write = self.mem_write_bytes(page_start, code)
        if n_write != len(code):
            raise OSError("write compiled code to memory", f"{n_write}/{len(code)} bytes written")
        self._create_remote_thread(page_start)

        if ret_type == TYPE_BOOL:
            ret = self.mem_read_bool(return_address)
        elif ret_type == TYPE_CHAR:
            ret = self.mem_read_char(return_address)
        elif ret_type == TYPE_UCHAR:
            ret = self.mem_read_uchar(return_address)
        elif ret_type == TYPE_INT16:
            ret = self.mem_read_int16(return_address)
        elif ret_type == TYPE_UINT16:
            ret = self.mem_read_uint16(return_address)
        elif ret_type == TYPE_INT32:
            ret = self.mem_read_int32(return_address)
        elif ret_type == TYPE_UINT32:
            ret = self.mem_read_uint32(return_address)
        elif ret_type == TYPE_INT64:
            ret = self.mem_read_int64(return_address)
        elif ret_type == TYPE_UINT64:
            ret = self.mem_read_uint64(return_address)
        elif ret_type == TYPE_FLOAT:
            ret = self.mem_read_float(return_address)
        elif ret_type == TYPE_DOUBLE:
            ret = self.mem_read_double(return_address)
        elif ret_type == TYPE_VOID_P:
            ret = self.mem_read_pointer(return_address)
        elif ret_type == TYPE_CHAR_P:
            char_address = self.mem_read_pointer(return_address)
            ret = self.mem_read_c_string(char_address)
        elif ret_type == TYPE_CS_STRING:
            ret = self._read_cs_string(return_address)
        else:
            ret = None
        self.mem_free(page_start)
        return ret

    def code_nop(self, address: int, size: int) -> NativePatch:
        return self.code_patch(b'\x90' * size, address)
