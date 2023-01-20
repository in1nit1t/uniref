import os
import struct
from pathlib import Path
from functools import wraps
from subprocess import Popen, PIPE

from uniref.define.struct import *
from uniref.define.constant import *
from uniref.define.types import *
from uniref.util.winapi import WinApi
from uniref.define.patch import NativePatch
from uniref.util.compiler import X86Compiler


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


def _register_mem_read_array(proxy):
    def wrapper(func):
        @wraps(func)
        def inner(*args, **kwargs):
            address = args[1] if len(args) > 1 else kwargs.get("address")
            count = args[2] if len(args) > 2 else kwargs.get("count")
            if not isinstance(address, int):
                raise TypeError("address should be int")
            if count <= 0:
                raise ValueError("count should be positive")
            return proxy(args[0], address, count, auto_release=False).elements
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


def _register_mem_write_array(proxy):
    def wrapper(func):
        @wraps(func)
        def inner(*args, **kwargs):
            address = args[1] if len(args) > 1 else kwargs.get("address")
            elements = args[2] if len(args) > 2 else kwargs.get("elements")
            if not isinstance(address, int):
                raise TypeError("address should be int")
            if len(elements) <= 0:
                raise ValueError("Array is empty")
            proxy(args[0], address=address, elements=elements, auto_release=False)
            return True
        return inner
    return wrapper


def _register_new_basic_type(clazz: type, proxy):
    def wrapper(func):
        @wraps(func)
        def inner(*args, **kwargs):
            value = args[1] if len(args) > 1 else kwargs.get("value")
            auto_release = args[2] if len(args) > 2 else kwargs.get("auto_release", True)
            if not isinstance(value, clazz):
                raise TypeError(f"value should be {clazz.__name__}")
            if not isinstance(auto_release, bool):
                raise TypeError("auto_release should be bool")
            return proxy(*args, **kwargs)
        return inner
    return wrapper


def _register_new_array_type(clazz: type, proxy):
    def wrapper(func):
        @wraps(func)
        def inner(*args, **kwargs):
            value = args[1] if len(args) > 1 else kwargs.get("value")
            auto_release = args[2] if len(args) > 2 else kwargs.get("auto_release", True)
            if not all([isinstance(v, clazz) for v in value]):
                raise TypeError("value should all be int")
            if not isinstance(auto_release, bool):
                raise TypeError("auto_release should be bool")
            return proxy(args[0], elements=value, auto_release=auto_release)
        return inner
    return wrapper


class WinInjector:
    """ Process injector for ``Windows``.
    All read, write, apply, and release memory operations are completed in the injected process.
    """
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

    def _read_cs_string(self, address: int) -> str:
        if self._bit_long == 32:
            raise NotImplementedError("32bit read System.String")
        else:
            klass = self.mem_read_uint64(address)
            length = self.mem_read_uint32(klass + 0x10)
            return self.mem_read_bytes(klass + 0x14, length * 2).decode("utf-16")

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

    def _code_patch_internal(self, code: str or bytes, address: int) -> NativePatch:
        if isinstance(code, str):
            code = self.code_compile(code, address)

        origin_code = self._mem_read(address, len(code))
        return NativePatch(self, address, code, origin_code)

    def mem_alloc(self,
                  alloc_address: int = 0,
                  alloc_size: int = PAGE_SIZE,
                  alloc_type: int = MEM_COMMIT | MEM_RESERVE,
                  page_prot: int = PAGE_EXECUTE_READWRITE
                  ) -> int:
        """ Allocate memory. """
        return WinApi.VirtualAllocEx(self._h_process, alloc_address, alloc_size, alloc_type, page_prot)

    def mem_free(self, free_address: int, free_size: int = 0, free_type: int = MEM_RELEASE):
        """ Free allocated memory. """
        return WinApi.VirtualFreeEx(self._h_process, free_address, free_size, free_type)

    def mem_set_protect(self, address: int, length: int, new_protect: int = PAGE_EXECUTE_READWRITE) -> int:
        """ Set memory protection. """
        old = c_uint32()
        WinApi.VirtualProtectEx(self._h_process, address, length, new_protect, byref(old))
        return old.value

    @_register_mem_read(size=1, fmt='?')
    def mem_read_bool(self, address: int) -> bool:
        """ Read a ``bool`` value from the specified address. """
        ...

    @_register_mem_read(size=1, fmt='b')
    def mem_read_char(self, address: int) -> int:
        """ Read a ``char`` value from the specified address. """
        ...

    @_register_mem_read(size=1, fmt='B')
    def mem_read_uchar(self, address: int) -> int:
        """ Read an ``unsigned char`` value from the specified address. """
        ...

    @_register_mem_read(size=2, fmt='h')
    def mem_read_int16(self, address: int) -> int:
        """ Read a ``short`` value from the specified address. """
        ...

    @_register_mem_read(size=2, fmt='H')
    def mem_read_uint16(self, address: int) -> int:
        """ Read an ``unsigned short`` value from the specified address. """
        ...

    @_register_mem_read(size=4, fmt='i')
    def mem_read_int32(self, address: int) -> int:
        """ Read an ``int`` value from the specified address. """
        ...

    @_register_mem_read(size=4, fmt='I')
    def mem_read_uint32(self, address: int) -> int:
        """ Read an ``unsigned int`` value from the specified address. """
        ...

    @_register_mem_read(size=8, fmt='q')
    def mem_read_int64(self, address: int) -> int:
        """ Read a ``long long`` value from the specified address. """
        ...

    @_register_mem_read(size=8, fmt='Q')
    def mem_read_uint64(self, address: int) -> int:
        """ Read an ``unsigned long long`` value from the specified address. """
        ...

    @_register_mem_read(size=4, fmt='f')
    def mem_read_float(self, address: int) -> float:
        """ Read a ``float`` value from the specified address. """
        ...

    @_register_mem_read(size=8, fmt='d')
    def mem_read_double(self, address: int) -> float:
        """ Read a ``double`` value from the specified address. """
        ...

    def mem_read_pointer(self, address: int) -> int:
        """ Read a ``void*`` value from the specified address. """
        if not isinstance(address, int):
            raise TypeError("address should be int")
        if self._bit_long == 32:
            return self.mem_read_uint32(address)
        else:
            return self.mem_read_uint64(address)

    def mem_read_bytes(self, address: int, count: int) -> bytes:
        """ Read ``count`` bytes from the specified address. """
        if not isinstance(address, int):
            raise TypeError("address should be int")
        if not isinstance(count, int):
            raise TypeError("count should be int")
        if count <= 0:
            raise ValueError("count should be positive")
        return self._mem_read(address, count)

    def mem_read_c_string(self, address: int) -> str:
        """ Read a C-style string from the specified address. """
        if not isinstance(address, int):
            raise TypeError("address should be int")

        string = b''
        while True:
            char = self._mem_read(address + len(string), 1)
            if char == b'\x00':
                break
            string += char
        return string.decode()

    def mem_read_multilevel_pointer(self, base: int, offsets: List[int]) -> int:
        """ Read multilevel pointer. """
        if not isinstance(base, int):
            raise TypeError("base should be int")
        if any([not isinstance(o, int) for o in offsets]):
            raise TypeError("offsets array should all be int")
        if not offsets:
            raise ValueError("offsets array is empty")
        p = self.mem_read_pointer(base + offsets[0])
        for i in range(1, len(offsets)):
            p = self.mem_read_pointer(p + offsets[i])
        return p

    @_register_mem_read_array(proxy=BoolArray)
    def mem_read_bool_array(self, address: int, count: int) -> List[bool]:
        """ Read a ``bool`` array from the specified address. """
        ...

    @_register_mem_read_array(proxy=CharArray)
    def mem_read_char_array(self, address: int, count: int) -> List[int]:
        """ Read a ``char`` array from the specified address. """
        ...

    @_register_mem_read_array(proxy=UCharArray)
    def mem_read_uchar_array(self, address: int, count: int) -> List[int]:
        """ Read an ``unsigned char`` array from the specified address. """
        ...

    @_register_mem_read_array(proxy=Int16Array)
    def mem_read_int16_array(self, address: int, count: int) -> List[int]:
        """ Read a ``short`` array from the specified address. """
        ...

    @_register_mem_read_array(proxy=UInt16Array)
    def mem_read_uint16_array(self, address: int, count: int) -> List[int]:
        """ Read an ``unsigned short`` array from the specified address. """
        ...

    @_register_mem_read_array(proxy=Int32Array)
    def mem_read_int32_array(self, address: int, count: int) -> List[int]:
        """ Read an ``int`` array from the specified address. """
        ...

    @_register_mem_read_array(proxy=UInt32Array)
    def mem_read_uint32_array(self, address: int, count: int) -> List[int]:
        """ Read an ``unsigned int`` array from the specified address. """
        ...

    @_register_mem_read_array(proxy=Int64Array)
    def mem_read_int64_array(self, address: int, count: int) -> List[int]:
        """ Read a ``long long`` array from the specified address. """
        ...

    @_register_mem_read_array(proxy=UInt64Array)
    def mem_read_uint64_array(self, address: int, count: int) -> List[int]:
        """ Read an ``unsigned long long`` array from the specified address. """
        ...

    @_register_mem_read_array(proxy=FloatArray)
    def mem_read_float_array(self, address: int, count: int) -> List[float]:
        """ Read a ``float`` array from the specified address. """
        ...

    @_register_mem_read_array(proxy=DoubleArray)
    def mem_read_double_array(self, address: int, count: int) -> List[float]:
        """ Read a ``double`` array from the specified address. """
        ...

    @_register_mem_read_array(proxy=PointerArray)
    def mem_read_pointer_array(self, address: int, count: int) -> List[int]:
        """ Read a ``void*`` array from the specified address. """
        ...

    @_register_mem_write(clazz=bool, fmt='?')
    def mem_write_bool(self, address: int, value: bool) -> bool:
        """ Write a ``bool`` value to the specified address. """
        ...

    @_register_mem_write(clazz=int, fmt='b')
    def mem_write_char(self, address: int, value: int) -> bool:
        """ Write a ``char`` value to the specified address. """
        ...

    @_register_mem_write(clazz=int, fmt='B')
    def mem_write_uchar(self, address: int, value: int) -> bool:
        """ Write an ``unsigned char`` value to the specified address. """
        ...

    @_register_mem_write(clazz=int, fmt='h')
    def mem_write_int16(self, address: int, value: int) -> bool:
        """ Write a ``short`` value to the specified address. """
        ...

    @_register_mem_write(clazz=int, fmt='H')
    def mem_write_uint16(self, address: int, value: int) -> bool:
        """ Write an ``unsigned short`` value to the specified address. """
        ...

    @_register_mem_write(clazz=int, fmt='i')
    def mem_write_int32(self, address: int, value: int) -> bool:
        """ Write an ``int`` value to the specified address. """
        ...

    @_register_mem_write(clazz=int, fmt='I')
    def mem_write_uint32(self, address: int, value: int) -> bool:
        """ Write an ``unsigned int`` value to the specified address. """
        ...

    @_register_mem_write(clazz=int, fmt='q')
    def mem_write_int64(self, address: int, value: int) -> bool:
        """ Write a ``long long`` value to the specified address. """
        ...

    @_register_mem_write(clazz=int, fmt='Q')
    def mem_write_uint64(self, address: int, value: int) -> bool:
        """ Write an ``unsigned long long`` value to the specified address. """
        ...

    @_register_mem_write(clazz=float, fmt='f')
    def mem_write_float(self, address: int, value: float) -> bool:
        """ Write a ``float`` value to the specified address. """
        ...

    @_register_mem_write(clazz=float, fmt='d')
    def mem_write_double(self, address: int, value: float) -> bool:
        """ Write a ``double`` value to the specified address. """
        ...

    def mem_write_pointer(self, address: int, value: int) -> int:
        """ Write a ``void*`` value to the specified address. """
        if not isinstance(address, int):
            raise TypeError("address should be int")
        if not isinstance(value, int):
            raise TypeError("value should be int")
        if self._bit_long == 32:
            return self.mem_write_uint32(address, value)
        else:
            return self.mem_write_uint64(address, value)

    def mem_write_bytes(self, address: int, value: bytes) -> int:
        """ Write a byte array to the specified address. """
        if not isinstance(address, int):
            raise TypeError("address should be int")
        if not isinstance(value, bytes):
            raise TypeError("value should be bytes")
        if len(value) == 0:
            raise ValueError("value length should be positive")
        return self._mem_write(address, value)

    def mem_write_c_string(self, address: int, value: str) -> bool:
        """ Write a C-style string to the specified address. (Automatically add ``\\x00``) """
        if len(value) == 0:
            to_write = b'\x00'
        else:
            to_write = value.encode(errors="ignore") + b'\x00'
        return self.mem_write_bytes(address, to_write) == len(value) + 1

    @_register_mem_write_array(proxy=BoolArray)
    def mem_write_bool_array(self, address: int, elements: List[int]) -> bool:
        """ Write a ``bool`` array to the specified address. """
        ...

    @_register_mem_write_array(proxy=CharArray)
    def mem_write_char_array(self, address: int, elements: List[int]) -> bool:
        """ Write a ``char`` array to the specified address. """
        ...

    @_register_mem_write_array(proxy=UCharArray)
    def mem_write_uchar_array(self, address: int, elements: List[int]) -> bool:
        """ Write an ``unsigned char`` array to the specified address. """
        ...

    @_register_mem_write_array(proxy=Int16Array)
    def mem_write_int16_array(self, address: int, elements: List[int]) -> bool:
        """ Write a ``short`` array to the specified address. """
        ...

    @_register_mem_write_array(proxy=UInt16Array)
    def mem_write_uint16_array(self, address: int, elements: List[int]) -> bool:
        """ Write an ``unsigned short`` array to the specified address. """
        ...

    @_register_mem_write_array(proxy=Int32Array)
    def mem_write_int32_array(self, address: int, elements: List[int]) -> bool:
        """ Write an ``int`` array to the specified address. """
        ...

    @_register_mem_write_array(proxy=UInt32Array)
    def mem_write_uint32_array(self, address: int, elements: List[int]) -> bool:
        """ Write an ``unsigned int`` array to the specified address. """
        ...

    @_register_mem_write_array(proxy=Int64Array)
    def mem_write_int64_array(self, address: int, elements: List[int]) -> bool:
        """ Write a ``long long`` array to the specified address. """
        ...

    @_register_mem_write_array(proxy=UInt64Array)
    def mem_write_uint64_array(self, address: int, elements: List[int]) -> bool:
        """ Write an ``unsigned long long`` array to the specified address. """
        ...

    @_register_mem_write_array(proxy=FloatArray)
    def mem_write_float_array(self, address: int, elements: List[float]) -> bool:
        """ Write a ``float`` array to the specified address. """
        ...

    @_register_mem_write_array(proxy=DoubleArray)
    def mem_write_double_array(self, address: int, elements: List[float]) -> bool:
        """ Write a ``double`` array to the specified address. """
        ...

    @_register_mem_write_array(proxy=PointerArray)
    def mem_write_pointer_array(self, address: int, elements: List[int]) -> bool:
        """ Write a ``void*`` array from to specified address. """
        ...

    @_register_new_basic_type(clazz=bool, proxy=Bool)
    def new_bool(self, value: bool, auto_release: bool = True) -> Bool:
        """ New a ``bool``

        :param value: initial value
        :param auto_release: whether to delete automatically

        If ``auto_release`` is set to ``True``, the life cycle of this newly allocated memory is the same as the ``Bool`` instance.
        Otherwise, you can release it manually later by calling ``Bool.release()``.

        Examples:
        
        .. code-block:: python

            from uniref import *

            ref = WinUniRef("game.exe")

            def auto_release_sample():
                bool_1 = ref.injector.new_bool(True)
                bool_2 = ref.injector.new_bool(True, auto_release=False)
                bool_3 = ref.injector.new_bool(True, auto_release=False)

                # ...

                bool_2.auto_release = True
                return bool_3

            manual_bool = auto_release_sample()
            # bool_1 and bool_2 have been released
            # now release bool_3 manually
            manual_bool.release()
        """
        ...

    @_register_new_basic_type(clazz=int, proxy=Char)
    def new_char(self, value: int, auto_release: bool = True) -> Char:
        """ New a ``char`` variable. Check ``new_bool``'s description for more details. """
        ...

    @_register_new_basic_type(clazz=int, proxy=UChar)
    def new_uchar(self, value: int, auto_release: bool = True) -> UChar:
        """ New an ``unsigned char`` variable. Check ``new_bool``'s description for more details. """
        ...

    @_register_new_basic_type(clazz=int, proxy=Int16)
    def new_int16(self, value: int, auto_release: bool = True) -> Int16:
        """ New a ``short`` variable. Check ``new_bool``'s description for more details. """
        ...

    @_register_new_basic_type(clazz=int, proxy=UInt16)
    def new_uint16(self, value: int, auto_release: bool = True) -> UInt16:
        """ New an ``unsigned short`` variable. Check ``new_bool``'s description for more details. """
        ...

    @_register_new_basic_type(clazz=int, proxy=Int32)
    def new_int32(self, value: int, auto_release: bool = True) -> Int32:
        """ New an ``int`` variable. Check ``new_bool``'s description for more details. """
        ...

    @_register_new_basic_type(clazz=int, proxy=UInt32)
    def new_uint32(self, value: int, auto_release: bool = True) -> UInt32:
        """ New an ``unsigned int`` variable. Check ``new_bool``'s description for more details. """
        ...

    @_register_new_basic_type(clazz=int, proxy=Int64)
    def new_int64(self, value: int, auto_release: bool = True) -> Int64:
        """ New a ``long long`` variable. Check ``new_bool``'s description for more details. """
        ...

    @_register_new_basic_type(clazz=int, proxy=UInt64)
    def new_uint64(self, value: int, auto_release: bool = True) -> UInt64:
        """ New an ``unsigned long long`` variable. Check ``new_bool``'s description for more details. """
        ...

    @_register_new_basic_type(clazz=float, proxy=Float)
    def new_float(self, value: float, auto_release: bool = True) -> Float:
        """ New a ``float`` variable. Check ``new_bool``'s description for more details. """
        ...

    @_register_new_basic_type(clazz=float, proxy=Double)
    def new_double(self, value: float, auto_release: bool = True) -> Double:
        """ New a ``double`` variable. Check ``new_bool``'s description for more details. """
        ...

    @_register_new_basic_type(clazz=int, proxy=Pointer)
    def new_pointer(self, value: int, auto_release: bool = True) -> Pointer:
        """ New a ``void*`` variable. Check ``new_bool``'s description for more details. """
        ...

    @_register_new_basic_type(clazz=str, proxy=CString)
    def new_c_string(self, value: str, auto_release: bool = True) -> CString:
        """ New a C-style string. Check ``new_bool``'s description for more details. """
        ...

    @_register_new_array_type(clazz=bool, proxy=BoolArray)
    def new_bool_array(self, value: List[bool], auto_release: bool = True) -> BoolArray:
        """ New a ``bool`` array.
        
        :param value: list of initial values
        :param auto_release: whether to delete automatically

        If ``auto_release`` is set to ``True``, the life cycle of this newly allocated memory is the same as the ``BoolArray`` instance.
        Otherwise, you can release it manually later by calling ``BoolArray.release()``.

        Examples:
        
        .. code-block:: python

            from uniref import *

            ref = WinUniRef("game.exe")

            def auto_release_sample():
                array_1 = ref.injector.new_bool_array([True, False])
                array_2 = ref.injector.new_bool_array([True, False, True], auto_release=False)
                array_3 = ref.injector.new_bool_array([True, False, True, True], auto_release=False)

                # ...

                array_2.auto_release = True
                return array_3

            manual_array = auto_release_sample()
            # array_1 and array_2 have been released
            # now release array_3 manually
            manual_array.release()
        """
        ...

    @_register_new_array_type(clazz=int, proxy=CharArray)
    def new_char_array(self, value: List[int], auto_release: bool = True) -> CharArray:
        """ New a ``char`` array. Check ``new_bool_array``'s description for more details. """
        ...

    @_register_new_array_type(clazz=int, proxy=UCharArray)
    def new_uchar_array(self, value: List[int], auto_release: bool = True) -> UCharArray:
        """ New an ``unsigned char`` array. Check ``new_bool_array``'s description for more details. """
        ...

    @_register_new_array_type(clazz=int, proxy=Int16Array)
    def new_int16_array(self, value: List[int], auto_release: bool = True) -> Int16Array:
        """ New a ``short`` array. Check ``new_bool_array``'s description for more details. """
        ...

    @_register_new_array_type(clazz=int, proxy=UInt16Array)
    def new_uint16_array(self, value: List[int], auto_release: bool = True) -> UInt16Array:
        """ New an ``unsigned short`` array. Check ``new_bool_array``'s description for more details. """
        ...

    @_register_new_array_type(clazz=int, proxy=Int32Array)
    def new_int32_array(self, value: List[int], auto_release: bool = True) -> Int32Array:
        """ New an ``int`` array. Check ``new_bool_array``'s description for more details. """
        ...

    @_register_new_array_type(clazz=int, proxy=UInt32Array)
    def new_uint32_array(self, value: List[int], auto_release: bool = True) -> UInt32Array:
        """ New an ``unsigned int`` array. Check ``new_bool_array``'s description for more details. """
        ...

    @_register_new_array_type(clazz=int, proxy=Int64Array)
    def new_int64_array(self, value: List[int], auto_release: bool = True) -> Int64Array:
        """ New a ``long long`` array. Check ``new_bool_array``'s description for more details. """
        ...

    @_register_new_array_type(clazz=int, proxy=UInt64Array)
    def new_uint64_array(self, value: List[int], auto_release: bool = True) -> UInt64Array:
        """ New an ``unsigned long long`` array. Check ``new_bool_array``'s description for more details. """
        ...

    @_register_new_array_type(clazz=float, proxy=FloatArray)
    def new_float_array(self, value: List[float], auto_release: bool = True) -> FloatArray:
        """ New a ``float`` array. Check ``new_bool_array``'s description for more details. """
        ...

    @_register_new_array_type(clazz=float, proxy=DoubleArray)
    def new_double_array(self, value: List[float], auto_release: bool = True) -> DoubleArray:
        """ New a ``double`` array. Check ``new_bool_array``'s description for more details. """
        ...

    @_register_new_array_type(clazz=int, proxy=PointerArray)
    def new_pointer_array(self, value: List[int], auto_release: bool = True) -> PointerArray:
        """ New a ``void*`` array. Check ``new_bool_array``'s description for more details. """
        ...

    def code_compile(self, code: str, address: int = 0) -> bytes:
        return self._code_compiler.compile(code, address)

    def code_patch(self, code: str or bytes, address: int) -> NativePatch:
        if not isinstance(code, (str, bytes)):
            raise TypeError("code should be str or bytes")
        if not isinstance(address, int):
            raise TypeError("address should be int")
        return self._code_patch_internal(code, address)

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
        """ Get module base by name in the injected process. """
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
