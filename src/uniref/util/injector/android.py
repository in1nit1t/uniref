import os
import frida
import struct
from typing import *
from pathlib import Path
from functools import wraps

from uniref.define.constant import *
from uniref.define.patch import NativePatch
from uniref.mono.assets import frida_type_map
from uniref.util.compiler import ArmCompiler
from uniref.util.injector.interface import Injector


def _register_mem_read(func):
    @wraps(func)
    def inner(*args, **kwargs):
        address = args[1] if len(args) > 1 else kwargs.get("address")
        if not isinstance(address, int):
            raise TypeError("address should be int")
        return func(*args, **kwargs)
    return inner


def _register_mem_write(clazz: type):
    def wrapper(func):
        @wraps(func)
        def inner(*args, **kwargs):
            address = args[1] if len(args) > 1 else kwargs.get("address")
            if not isinstance(address, int):
                raise TypeError("address should be int")
            value = args[2] if len(args) > 2 else kwargs.get("value")
            if not isinstance(value, clazz):
                raise TypeError(f"value should be {clazz.__name__}")
            return isinstance(func(*args, **kwargs), str)
        return inner
    return wrapper


class AndroidInjector(Injector):

    def __init__(
        self,
        process_name: Optional[str] = None,
        package_name: Optional[str] = None,
        device_id: Optional[str] = None
    ) -> None:
        self._agent = None
        self._session = None
        self._bit_long = 0
        self._process_id = 0

        self._device = self._find_device(device_id)
        self._session = self._attach_application(process_name, package_name)

        script_path = Path(os.path.abspath(__file__)).parent.parent.parent / "bin/android/agent.js"
        self._agent = self._session.create_script(script_path.read_text("utf-8", "ignore"))
        self._agent.load()
        self._api = self._agent.exports

        self._code_compiler = ArmCompiler(bit_long=self.bit_long)

    @property
    def bit_long(self) -> int:
        if not self._bit_long:
            self._bit_long = self._api.pointer_size() * 8
        return self._bit_long

    @property
    def process_id(self) -> int:
        if not self._process_id:
            self._process_id = self._api.pid()
        return self._process_id

    @property
    def code_compiler(self):
        return self._code_compiler

    def _find_device(self, device_id: Optional[str]) -> frida.core.Device:
        if device_id:
            device = frida.get_device(device_id)
        else:
            device = frida.get_usb_device()
        return device

    def _attach_application(self, process_name: Optional[str], package_name: Optional[str]) -> Optional[frida.core.Session]:
        if not process_name and not package_name:
            app = self._device.get_frontmost_application()
            if app:
                return self._device.attach(app.pid)
            else:
                raise ValueError("No frontmost application")

        if process_name:
            return self._device.attach(process_name)

        apps = self._device.enumerate_applications(scope="full")
        for app in apps:
            if app.identifier == package_name and app.pid:
                return self._device.attach(app.pid)
        raise ValueError("Application process not found")

    def _mem_read(self, address: int, count: int) -> bytes:
        try:
            array = self._api.read_byte_array(address, count)
        except:
            array = None
        if not array:
            raise MemoryError(f"Address {hex(address)} not readable")
        return array

    def _mem_write(self, address: int, buffer: bytes) -> int:
        try:
            ret = self._api.write_byte_array(address, list(buffer))
        except:
            ret = None
        if not ret:
            raise MemoryError(f"Address {hex(address)} not writeable")
        return len(buffer)

    def _enumerate_modules(self) -> List[dict]:
        return self._api.enumerate_modules()

    def mem_alloc(self, alloc_size: int = -1, protection: str = "rwx") -> int:
        """ Allocate memory. """
        memory = int(self._api.mem_alloc(alloc_size), 16)
        self.mem_set_protect(memory, alloc_size, protection)
        return memory & 0xFFFFFFFFFFFF

    def mem_free(self, address: int) -> None:
        """ Free allocated memory. """
        self._api.mem_free(str(address))

    def mem_set_protect(self, address: int, length: int, new_protect: str = "rwx") -> None:
        """ Set memory protection. """
        self._api.mem_protect(address, length, new_protect)

    @_register_mem_read
    def mem_read_bool(self, address: int) -> bool:
        return self._api.read_bool(address)

    @_register_mem_read
    def mem_read_char(self, address: int) -> int:
        return self._api.read_char(address)

    @_register_mem_read
    def mem_read_uchar(self, address: int) -> int:
        return self._api.read_uchar(address)

    @_register_mem_read
    def mem_read_int16(self, address: int) -> int:
        return self._api.read_int16(address)

    @_register_mem_read
    def mem_read_uint16(self, address: int) -> int:
        return self._api.read_uint16(address)

    @_register_mem_read
    def mem_read_int32(self, address: int) -> int:
        return self._api.read_int32(address)

    @_register_mem_read
    def mem_read_uint32(self, address: int) -> int:
        return self._api.read_uint32(address)

    @_register_mem_read
    def mem_read_int64(self, address: int) -> int:
        return struct.unpack("q", self._mem_read(address, 8))[0]

    @_register_mem_read
    def mem_read_uint64(self, address: int) -> int:
        return struct.unpack("Q", self._mem_read(address, 8))[0]

    @_register_mem_read
    def mem_read_float(self, address: int) -> float:
        return self._api.read_float(address)

    @_register_mem_read
    def mem_read_double(self, address: int) -> float:
        return self._api.read_double(address)

    @_register_mem_read
    def mem_read_pointer(self, address: int) -> int:
        return int(self._api.read_pointer(address), 16) & 0xFFFFFFFFFFFF

    @_register_mem_read
    def mem_read_c_string(self, address: int) -> str:
        return self._api.read_c_string(address)

    @_register_mem_write(clazz=bool)
    def mem_write_bool(self, address: int, value: bool) -> bool:
        return self._api.write_bool(address, 1 if value else 0)

    @_register_mem_write(clazz=int)
    def mem_write_char(self, address: int, value: int) -> bool:
        return self._api.write_char(address, value)

    @_register_mem_write(clazz=int)
    def mem_write_uchar(self, address: int, value: int) -> bool:
        return self._api.write_uchar(address, value)

    @_register_mem_write(clazz=int)
    def mem_write_int16(self, address: int, value: int) -> bool:
        return self._api.write_int16(address, value)

    @_register_mem_write(clazz=int)
    def mem_write_uint16(self, address: int, value: int) -> bool:
        return self._api.write_uint16(address, value)

    @_register_mem_write(clazz=int)
    def mem_write_int32(self, address: int, value: int) -> bool:
        return self._api.write_int32(address, value)

    @_register_mem_write(clazz=int)
    def mem_write_uint32(self, address: int, value: int) -> bool:
        return self._api.write_uint32(address, value)

    def mem_write_int64(self, address: int, value: int) -> bool:
        if not isinstance(address, int):
            raise TypeError("address should be int")
        if not isinstance(value, int):
            raise TypeError(f"value should be int")
        return self._mem_write(address, struct.pack("q", value)) == 8

    def mem_write_uint64(self, address: int, value: int) -> bool:
        if not isinstance(address, int):
            raise TypeError("address should be int")
        if not isinstance(value, int):
            raise TypeError(f"value should be int")
        return self._mem_write(address, struct.pack("Q", value)) == 8

    @_register_mem_write(clazz=float)
    def mem_write_float(self, address: int, value: float) -> bool:
        return self._api.write_float(address, value)

    @_register_mem_write(clazz=float)
    def mem_write_double(self, address: int, value: float) -> bool:
        return self._api.write_double(address, value)

    @_register_mem_write(clazz=int)
    def mem_write_pointer(self, address: int, value: int) -> int:
        return self._api.write_pointer(address, value & 0xFFFFFFFFFFFF)

    @_register_mem_write(clazz=str)
    def mem_write_c_string(self, address: int, value: str) -> bool:
        return self._api.write_utf8_string(address, value)

    def get_module_base(self, module_name: str) -> int:
        if not isinstance(module_name, str):
            raise TypeError("module_name should be str")
        address = self._api.find_base_address(module_name)
        if isinstance(address, str):
            return int(address, 16)
        return 0

    def get_proc_address(self, module_name: str, proc_name: str) -> int:
        """ Get module exported function address in the injected process. """
        if not isinstance(proc_name, str):
            raise TypeError("proc_name should be str")
        if not isinstance(module_name, str):
            raise TypeError("module_name should be str")

        address = self._api.find_export_by_name(module_name, proc_name)
        if isinstance(address, str):
            return int(address, 16)
        return 0

    def call_native_function(self, func_address: int, args: Tuple[int], ret_type: int, call_type: int) -> Any:
        if not isinstance(func_address, int):
            raise TypeError("func_address should be int")
        if not isinstance(args, tuple):
            raise TypeError("args should be a tuple of int")
        if not isinstance(ret_type, int):
            raise TypeError("ret_type should be int")
        if func_address <= 0:
            raise ValueError("func_address should be positive")
        if ret_type not in range(TYPE_CS_STRING + 1):
            raise ValueError(f"Unsupported return type")

        real_ret_type = frida_type_map.get(ret_type, "void")

        argc = len(args)
        if argc == 0:
            ret_val = self._api.call_void_nf(func_address, real_ret_type)
        elif argc == 1:
            ret_val = self._api.call_nf_i(func_address, real_ret_type, *args)
        elif argc == 2:
            ret_val = self._api.call_nf_i_i(func_address, real_ret_type, *args)
        elif argc == 3:
            ret_val = self._api.call_nf_i_i_i(func_address, real_ret_type, *args)
        elif argc == 4:
            ret_val = self._api.call_nf_i_v(func_address, real_ret_type, *args)
        elif argc == 5:
            ret_val = self._api.call_nf_v(func_address, real_ret_type, *args)
        else:
            raise NotImplementedError("Too many parameters (more than 5)")

        if ret_type == TYPE_BOOL:
            real_ret_val = ret_val != 0
        elif ret_type == TYPE_VOID_P:
            real_ret_val = int(ret_val, 16) & 0xFFFFFFFFFFFF
        elif ret_type == TYPE_CHAR_P:
            real_ret_val = self.mem_read_c_string(int(ret_val, 16) & 0xFFFFFFFFFFFF)
        elif ret_type == TYPE_CS_STRING:
            real_ret_val = self._read_cs_string(ret_val & 0xFFFFFFFFFFFF)
        else:
            real_ret_val = ret_val
        return real_ret_val

    def code_nop(self, address: int, size: int) -> NativePatch:
        real_size = (size + 3) // 4
        if self.bit_long == 32:
            nop = b"\x00\x00\x80\xE2"
        else:
            nop = b"\xE0\x03\x00\xAA"
        return self.code_patch(nop * real_size, address)
