from functools import wraps
from abc import ABCMeta, abstractmethod

from uniref.define.types import *
from uniref.define.patch import NativePatch


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


class Injector(metaclass=ABCMeta):
    """
    Process injector interface.
    All read, write, apply, and release memory operations are completed in the injected process.
    """

    @property
    def bit_long(self) -> int:
        """ Application bit long """
        raise NotImplementedError

    @property
    def process_id(self) -> int:
        """ PID """
        raise NotImplementedError

    @property
    def code_compiler(self):
        raise NotImplementedError

    @abstractmethod
    def _mem_read(self, address: int, count: int) -> bytes:
        ...

    @abstractmethod
    def _mem_write(self, address: int, buffer: bytes) -> int:
        ...

    @abstractmethod
    def mem_alloc(self, alloc_size: int, protection: str = "rwx") -> int:
        """ Allocate memory.

        .. note::
            This method has different parameters on different platforms.
        """
        ...

    @abstractmethod
    def mem_free(self, address: int) -> None:
        """ Free allocated memory.

        .. note::
            This method has different parameters on different platforms.
        """
        ...

    @abstractmethod
    def mem_set_protect(self, address: int, length: int, new_protect: str) -> Optional[str]:
        """ Set memory protection.

        .. note::
            This method has different parameters on different platforms.
        """
        ...

    @abstractmethod
    def mem_read_bool(self, address: int) -> bool:
        """ Read a ``bool`` value from the specified address. """
        ...

    @abstractmethod
    def mem_read_char(self, address: int) -> int:
        """ Read a ``char`` value from the specified address. """
        ...

    @abstractmethod
    def mem_read_uchar(self, address: int) -> int:
        """ Read an ``unsigned char`` value from the specified address. """
        ...

    @abstractmethod
    def mem_read_int16(self, address: int) -> int:
        """ Read a ``short`` value from the specified address. """
        ...

    @abstractmethod
    def mem_read_uint16(self, address: int) -> int:
        """ Read an ``unsigned short`` value from the specified address. """
        ...

    @abstractmethod
    def mem_read_int32(self, address: int) -> int:
        """ Read an ``int`` value from the specified address. """
        ...

    @abstractmethod
    def mem_read_uint32(self, address: int) -> int:
        """ Read an ``unsigned int`` value from the specified address. """
        ...

    @abstractmethod
    def mem_read_int64(self, address: int) -> int:
        """ Read a ``long long`` value from the specified address. """
        ...

    @abstractmethod
    def mem_read_uint64(self, address: int) -> int:
        """ Read an ``unsigned long long`` value from the specified address. """
        ...

    @abstractmethod
    def mem_read_float(self, address: int) -> float:
        """ Read a ``float`` value from the specified address. """
        ...

    @abstractmethod
    def mem_read_double(self, address: int) -> float:
        """ Read a ``double`` value from the specified address. """
        ...

    @abstractmethod
    def mem_read_pointer(self, address: int) -> int:
        """ Read a ``void*`` value from the specified address. """
        ...

    @abstractmethod
    def mem_read_c_string(self, address: int) -> str:
        """ Read a C-style string from the specified address. """
        ...

    @abstractmethod
    def mem_write_bool(self, address: int, value: bool) -> bool:
        """ Write a ``bool`` value to the specified address. """
        ...

    @abstractmethod
    def mem_write_char(self, address: int, value: int) -> bool:
        """ Write a ``char`` value to the specified address. """
        ...

    @abstractmethod
    def mem_write_uchar(self, address: int, value: int) -> bool:
        """ Write an ``unsigned char`` value to the specified address. """
        ...

    @abstractmethod
    def mem_write_int16(self, address: int, value: int) -> bool:
        """ Write a ``short`` value to the specified address. """
        ...

    @abstractmethod
    def mem_write_uint16(self, address: int, value: int) -> bool:
        """ Write an ``unsigned short`` value to the specified address. """
        ...

    @abstractmethod
    def mem_write_int32(self, address: int, value: int) -> bool:
        """ Write an ``int`` value to the specified address. """
        ...

    @abstractmethod
    def mem_write_uint32(self, address: int, value: int) -> bool:
        """ Write an ``unsigned int`` value to the specified address. """
        ...

    @abstractmethod
    def mem_write_int64(self, address: int, value: int) -> bool:
        """ Write a ``long long`` value to the specified address. """
        ...

    @abstractmethod
    def mem_write_uint64(self, address: int, value: int) -> bool:
        """ Write an ``unsigned long long`` value to the specified address. """
        ...

    @abstractmethod
    def mem_write_float(self, address: int, value: float) -> bool:
        """ Write a ``float`` value to the specified address. """
        ...

    @abstractmethod
    def mem_write_double(self, address: int, value: float) -> bool:
        """ Write a ``double`` value to the specified address. """
        ...

    @abstractmethod
    def mem_write_pointer(self, address: int, value: int) -> int:
        """ Write a ``void*`` value to the specified address. """
        ...

    @abstractmethod
    def mem_write_c_string(self, address: int, value: str) -> bool:
        """ Write a C-style string to the specified address. (Automatically add ``\\x00``) """
        ...

    @abstractmethod
    def get_module_base(self, module_name: str) -> int:
        """ Get module base by name in the injected process. """
        ...

    @abstractmethod
    def get_proc_address(self) -> int:
        """ Get module exported function address in the injected process.

        .. note::
            This method has different parameters on different platforms.
        """
        ...

    @abstractmethod
    def call_native_function(self, func_address: int, args: Tuple[int], ret_type: int, call_type: int) -> Any:
        ...

    @abstractmethod
    def code_nop(self, address: int, size: int) -> NativePatch:
        ...

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

    def _read_cs_string(self, address: int) -> str:
        if self.bit_long == 32:
            raise NotImplementedError("32-bit read System.String")
        else:
            klass = self.mem_read_uint64(address)
            length = self.mem_read_uint32(klass + 0x10)
            return self.mem_read_bytes(klass + 0x14, length * 2).decode("utf-16")

    def _code_patch_internal(self, code: str or bytes, address: int) -> NativePatch:
        if isinstance(code, str):
            code = self.code_compile(code, address)

        origin_code = self._mem_read(address, len(code))
        return NativePatch(self, address, code, origin_code)

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

    def mem_read_bytes(self, address: int, count: int) -> bytes:
        """ Read ``count`` bytes from the specified address. """
        if not isinstance(address, int):
            raise TypeError("address should be int")
        if not isinstance(count, int):
            raise TypeError("count should be int")
        if count <= 0:
            raise ValueError("count should be positive")
        return self._mem_read(address, count)

    def mem_write_bytes(self, address: int, value: bytes) -> int:
        """ Write a byte array to the specified address. """
        if not isinstance(address, int):
            raise TypeError("address should be int")
        if not isinstance(value, bytes):
            raise TypeError("value should be bytes")
        if len(value) == 0:
            raise ValueError("value length should be positive")
        return self._mem_write(address, value)

    def code_compile(self, code: str, address: int = 0) -> bytes:
        return self.code_compiler.compile(code, address)

    def code_patch(self, code: str or bytes, address: int) -> NativePatch:
        if not isinstance(code, (str, bytes)):
            raise TypeError("code should be str or bytes")
        if not isinstance(address, int):
            raise TypeError("address should be int")
        return self._code_patch_internal(code, address)
