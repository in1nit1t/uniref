from typing import *


class _BasicType:
    """ Base class of ``Bool``, ``Char``, ``UChar``, ``Int16``, ``UInt16``, ``Int32``, ``UInt32``,
    ``Int64``, ``UInt64``, ``Float``, ``Double`` and ``Pointer``.
    
    Examples:

    >>> from uniref import WinUniRef
    >>> ref = WinUniRef("game.exe") 
    >>> int32 = ref.injector.new_int32(1) 
    >>> type(int32) 
    <class 'uniref.define.types.Int32'>
    >>> hex(int32.address)
    '0xd00000'
    >>> int32.value
    1
    >>> int32.value = 12345
    >>> int32.value
    12345
    >>> int32.release()

    """
    def __init__(self, injector: object, value: Any, elem_size: int, auto_release: bool = True) -> None:
        self._injector = injector
        if elem_size <= 0:
            raise ValueError("Element size should be positive")
        self._value = value
        self._elem_size = elem_size
        self._auto_release = auto_release

        self._address = self._injector.mem_alloc(alloc_size=elem_size, protection="rw-")
        self._assign_value()

    def __del__(self):
        if self._auto_release:
            self.release()

    @property
    def value(self) -> int:
        """ variable value """
        if self._address == 0:
            raise MemoryError(f"Memory has been freed")
        return self._do_read(self._address)

    @value.setter
    def value(self, value: Any) -> None:
        self.set_value(value)

    def set_value(self, value: Any) -> None:
        """ Set variable value. """
        self._value = value
        self._assign_value()

    @property
    def address(self) -> int:
        """ variable address """
        return self._address

    @property
    def auto_release(self) -> bool:
        """ auto release """
        return self._auto_release

    @auto_release.setter
    def auto_release(self, value: bool) -> None:
        self.set_auto_release(value)

    def set_auto_release(self, value: bool) -> None:
        """ Set whether to release automatically. """
        if not isinstance(value, bool):
            raise TypeError("auto_release should be bool")
        self._auto_release = value

    def _assign_value(self) -> None:
        if self._address == 0:
            raise MemoryError(f"Memory has been freed")
        self._do_write(self._address, self._value)

    def release(self) -> None:
        """ Release the memory. """
        if self._address:
            self._injector.mem_free(self._address)
            self._address = 0


class Bool(_BasicType):

    def __init__(self, injector: object, value: bool, auto_release: bool = True) -> None:
        self._do_read = injector.mem_read_bool
        self._do_write = injector.mem_write_bool
        super(Bool, self).__init__(injector, value, 1, auto_release)


class Char(_BasicType):

    def __init__(self, injector: object, value: int, auto_release: bool = True) -> None:
        self._do_read = injector.mem_read_char
        self._do_write = injector.mem_write_char
        super(Char, self).__init__(injector, value, 1, auto_release)


class UChar(_BasicType):

    def __init__(self, injector: object, value: int, auto_release: bool = True) -> None:
        self._do_read = injector.mem_read_uchar
        self._do_write = injector.mem_write_uchar
        super(UChar, self).__init__(injector, value, 1, auto_release)


class Int16(_BasicType):

    def __init__(self, injector: object, value: int, auto_release: bool = True) -> None:
        self._do_read = injector.mem_read_int16
        self._do_write = injector.mem_write_int16
        super(Int16, self).__init__(injector, value, 2, auto_release)


class UInt16(_BasicType):

    def __init__(self, injector: object, value: int, auto_release: bool = True) -> None:
        self._do_read = injector.mem_read_uint16
        self._do_write = injector.mem_write_uint16
        super(UInt16, self).__init__(injector, value, 2, auto_release)


class Int32(_BasicType):

    def __init__(self, injector: object, value: int, auto_release: bool = True) -> None:
        self._do_read = injector.mem_read_int32
        self._do_write = injector.mem_write_int32
        super(Int32, self).__init__(injector, value, 4, auto_release)


class UInt32(_BasicType):

    def __init__(self, injector: object, value: int, auto_release: bool = True) -> None:
        self._do_read = injector.mem_read_uint32
        self._do_write = injector.mem_write_uint32
        super(UInt32, self).__init__(injector, value, 4, auto_release)


class Int64(_BasicType):

    def __init__(self, injector: object, value: int, auto_release: bool = True) -> None:
        self._do_read = injector.mem_read_int64
        self._do_write = injector.mem_write_int64
        super(Int64, self).__init__(injector, value, 8, auto_release)


class UInt64(_BasicType):

    def __init__(self, injector: object, value: int, auto_release: bool = True) -> None:
        self._do_read = injector.mem_read_uint64
        self._do_write = injector.mem_write_uint64
        super(UInt64, self).__init__(injector, value, 8, auto_release)


class Float(_BasicType):

    def __init__(self, injector: object, value: float, auto_release: bool = True) -> None:
        self._do_read = injector.mem_read_float
        self._do_write = injector.mem_write_float
        super(Float, self).__init__(injector, value, 4, auto_release)


class Double(_BasicType):

    def __init__(self, injector: object, value: float, auto_release: bool = True) -> None:
        self._do_read = injector.mem_read_double
        self._do_write = injector.mem_write_double
        super(Double, self).__init__(injector, value, 8, auto_release)


class Pointer(_BasicType):

    def __init__(self, injector: object, value: int, auto_release: bool = True):
        self._do_read = injector.mem_read_pointer
        self._do_write = injector.mem_write_pointer
        elem_size = 4 if injector.bit_long == 32 else 8
        super(Pointer, self).__init__(injector, value, elem_size, auto_release)


class _ArrayType:
    """ Base class of ``BoolArray``, ``CharArray``, ``UCharArray``, ``Int16Array``, ``UInt16Array``,
    ``Int32Array``, ``UInt32Array``, ``Int64Array``, ``UInt64Array``, ``FloatArray``, ``DoubleArray`` and ``PointerArray``.

    Examples:

    >>> from uniref import WinUniRef
    >>> ref = WinUniRef("game.exe") 
    >>> array = ref.injector.new_double_array([1.5, 5.1, 9.2])
    >>> type(array) 
    <class 'uniref.define.types.DoubleArray'>
    >>> hex(array.address)
    '0xe00000'
    >>> array.elem_count
    3
    >>> array.elements
    [1.5, 5.1, 9.2]
    >>> array[0]
    1.5
    >>> array[0] = 2.5
    >>> array.elements
    [2.5, 5.1, 9.2]
    >>> array.elements = [0.1, 0.2, 0.3]
    >>> array.elements
    [0.1, 0.2, 0.3]
    >>> array.release()

    """
    def __init__(
            self,
            injector: object,
            elem_size: int,
            address: int = 0,
            element_count: int = 0,
            elements: Optional[List[Any]] = None,
            auto_release: bool = True
    ) -> None:
        self._injector = injector
        if elem_size <= 0:
            raise ValueError("Element size should be positive")
        self._elem_size = elem_size

        if elements:
            elem_count = len(elements)
        else:
            elem_count = element_count
        if elem_count <= 0:
            raise ValueError("Array is empty")
        if address > 0:
            self._address = address
        else:
            self._address = self._injector.mem_alloc(alloc_size=elem_size * elem_count, protection="rw-")

        self._elements = elements
        self._elem_count = elem_count
        self._auto_release = auto_release

        if elements:
            self._assign_array()

    def __del__(self):
        if self._auto_release:
            self.release()

    def __getitem__(self, idx: int) -> Any:
        if not isinstance(idx, int):
            raise TypeError("Use int as array index")
        if idx >= self._elem_count:
            raise IndexError(f"Index is greater than array size")
        if self._address == 0:
            raise MemoryError(f"Memory has been freed")
        return self._do_read(self._address + self._elem_size * idx)

    def __setitem__(self, idx: int, value: Any) -> None:
        if not isinstance(idx, int):
            raise TypeError("Use int as array index")
        if idx >= self._elem_count:
            raise IndexError(f"Index is greater than array size")
        if self._address == 0:
            raise MemoryError(f"Memory has been freed")
        self._do_write(self._address + self._elem_size * idx, value)

    @property
    def address(self) -> int:
        """ array address """
        return self._address

    @property
    def elements(self) -> List[Any]:
        """ array elements """
        if self._address == 0:
            raise MemoryError(f"Memory has been freed")
        elements = []
        for i in range(self._elem_count):
            elements.append(self._do_read(self._address + self._elem_size * i))
        return elements

    @elements.setter
    def elements(self, value: List[Any]) -> None:
        self.set_elements(value)

    def set_elements(self, value: List[Any]) -> None:
        """ Update array elements. """
        if not isinstance(value, list):
            raise TypeError("Elements should be list")
        if len(value) != self._elem_count:
            raise ValueError("Size of the new array is different from the original length")
        self._elements = value
        self._assign_array()

    @property
    def elem_size(self) -> int:
        return self._elem_size

    @property
    def elem_count(self) -> int:
        """ number of array elements """
        return self._elem_count

    @property
    def auto_release(self) -> bool:
        """ auto release """
        return self._auto_release

    @auto_release.setter
    def auto_release(self, value: bool) -> None:
        self.set_auto_release(value)

    def set_auto_release(self, value: bool) -> None:
        """ Set whether to release automatically. """
        if not isinstance(value, bool):
            raise TypeError("auto_release should be bool")
        self._auto_release = value

    def _assign_array(self) -> None:
        if self._address == 0:
            raise MemoryError(f"Memory has been freed")
        for i in range(self._elem_count):
            self._do_write(self._address + self._elem_size * i, self._elements[i])

    def release(self) -> None:
        """ Release the memory. """
        if self._address:
            self._injector.mem_free(self._address)
            self._address = 0


class BoolArray(_ArrayType):

    def __init__(
            self,
            injector: object,
            address: int = 0,
            element_count: int = 0,
            elements: Optional[List[bool]] = None,
            auto_release: bool = True
    ) -> None:
        self._do_read = injector.mem_read_bool
        self._do_write = injector.mem_write_bool
        super(BoolArray, self).__init__(injector, 1, address, element_count, elements, auto_release)


class CharArray(_ArrayType):

    def __init__(
            self,
            injector: object,
            address: int = 0,
            element_count: int = 0,
            elements: Optional[List[int]] = None,
            auto_release: bool = True
    ) -> None:
        self._do_read = injector.mem_read_char
        self._do_write = injector.mem_write_char
        super(CharArray, self).__init__(injector, 1, address, element_count, elements, auto_release)


class UCharArray(_ArrayType):

    def __init__(
            self,
            injector: object,
            address: int = 0,
            element_count: int = 0,
            elements: Optional[List[int]] = None,
            auto_release: bool = True
    ) -> None:
        self._do_read = injector.mem_read_uchar
        self._do_write = injector.mem_write_uchar
        super(UCharArray, self).__init__(injector, 1, address, element_count, elements, auto_release)


class Int16Array(_ArrayType):

    def __init__(
            self,
            injector: object,
            address: int = 0,
            element_count: int = 0,
            elements: Optional[List[int]] = None,
            auto_release: bool = True
    ) -> None:
        self._do_read = injector.mem_read_int16
        self._do_write = injector.mem_write_int16
        super(Int16Array, self).__init__(injector, 2, address, element_count, elements, auto_release)


class UInt16Array(_ArrayType):

    def __init__(
            self,
            injector: object,
            address: int = 0,
            element_count: int = 0,
            elements: Optional[List[int]] = None,
            auto_release: bool = True
    ) -> None:
        self._do_read = injector.mem_read_uint16
        self._do_write = injector.mem_write_uint16
        super(UInt16Array, self).__init__(injector, 2, address, element_count, elements, auto_release)


class Int32Array(_ArrayType):

    def __init__(
            self,
            injector: object,
            address: int = 0,
            element_count: int = 0,
            elements: Optional[List[int]] = None,
            auto_release: bool = True
    ) -> None:
        self._do_read = injector.mem_read_int32
        self._do_write = injector.mem_write_int32
        super(Int32Array, self).__init__(injector, 4, address, element_count, elements, auto_release)


class UInt32Array(_ArrayType):

    def __init__(
            self,
            injector: object,
            address: int = 0,
            element_count: int = 0,
            elements: Optional[List[int]] = None,
            auto_release: bool = True
    ) -> None:
        self._do_read = injector.mem_read_uint32
        self._do_write = injector.mem_write_uint32
        super(UInt32Array, self).__init__(injector, 4, address, element_count, elements, auto_release)


class Int64Array(_ArrayType):

    def __init__(
            self,
            injector: object,
            address: int = 0,
            element_count: int = 0,
            elements: Optional[List[int]] = None,
            auto_release: bool = True
    ) -> None:
        self._do_read = injector.mem_read_int64
        self._do_write = injector.mem_write_int64
        super(Int64Array, self).__init__(injector, 8, address, element_count, elements, auto_release)


class UInt64Array(_ArrayType):

    def __init__(
            self,
            injector: object,
            address: int = 0,
            element_count: int = 0,
            elements: Optional[List[int]] = None,
            auto_release: bool = True
    ) -> None:
        self._do_read = injector.mem_read_uint64
        self._do_write = injector.mem_write_uint64
        super(UInt64Array, self).__init__(injector, 8, address, element_count, elements, auto_release)


class FloatArray(_ArrayType):

    def __init__(
            self,
            injector: object,
            address: int = 0,
            element_count: int = 0,
            elements: Optional[List[float]] = None,
            auto_release: bool = True
    ) -> None:
        self._do_read = injector.mem_read_float
        self._do_write = injector.mem_write_float
        super(FloatArray, self).__init__(injector, 4, address, element_count, elements, auto_release)


class DoubleArray(_ArrayType):

    def __init__(
            self,
            injector: object,
            address: int = 0,
            element_count: int = 0,
            elements: Optional[List[float]] = None,
            auto_release: bool = True
    ) -> None:
        self._do_read = injector.mem_read_double
        self._do_write = injector.mem_write_double
        super(DoubleArray, self).__init__(injector, 8, address, element_count, elements, auto_release)


class PointerArray(_ArrayType):

    def __init__(
            self,
            injector: object,
            address: int = 0,
            element_count: int = 0,
            elements: Optional[List[int]] = None,
            auto_release: bool = True
    ):
        address &= 0xFFFFFFFFFFFF
        self._do_read = injector.mem_read_pointer
        self._do_write = injector.mem_write_pointer
        elem_size = 4 if injector.bit_long == 32 else 8
        super(PointerArray, self).__init__(injector, elem_size, address, element_count, elements, auto_release)


class CString:
    """ This class's instance is returned by calling ``Injector.new_c_string`` """

    def __init__(self, injector: object, value: str, auto_release: bool = True):
        self._injector = injector
        self._value = value
        self._auto_release = auto_release

        self._address = self._injector.mem_alloc(alloc_size=len(value) + 1, protection="rw-")
        self._assign_value()

    def __del__(self):
        if self._auto_release:
            self.release()

    @property
    def value(self) -> str:
        """ string value """
        if self._address == 0:
            raise MemoryError(f"Memory has been freed")
        return self._injector.mem_read_c_string(self._address)

    @value.setter
    def value(self, value: str) -> None:
        raise NotImplementedError("CString is not editable")

    @property
    def address(self) -> int:
        """ string address """
        return self._address

    @property
    def auto_release(self) -> bool:
        """ auto release """
        return self._auto_release

    @auto_release.setter
    def auto_release(self, value: bool) -> None:
        self.set_auto_release(value)

    def set_auto_release(self, value: bool) -> None:
        """ Set whether to release automatically. """
        if not isinstance(value, bool):
            raise TypeError("auto_release should be bool")
        self._auto_release = value

    def _assign_value(self) -> None:
        if self._address == 0:
            raise MemoryError(f"Memory has been freed")
        self._injector.mem_write_c_string(self._address, self._value)

    def release(self) -> None:
        """ Release the memory. """
        if self._address:
            self._injector.mem_free(self._address)
            self._address = 0
