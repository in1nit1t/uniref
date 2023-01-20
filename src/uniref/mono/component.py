from typing import *

from uniref.mono.assets import *
from uniref.define.constant import *
from uniref.define.patch import NativePatch


class MonoNativeFunc:

    def __init__(self, func_name: str, il2cpp: bool, arg_cnt: int = 0, ret_type: int = TYPE_VOID) -> None:
        self._func_name = func_name
        self._il2cpp = il2cpp
        self._arg_cnt = arg_cnt
        self._ret_type = ret_type

        self._func_address = 0
        self._mono_injector = None

    def __call__(self, *args, **kwargs) -> int:
        if self._mono_injector is None:
            raise _MonoNativeError("mono_injector is NULL")
        if self._func_address == 0:
            raise _MonoNativeError(f"Function {self._func_name} not found")

        if self._il2cpp:
            arg_cnt, ret_type = il2cpp_native_func_property[self._func_name]
        else:
            arg_cnt, ret_type = mono_native_func_property[self._func_name]
        if len(args) != arg_cnt:
            raise _MonoNativeError(f"Function {self._func_name} needs {arg_cnt} parameter(s)")
        args = args[:arg_cnt]
        if not all([isinstance(arg, int) for arg in args]):
            raise _MonoNativeError(f"Native function arguments should all be int in Python")
        return self._mono_injector.call_native_function(self._func_address, args, ret_type, CALL_TYPE_CDECL)

    @property
    def name(self) -> str:
        if self._il2cpp:
            return "il2cpp" + self._func_name[4:]
        return self._func_name

    @property
    def address(self) -> int:
        return self._func_address

    def callable(self) -> bool:
        return self._func_address != 0

    def set_address(self, address: int) -> None:
        self._func_address = address

    def set_mono_injector(self, injector: object) -> None:
        self._mono_injector = injector


class MonoNativeFuncSet:

    def __init__(self, il2cpp: bool) -> None:
        self._il2cpp = il2cpp
        self._ptr = dict()

        if self._il2cpp:
            for name, prop in il2cpp_native_func_property.items():
                self._ptr[name] = MonoNativeFunc(name, *prop)
        else:
            for name, prop in mono_native_func_property.items():
                self._ptr[name] = MonoNativeFunc(name, *prop)

    def __setitem__(self, key: str, value: int) -> None:
        if not isinstance(key, str):
            raise TypeError("key should be str")
        if not isinstance(value, int):
            raise TypeError("value should be int")
        if key in self._ptr:
            self._ptr[key].set_address(value)
        else:
            raise NotImplementedError(key)

    def __getitem__(self, item: str) -> Optional[MonoNativeFunc]:
        return self._ptr.get(item, None)


class MonoField:
    """ ``MonoField`` carries class property reflection information.
    
    For ``MonoField`` objects, you can call the ``is_static`` method to determine whether the field is static (modified by the static keyword).

    If it is a static field, there is no need to set the class instance, otherwise, the address of the class instance corresponding to the field needs to be set first.

    Examples:

    >>> ref = WinUniRef("TheForest.exe")
    >>> PlayerStats = ref.find_class_in_image("Assembly-CSharp", "PlayerStats")
    >>> Energy = PlayerStats.find_field("Energy")
    >>> Energy.value
    ValueError: Field Energy is not static, set instance address first
    >>> Energy.instance = 0x12345678
    >>> Energy.value
    10.0
    >>> Energy.value = 80.0
    >>> Energy.value
    80.0
    >>> Energy.set_value(90.0)
    >>> Energy.value
    90.0

    In addition, when you modify the value of the field, you need to use the **correct** Python type to assign the value according to the type of the field.
    The type mapping is shown in the table below.

    +----------------+--------------+
    |       C#       |    Python    |
    +================+==============+
    | System.Boolean |     bool     |
    +----------------+--------------+
    | System.SByte,  |     int      |
    | System.Byte,   |              |
    |                |              |
    | System.Int16,  |              |
    | System.UInt16, |              |
    |                |              |
    | System.Int32,  |              |
    | System.UInt32, |              |
    |                |              |
    | System.Int64,  |              |
    | System.UInt64  |              |
    +----------------+--------------+
    | System.Single, |    float     |
    | System.Double  |              |
    +----------------+--------------+
    | System.String, | Not Editable |
    | System.Decimal |              |
    +----------------+--------------+
    |     Else       |     int      |
    +----------------+--------------+

    """
    def __init__(self, mono_injector: object, klass: int, field: int, filed_name: str = '') -> None:
        self._handle = field
        self._mono_injector = mono_injector
        if not isinstance(klass, int):
            raise TypeError("klass should be int")
        self._klass = MonoClass(mono_injector, None, klass)

        self._flags = 0
        self._parent = 0
        self._offset = 0
        self._instance = 0
        self._mono_type = 0
        self._field_type = 0
        self._type_name = ''
        self._name = filed_name

    @property
    def handle(self) -> int:
        """ value as ``MonoClassField*`` """
        return self._handle

    @property
    def klass(self) -> object:
        """ ``MonoClass`` instance of the field """
        return self._klass

    @property
    def address(self) -> int:
        """ field address. Maybe 0 if it is static """
        if self.is_static():
            return self._mono_injector.get_static_field_address(self._klass.handle, self._handle)
        else:
            return self.instance + self.offset

    @property
    def value(self) -> Optional[Any]:
        """ field value """
        if self.is_static():
            return self._mono_injector.get_static_field_value(self._klass.handle, self._handle, self.type_name)
        else:
            return self._mono_injector._try_get_value(self.address, self.type_name)

    @value.setter
    def value(self, v: Any) -> None:
        self.set_value(v)

    def set_value(self, v: Any) -> None:
        """ Set field value. """
        if self.is_static():
            success = self._mono_injector.set_static_field_value(self._klass.handle, self._handle, self.type_name, v)
        else:
            success = self._mono_injector._try_set_value(self.address, v, self.type_name)
        if not success:
            raise TypeError("Wrong type of value given")

    @property
    def instance(self) -> int:
        """ class instance address of the field """
        if self._instance <= 0:
            raise ValueError(f"Field {self.name} is not static, set instance address first")
        return self._instance

    @instance.setter
    def instance(self, value: int) -> None:
        self.set_instance(value)

    def set_instance(self, value: int) -> None:
        """ Set class instance address of the field. """
        if not isinstance(value, int):
            raise TypeError("instance should be int")
        if value <= 0:
            raise ValueError("instance should be positive")
        self._instance = value

    @property
    def parent(self) -> int:
        if not self._parent:
            self._parent = self._mono_injector.mono_field_get_parent(self._handle)
        return self._parent

    @property
    def offset(self) -> int:
        """ field offset in the class """
        if not self._offset:
            self._offset = self._mono_injector.mono_field_get_offset(self._handle)
        return self._offset

    @property
    def flags(self) -> int:
        """ field flags """
        if not self._flags:
            self._flags = self._mono_injector.mono_field_get_flags(self._handle)
        return self._flags

    @property
    def name(self) -> str:
        """ field name """
        if not self._name:
            self._name = self._mono_injector.mono_field_get_name(self._handle)
        return self._name

    @property
    def mono_type(self) -> int:
        if not self._mono_type:
            self._mono_type = self._mono_injector.mono_type_get_type(self.field_type)
        return self._mono_type

    @property
    def field_type(self) -> int:
        if not self._field_type:
            self._field_type = self._mono_injector.mono_field_get_type(self._handle)
        return self._field_type

    @property
    def type_name(self) -> str:
        """ field type name """
        if not self._type_name:
            self._type_name = self._mono_injector.mono_type_get_name(self.field_type)
        return self._type_name

    def is_const(self) -> bool:
        """ Check if the field is const. """
        return (self.flags & FIELD_ATTRIBUTE_LITERAL) != 0

    def is_static(self) -> bool:
        """ Check if the field is static. """
        return (self.flags & (FIELD_ATTRIBUTE_STATIC | FIELD_ATTRIBUTE_HAS_FIELD_RVA)) != 0


class MonoMethod:
    """ ``MonoMethod`` carries class method reflection information.

    For ``MonoMethod`` objects, you can call the ``is_static`` to determine whether the method is static (modified by the static keyword).

    If it is a static method, there is no need to set the class instance, otherwise, the address of the class instance corresponding to the method needs to be set first.

    Examples:

    >>> ref = WinUniRef("TheForest.exe")
    >>> PlayerStats = ref.find_class_in_image("Assembly-CSharp", "PlayerStats")
    >>> SetCold = PlayerStats.find_method("SetCold")
    >>> hex(SetCold.address)
    '0x6e673b0'
    >>> SetCold(args=(1,))
    ValueError: Not a static method, set class instance first
    >>> SetCold.instance = 0x12345678
    >>> SetCold(args=(1,))

    You can call a ``MonoMethod`` object like a Python function, passing the argument tuple via ``args``.
    The ``args`` tuple requires that the elements in it are all of type int, and currently does not support parameters of types such as float / str.

    For **32-bit** applications, you need to additionally specify the type of function calling convention. The supported types are as follows::

        CALL_TYPE_CDECL
        CALL_TYPE_STDCALL
        CALL_TYPE_THISCALL
        CALL_TYPE_FASTCALL

    Please set the function calling convention under the correct analysis result, otherwise the program may crash.

    Examples:

    .. code-block:: python

        from uniref import *

        ref = WinUniRef("game.exe")
        TestClass = ref.find_class_in_image("Assembly-CSharp", "TestClass")
        TestClass.instance = 0x12345678
        TestMethod = TestClass.find_method("TestMethod")
        TestMethod(args=(1, 2), call_type=CALL_TYPE_CDECL)

    """
    def __init__(self, mono_injector: object, klass: int, method: int, method_name: str = '') -> None:
        self._handle = method
        self._mono_injector = mono_injector
        if isinstance(klass, int):
            self._klass = MonoClass(mono_injector, None, klass)
        else:
            self._klass = None

        self._flags = 0
        self._instance = 0
        self._signature = ''
        self._name = method_name
        self._address = 0

    def __call__(self, args: Optional[Tuple[int]] = None, call_type: int = CALL_TYPE_THISCALL) -> Any:
        ret_type = type_map.get(self.return_type_name, TYPE_VOID_P)
        if ret_type == -1:
            raise NotImplementedError("System.Decimal")
        if self._instance == 0 and not self.is_static():
            raise ValueError("Not a static method, set class instance first")
        func_args = (self.instance,)
        if args:
            if not isinstance(args, tuple):
                raise TypeError("args should be tuple")
            if not all([isinstance(arg, int) for arg in args]):
                raise NotImplementedError(f"Function arguments should all be int in Python")
            func_args += args
        return self._mono_injector.call_native_function(self.address, func_args, ret_type, call_type)

    @property
    def handle(self) -> int:
        """ value as ``MonoMethod*`` """
        return self._handle

    @property
    def size(self) -> int:
        """ method size. Maybe -1 if app uses IL2CPP """
        return self._mono_injector.get_method_size(self._handle)

    @property
    def klass(self) -> object:
        """ ``MonoClass`` instance of the method """
        if not self._klass:
            self._klass = self._mono_injector.get_method_class(self.handle)
        return self._klass

    @property
    def flags(self) -> int:
        """ method flags """
        if not self._flags:
            self._flags = self._mono_injector.mono_method_get_flags(self._handle, 0)
        return self._flags

    @property
    def instance(self) -> int:
        """ class instance address of the method """
        return self._instance

    @instance.setter
    def instance(self, value: int) -> None:
        self.set_instance(value)

    def set_instance(self, value: int) -> None:
        """ Set class instance address of the method. """
        if not isinstance(value, int):
            raise TypeError("instance should be int")
        if value <= 0:
            raise ValueError("instance should be positive")
        self._instance = value

    @property
    def address(self) -> int:
        """ method machine code address """
        if not self._address:
            self._address = self._mono_injector.compile_method(self._handle)
        return self._address

    @property
    def name(self) -> str:
        """ method name """
        if not self._name:
            self._name = self._mono_injector.get_method_name(self._handle)
        return self._name

    @property
    def signature(self) -> str:
        """ method signature """
        if not self._signature:
            self._signature = self._mono_injector.get_method_signature(self._handle)
        return self._signature

    @property
    def return_type_name(self) -> str:
        """ method return type name """
        return self.signature[:self.signature.index(' ')]

    def is_static(self) -> bool:
        """ Check if the method is static. """
        return (self.flags & METHOD_ATTRIBUTE_STATIC) != 0

    def native_patch(self, offset: int, code: str or bytes) -> NativePatch:
        """ Patch method machine code.

        :param offset: offset from the beginning of the function
        :param code: can be ``str`` or ``bytes``
        :return: ``NativePatch`` instance

        When the code parameter is of ``bytes`` type , the specified offset of the method will be modified to the given byte array.

        When the code parameter is of ``str`` type, it will be regarded as assembly code and translated into machine code before patching.
        The assembly engine is `keystone <https://www.keystone-engine.org/>`_ .

        Meanwhile, you can enable and disable this patch through the ``NativePatch`` instance returned by the function.

        Examples:

        .. code-block:: python

            from uniref import *

            ref = WinUniRef("game.exe")
            TestClass = ref.find_class_in_image("Assembly-CSharp", "TestClass")
            TestMethod = TestClass.find_method("TestMethod")

            patch_1 = TestMethod.native_patch(0x222, b'H\\xc7\\xc0\\x01\\x00\\x00\\x00')  # mov rax, 1

            asm = "mov rax, 1; mov rbx, 2; add rax, rbx"
            patch_2 = TestMethod.native_patch(0x333, asm)

            # disable patch
            patch_1.disable()
            patch_2.disable()

            # enable again
            patch_1.enable()
            patch_2.enable()

        """
        return self._mono_injector.code_patch(code, self.address + offset)

    def native_nop(self, offset: int, size: int) -> NativePatch:
        """ NOP method machine code.

        :param offset: offset from the beginning of the function
        :param size: nop size in bytes
        :return: ``NativePatch`` instance
        """
        return self.native_patch(offset, b'\x90' * size)


class MonoClass:
    """ ``MonoClass`` carries class reflection information. """

    def __init__(self, mono_injector: object, image: Optional[int], klass: int, class_name: str = '', class_namespace: str = '') -> None:
        self._handle = klass
        self._mono_injector = mono_injector
        if isinstance(image, int):
            self._image = MonoImage(mono_injector, None, image)
        else:
            self._image = None

        self._vtable = 0
        self._instance = 0
        self._parent = None
        self._name = class_name
        self._namespace = class_namespace

    @property
    def handle(self) -> int:
        """ value as ``MonoClass*`` """
        return self._handle

    @property
    def instance(self) -> int:
        """ class instance address """
        return self._instance

    @instance.setter
    def instance(self, value: int) -> None:
        self.set_instance(value)

    def set_instance(self, value: int) -> None:
        """ Set class instance address. """
        if not isinstance(value, int):
            raise TypeError("instance should be int")
        if value <= 0:
            raise ValueError("instance should be positive")
        self._instance = value

    @property
    def vtable(self):
        if not self._vtable:
            self._vtable = self._mono_injector.get_class_vtable(self.handle)
        return self._vtable

    @property
    def image(self) -> object:
        """ image to which the class belongs (``MonoImage``) """
        if not self._image:
            self._image = self._mono_injector.get_class_image(self._handle)
        return self._image

    @property
    def parent(self) -> object:
        """ parent class (``MonoClass``) """
        if not self._parent:
            self._parent = self._mono_injector.get_parent_class(self._handle)
        return self._parent

    @property
    def name(self) -> str:
        """ class name """
        if not self._name:
            self._name = self._mono_injector.get_class_name(self._handle)
        return self._name

    @property
    def namespace(self) -> str:
        """ class namespace """
        if not self._namespace:
            self._namespace = self._mono_injector.get_class_namespace(self._handle)
        return self._namespace

    def list_fields(self) -> List[MonoField]:
        """ List all fields in class. """
        fields = self._mono_injector.enum_fields_in_class(self._handle)
        if self._instance > 0:
            for field in fields:
                field.set_instance(self._instance)
        return fields

    def find_field(self, field_name: str) -> Optional[MonoField]:
        """ Find the field by its name.

        :return: ``MonoField`` instance if field is found, else ``None``.
        """
        if not isinstance(field_name, str):
            raise TypeError("field_name should be str")
        field = self._mono_injector.find_field_in_class(self._handle, field_name)
        if field:
            if self._instance > 0:
                field.set_instance(self._instance)
            return field

    def find_field_by_offset(self, offset: int) -> Optional[MonoField]:
        """ Find the field by its offset.

        :return: ``MonoField`` instance if field is found, else ``None``.
        """
        if not isinstance(offset, int):
            raise TypeError("offset should be int")
        fields = self.list_fields()
        for field in fields:
            if field.offset == offset:
                return field

    def list_methods(self) -> List[MonoMethod]:
        """ List all methods in class. """
        methods = self._mono_injector.enum_methods_in_class(self._handle)
        if self._instance > 0:
            for method in methods:
                method.set_instance(self._instance)
        return methods

    def find_method(self, method_name: str, param_count: int = - 1) -> Optional[MonoMethod]:
        """ Find the method in the class.

        If there are different overloads of a method in the same class,
        you can distinguish them by the number of parameters. This is what the ``param_count`` means.

        :return: ``MonoMethod`` instance if method is found, else ``None``.
        """
        if not isinstance(method_name, str):
            raise TypeError("method_name should be str")
        if not isinstance(param_count, int):
            raise TypeError("param_count should be int")
        method = self._mono_injector.find_method_in_class(self._handle, method_name, param_count)
        if method:
            if self._instance > 0:
                method.set_instance(self._instance)
            return method

    def guess_instance_address(self, mem_writeable: bool = True) -> List[int]:
        """ Guess class instance address in memory.

        :param mem_writeable: the memory space where the class instance is located must be writable
        :return: a list of all class instance addresses guessed
        """
        if not isinstance(mem_writeable, bool):
            raise TypeError("mem_writable should be bool")
        return self._mono_injector.guess_class_instance_address(self._handle, mem_writeable)


class MonoImage:
    """ ``MonoImage`` carries image reflection information. """

    def __init__(self, mono_injector: object, assembly: Optional[int], image: int, image_name: str = '', image_filename: str = ''):
        self._handle = image
        self._mono_injector = mono_injector
        if isinstance(assembly, int):
            self._assembly = MonoAssembly(mono_injector, assembly)
        else:
            self._assembly = None

        self._name = image_name
        self._filename = image_filename

    @property
    def handle(self) -> int:
        """ value as ``MonoImage*`` """
        return self._handle

    @property
    def assembly(self) -> object:
        """ the assembly to which the image belongs (``MonoAssembly``) """
        if not self._assembly:
            self._assembly = self._mono_injector.get_image_assembly(self.handle)
        return self._assembly

    @property
    def name(self) -> str:
        """ image name """
        if not self._name:
            self._name = self._mono_injector.get_image_name(self._handle)
        return self._name

    @property
    def filename(self) -> str:
        """ image filename """
        if not self._filename:
            self._filename = self._mono_injector.get_image_filename(self._handle)
        return self._filename

    def list_classes(self) -> List[MonoClass]:
        """ List all classes in the image. """
        return self._mono_injector.enum_classes_in_image(self._handle)

    def find_class(self, class_path: str) -> MonoClass:
        """ Find the class in the image.

        :return: ``MonoClass`` instance if class is found, else ``None``.
        """
        if not isinstance(class_path, str):
            raise TypeError("class_path should be str")
        if '.' in class_path:
            dot = class_path.rfind('.')
            class_namespace = class_path[:dot]
            class_name = class_path[dot + 1:]
        else:
            class_namespace = ''
            class_name = class_path
        class_name = class_name.replace('+', '/')
        return self._mono_injector.find_class_in_image(self._handle, class_namespace, class_name)


class MonoAssembly:
    """ ``MonoAssembly`` carries assembly reflection information. """

    def __init__(self, mono_injector: object, assembly: int):
        self._handle = assembly
        self._mono_injector = mono_injector
        self._image = None

    @property
    def handle(self) -> int:
        """ value as ``MonoAssembly*`` """
        return self._handle

    @property
    def image(self) -> MonoImage:
        """ image corresponding to the assembly"""
        if not self._image:
            self._image = self._mono_injector.get_assembly_image(self._handle)
        return self._image


class _MonoNativeError(Exception):
    ...
