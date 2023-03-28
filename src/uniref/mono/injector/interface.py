from functools import wraps
from abc import ABCMeta, abstractmethod

from uniref.mono.component import *
from uniref.util.injector.interface import Injector


def _register_mono_func(func):
    @wraps(func)
    def inner(*args, **kwargs):
        return args[0]._func_set[func.__name__](*args[1:], **kwargs)
    return inner


class MonoInjector(Injector, metaclass=ABCMeta):

    @property
    def h_mono(self) -> int:
        raise NotImplementedError

    @property
    def use_il2cpp(self) -> bool:
        raise NotImplementedError

    @property
    def root_domain(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def _mono_detect(self) -> None:
        ...

    @abstractmethod
    def _build_mono_func_set(self) -> MonoNativeFuncSet:
        ...

    @abstractmethod
    def enum_assemblies(self) -> List[MonoAssembly]:
        ...

    @abstractmethod
    def guess_class_instance_address(self, klass: int, mem_writeable: bool = True) -> List[int]:
        ...

    @_register_mono_func
    def mono_get_root_domain(self) -> int:
        ...

    @_register_mono_func
    def mono_thread_attach(self, domain: int) -> int:
        ...

    @_register_mono_func
    def mono_thread_detach(self, mono_thread: int) -> None:
        ...

    @_register_mono_func
    def mono_assembly_foreach(self, func: int, user_data: int) -> int:
        ...

    @_register_mono_func
    def mono_assembly_get_image(self, assembly: int) -> int:
        ...

    @_register_mono_func
    def mono_image_get_name(self, image: int) -> str:
        ...

    @_register_mono_func
    def mono_image_get_filename(self, image: int) -> str:
        ...

    @_register_mono_func
    def mono_image_get_table_info(self, image: int, table_id: int) -> int:
        ...

    @_register_mono_func
    def mono_image_get_assembly(self, image: int) -> int:
        ...

    @_register_mono_func
    def mono_table_info_get_rows(self, table_info: int) -> int:
        ...

    @_register_mono_func
    def mono_class_get(self, image: int, token_index: int) -> int:
        ...

    @_register_mono_func
    def mono_class_get_name(self, klass: int) -> str:
        ...

    @_register_mono_func
    def mono_class_get_namespace(self, klass: int) -> str:
        ...

    @_register_mono_func
    def mono_class_get_fields(self, klass: int, _iter: int) -> int:
        ...

    @_register_mono_func
    def mono_class_from_mono_type(self, _type: int) -> int:
        ...

    @_register_mono_func
    def mono_class_vtable(self, domain: int, klass: int) -> int:
        ...

    @_register_mono_func
    def mono_type_get_type(self, _type: int) -> int:
        ...

    @_register_mono_func
    def mono_type_get_name(self, _type: int) -> str:
        ...

    @_register_mono_func
    def mono_type_get_class(self, _type: int) -> int:
        ...

    @_register_mono_func
    def mono_field_get_type(self, field: int) -> int:
        ...

    @_register_mono_func
    def mono_field_get_parent(self, field: int) -> int:
        ...

    @_register_mono_func
    def mono_field_get_offset(self, field: int) -> int:
        ...

    @_register_mono_func
    def mono_field_get_flags(self, _type: int) -> int:
        ...

    @_register_mono_func
    def mono_field_get_name(self, field: int) -> str:
        ...

    @_register_mono_func
    def mono_field_static_get_value(self, vtable: int, field: int, output: int) -> int:
        ...

    @_register_mono_func
    def mono_field_static_set_value(self, vtable: int, field: int, _input: int) -> int:
        ...

    @_register_mono_func
    def mono_class_get_methods(self, klass: int, _iter: int) -> int:
        ...

    @_register_mono_func
    def mono_method_get_name(self, method: int) -> str:
        ...

    @_register_mono_func
    def mono_method_get_param_names(self, method: int, names: int) -> int:
        ...

    @_register_mono_func
    def mono_method_get_class(self, method: int) -> int:
        ...

    @_register_mono_func
    def mono_compile_method(self, method: int) -> int:
        ...

    @_register_mono_func
    def mono_method_signature(self, method: int) -> int:
        ...

    @_register_mono_func
    def mono_method_get_flags(self, method: int, ptype: int) -> int:
        ...

    @_register_mono_func
    def mono_class_from_name(self, image: int, namespace: int, name: int) -> int:
        ...

    @_register_mono_func
    def mono_class_from_name_case(self, image: int, namespace: int, name: int) -> int:
        ...

    @_register_mono_func
    def mono_class_get_field_from_name(self, klass: int, name: int) -> int:
        ...

    @_register_mono_func
    def mono_class_get_method_from_name(self, klass: int, name: int, param_count: int) -> int:
        ...

    @_register_mono_func
    def mono_vtable_get_static_field_data(self, vtable: int) -> int:
        ...

    @_register_mono_func
    def mono_class_is_generic(self, klass: int) -> int:
        ...

    @_register_mono_func
    def mono_class_get_parent(self, klass: int) -> int:
        ...

    @_register_mono_func
    def mono_class_get_image(self, klass: int) -> int:
        ...

    @_register_mono_func
    def mono_class_instance_size(self, klass) -> int:
        ...

    @_register_mono_func
    def mono_domain_get(self) -> int:
        ...

    @_register_mono_func
    def mono_domain_set(self, domain: int, force: int) -> int:
        ...

    @_register_mono_func
    def mono_jit_info_table_find(self, domain: int, addr: int) -> int:
        ...

    @_register_mono_func
    def mono_jit_info_get_code_size(self, ji: int) -> int:
        ...

    @_register_mono_func
    def mono_signature_get_desc(self, signature: int, include_namespace: int) -> str:
        ...

    @_register_mono_func
    def mono_signature_get_param_count(self, signature: int) -> int:
        ...

    @_register_mono_func
    def mono_signature_get_return_type(self, signature: int) -> int:
        ...

    @_register_mono_func
    def mono_runtime_invoke(self, method: int, obj: int, params: int, exc: int):
        ...

    @_register_mono_func
    def il2cpp_domain_get_assemblies(self, domain: int, size: int) -> int:
        ...

    @_register_mono_func
    def il2cpp_image_get_class_count(self, image: int) -> int:
        ...

    @_register_mono_func
    def il2cpp_image_get_class(self, image: int, index: int) -> int:
        ...

    @_register_mono_func
    def il2cpp_method_get_param_count(self, method: int) -> int:
        ...

    @_register_mono_func
    def il2cpp_method_get_param_name(self, method: int, index: int) -> str:
        ...

    @_register_mono_func
    def il2cpp_method_get_param(self, method: int, index: int) -> int:
        ...

    @_register_mono_func
    def il2cpp_method_get_return_type(self, method: int) -> int:
        ...

    @_register_mono_func
    def il2cpp_field_static_get_value(self, field: int, output: int) -> int:
        ...

    @_register_mono_func
    def il2cpp_field_static_set_value(self, field: int, _input: int) -> int:
        ...

    def _mono_init(self) -> None:
        self._func_set = self._build_mono_func_set()

        if self.use_il2cpp:
            self._root_domain = self.mono_domain_get()
        else:
            self._root_domain = self.mono_get_root_domain()

        attach = self._func_set["mono_thread_attach"].address
        detach = self._func_set["mono_thread_detach"].address
        self._func_set.set_user_data([self._root_domain, attach, detach])

    def _mono_enum_assembly_impl(self, enum_assembly_callback) -> List[MonoAssembly]:
        callback_address = self.mem_alloc(alloc_size=len(enum_assembly_callback))
        self._mem_write(callback_address, enum_assembly_callback)

        user_data_address = self.mem_alloc(alloc_size=PAGE_SIZE, protection="rw-")
        self.mem_write_uint32(user_data_address, 0)

        self.mono_assembly_foreach(callback_address, user_data_address)

        cnt = self.mem_read_uint32(user_data_address)
        offset = 4 if self.bit_long == 32 else 8
        array = self.mem_read_pointer_array(user_data_address + offset, cnt)
        assemblies = [MonoAssembly(self, assembly) for assembly in array]

        self.mem_free(user_data_address)
        self.mem_free(callback_address)
        return assemblies

    def _il2cpp_enum_assembly_impl(self) -> List[MonoAssembly]:
        count = self.new_pointer(0)
        address = self.il2cpp_domain_get_assemblies(self._root_domain, count.address)
        assembly_count = count.value
        if assembly_count:
            array = self.mem_read_pointer_array(address, assembly_count)
            return [MonoAssembly(self, assembly) for assembly in array]
        return []

    def _try_get_value(self, address: int, type_name: str) -> Optional[Any]:
        try:
            if type_name == "System.Boolean":
                value = self.mem_read_bool(address)
            elif type_name == "System.SByte":
                value = self.mem_read_char(address)
            elif type_name == "System.Byte":
                value = self.mem_read_uchar(address)
            elif type_name == "System.Int16":
                value = self.mem_read_int16(address)
            elif type_name == "System.UInt16":
                value = self.mem_read_uint16(address)
            elif type_name == "System.Int32":
                value = self.mem_read_int32(address)
            elif type_name == "System.UInt32":
                value = self.mem_read_uint32(address)
            elif type_name == "System.Int64":
                value = self.mem_read_int64(address)
            elif type_name == "System.UInt64":
                value = self.mem_read_uint64(address)
            elif type_name == "System.Single":
                value = self.mem_read_float(address)
            elif type_name == "System.Double":
                value = self.mem_read_double(address)
            elif type_name == "System.String":
                value = self._read_cs_string(address)
            elif type_name == "System.Decimal":
                raise NotImplementedError("Read System.Decimal")
            else:
                value = self.mem_read_pointer(address)
        except:
            return None
        return value

    def _try_set_value(self, address: int, value: Any, type_name: str) -> bool:
        try:
            if type_name == "System.Boolean":
                self.mem_write_bool(address, value)
            elif type_name == "System.SByte":
                self.mem_write_char(address, value)
            elif type_name == "System.Byte":
                self.mem_write_uchar(address, value)
            elif type_name == "System.Int16":
                self.mem_write_int16(address, value)
            elif type_name == "System.UInt16":
                self.mem_write_uint16(address, value)
            elif type_name == "System.Int32":
                self.mem_write_int32(address, value)
            elif type_name == "System.UInt32":
                self.mem_write_uint32(address, value)
            elif type_name == "System.Int64":
                self.mem_write_int64(address, value)
            elif type_name == "System.UInt64":
                self.mem_write_uint64(address, value)
            elif type_name == "System.Single":
                self.mem_write_float(address, value)
            elif type_name == "System.Double":
                self.mem_write_double(address, value)
            elif type_name == "System.String":
                raise NotImplementedError("Modify System.String")
            elif type_name == "System.Decimal":
                raise NotImplementedError("Modify System.Decimal")
            else:
                self.mem_write_pointer(address, value)
        except TypeError:
            return False
        return True

    def native_func_exist(self, func_name: str) -> bool:
        native_func = self._func_set[func_name]
        if native_func:
            return native_func.callable()
        return False

    def get_native_func(self, func_name: str) -> Optional[MonoNativeFunc]:
        return self._func_set[func_name]

    def get_assembly_image(self, assembly: int) -> MonoImage:
        return MonoImage(self, assembly, self.mono_assembly_get_image(assembly))

    def enum_images(self) -> List[MonoImage]:
        images = []
        assemblies = self.enum_assemblies()
        for assembly in assemblies:
            handle = assembly.handle
            image = self.mono_assembly_get_image(handle) & 0xFFFFFFFFFFFF
            images.append(MonoImage(self, handle, image))
        return images

    def enum_classes_in_image(self, image: int) -> List[MonoClass]:
        classes = []
        if self.use_il2cpp:
            class_count = 0
            if self.native_func_exist("il2cpp_image_get_class_count") \
                    and self.native_func_exist("il2cpp_image_get_class"):
                class_count = self.il2cpp_image_get_class_count(image)
            for i in range(class_count):
                klass = self.il2cpp_image_get_class(image, i) & 0xFFFFFFFFFFFF
                if klass:
                    classes.append(MonoClass(self, image, klass))
        else:
            type_define = self.mono_image_get_table_info(image, MONO_TABLE_TYPEDEF)
            if not type_define:
                return []
            define_cnt = self.mono_table_info_get_rows(type_define)
            for i in range(define_cnt):
                klass = self.mono_class_get(image, MONO_TOKEN_TYPE_DEF | i + 1)
                if klass:
                    classes.append(MonoClass(self, image, klass))
        return classes

    def enum_fields_in_class(self, klass: int) -> List[MonoField]:
        fields = []
        iter_ptr = self.new_pointer(0)
        while True:
            field = self.mono_class_get_fields(klass, iter_ptr.address) & 0xFFFFFFFFFFFF
            if not field:
                break
            fields.append(MonoField(self, klass, field))
        return fields

    def enum_methods_in_class(self, klass: int) -> List[MonoMethod]:
        methods = []
        iter_ptr = self.new_pointer(0)
        while True:
            method = self.mono_class_get_methods(klass, iter_ptr.address) & 0xFFFFFFFFFFFF
            if not method:
                break
            methods.append(MonoMethod(self, klass, method))
        return methods

    def find_image_by_name(self, image_name: str) -> Optional[MonoImage]:
        assemblies = self.enum_assemblies()
        for assembly in assemblies:
            image = self.mono_assembly_get_image(assembly.handle) & 0xFFFFFFFFFFFF
            name = self.mono_image_get_name(image)
            if name == image_name:
                return MonoImage(self, assembly.handle, image, image_name=name)
        return None

    def get_image_assembly(self, image: int) -> MonoAssembly:
        assembly = self.mono_image_get_assembly(image) & 0xFFFFFFFFFFFF
        return MonoAssembly(self, assembly) if assembly else None

    def get_image_name(self, image: int) -> str:
        return self.mono_image_get_name(image)

    def get_image_filename(self, image: int) -> str:
        return self.mono_image_get_filename(image)

    def find_class_in_image(self, image: int, namespace: str, name: str) -> Optional[MonoClass]:
        name = self.new_c_string(name)
        namespace = self.new_c_string(namespace)

        klass = 0
        if self.native_func_exist("mono_class_from_name_case"):
            klass = self.mono_class_from_name_case(image, namespace.address, name.address)
        if not klass:
            klass = self.mono_class_from_name(image, namespace.address, name.address)
        klass &= 0xFFFFFFFFFFFF
        return MonoClass(self, image, klass) if klass else None

    def get_class_name(self, klass: int) -> str:
        return self.mono_class_get_name(klass)

    def get_class_namespace(self, klass: int) -> str:
        return self.mono_class_get_namespace(klass)

    def get_parent_class(self, klass: int) -> Optional[MonoClass]:
        parent = self.mono_class_get_parent(klass) & 0xFFFFFFFFFFFF
        return MonoClass(self, None, parent) if parent else None

    def get_class_image(self, klass: int) -> Optional[MonoImage]:
        image = self.mono_class_get_image(klass) & 0xFFFFFFFFFFFF
        return MonoImage(self, None, image) if image else None

    def get_class_vtable(self, klass: int) -> int:
        if self.use_il2cpp:
            return klass
        else:
            return self.mono_class_vtable(self._root_domain, klass)

    def find_field_in_class(self, klass: int, name: str) -> Optional[MonoField]:
        name = self.new_c_string(name)
        field = self.mono_class_get_field_from_name(klass, name.address) & 0xFFFFFFFFFFFF
        return MonoField(self, klass, field) if field else None

    def get_static_field_address(self, klass: int, field: int) -> int:
        if not self.use_il2cpp:
            vtable = self.get_class_vtable(klass)
            if vtable:
                static_field_data = self.mono_vtable_get_static_field_data(vtable)
                if static_field_data > 0x10000:
                    return static_field_data + self.mono_field_get_offset(field)
        return 0

    def get_static_field_value(self, klass: int, field: int, type_name: str) -> Optional[Any]:
        if self.use_il2cpp:
            output = self.new_uint64(0)
            self.il2cpp_field_static_get_value(field, output.address)
            return self._try_get_value(output.address, type_name)
        else:
            address = self.get_static_field_address(klass, field)
            if not address:
                raise AttributeError("Static field address not found")
            return self._try_get_value(address, type_name)

    def set_static_field_value(self, klass: int, field: int, type_name: str, value: Any) -> bool:
        if self.use_il2cpp:
            _input = self.new_uint64(0)
            if self._try_set_value(_input.address, value, type_name):
                self.il2cpp_field_static_set_value(field, _input.address)
                return True
            return False
        else:
            address = self.get_static_field_address(klass, field)
            if not address:
                raise AttributeError("Static field address not found")
            return self._try_set_value(address, value, type_name)

    def find_method_in_class(self, klass: int, name: str, param_count: int = -1) -> Optional[MonoMethod]:
        name = self.new_c_string(name)
        method = self.mono_class_get_method_from_name(klass, name.address, param_count) & 0xFFFFFFFFFFFF
        return MonoMethod(self, klass, method) if method else None

    def get_method_name(self, method: int) -> str:
        return self.mono_method_get_name(method)

    def get_method_size(self, method: int) -> int:
        if self.native_func_exist("mono_jit_info_table_find"):
            info_table = self.mono_jit_info_table_find(self._root_domain, method)
            if info_table:
                return self.mono_jit_info_get_code_size(info_table)
        return -1

    def get_method_class(self, method: int) -> Optional[MonoClass]:
        klass = self.mono_method_get_class(method) & 0xFFFFFFFFFFFF
        return MonoClass(self, None, klass) if klass else None

    def get_method_signature(self, method: int) -> str:
        if self.use_il2cpp:
            param_count = self.il2cpp_method_get_param_count(method)
            param_info = ''
            for i in range(param_count):
                param_name = self.il2cpp_method_get_param_name(method, i)
                param_type = self.il2cpp_method_get_param(method, i)
                type_name = self.mono_type_get_name(param_type)
                param_info += f"{type_name} {param_name}, "
            return_type = self.il2cpp_method_get_return_type(method)
            return_type_str = self.mono_type_get_name(return_type)
            return f"{return_type_str} ({param_info[:-2]})"
        else:
            method_sig = self.mono_method_signature(method)
            param_desc = self.mono_signature_get_desc(method_sig, 1)
            param_count = self.mono_signature_get_param_count(method_sig)

            if param_count:
                names_ptr_array = self.new_pointer_array([0 for _ in range(param_count)])
                self.mono_method_get_param_names(method, names_ptr_array.address)

                param_names = []
                names_ptr_array = names_ptr_array.elements
                for i in range(param_count):
                    param_names.append(self.mem_read_c_string(names_ptr_array[i]))

            return_type = self.mono_signature_get_return_type(method_sig)
            return_type_str = self.mono_type_get_name(return_type)

            param_info = ''
            if param_count or param_desc:
                param_types = param_desc.split(',')
                if param_count == len(param_types):
                    param_info = ', '.join([f"{param_types[i]} {param_names[i]}" for i in range(param_count)])
                else:
                    param_info = "<parse error>"

            return f"{return_type_str} ({param_info})"

    def compile_method(self, method: int) -> int:
        if self.use_il2cpp:
            return self.mem_read_pointer(method)
        else:
            klass = self.mono_method_get_class(method)
            if not klass:
                return 0
            is_generic_exist = self.native_func_exist("mono_class_is_generic")
            if (is_generic_exist and self.mono_class_is_generic(klass) == 0) or (not is_generic_exist):
                return self.mono_compile_method(method)
        return 0
