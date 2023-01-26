import struct

from uniref.mono.component import *
from uniref.util.injector import AndroidInjector
from uniref.mono.component import MonoNativeFuncSet
from uniref.mono.injector.interface import MonoInjector


class AndroidMonoInjector(AndroidInjector, MonoInjector):
    """ Unity application injector for ``Android``. """

    def __init__(self, *args, **kwargs):
        self._mono_thread = 0
        super().__init__(*args, **kwargs)
        self._root_domain = 0
        self._func_set = None
        self._use_il2cpp = False
        self._mono_module = None

        self._mono_detect()
        self._mono_attach()

    def __del__(self):
        self._mono_detach()

    @property
    def h_mono(self) -> int:
        if isinstance(self._mono_module, dict):
            return int(self._mono_module.get("base", '0'), 16)
        return 0

    @property
    def use_il2cpp(self) -> bool:
        return self._use_il2cpp

    @property
    def root_domain(self) -> int:
        return self._root_domain

    @property
    def attach_thread(self) -> int:
        return self._mono_thread

    def _mono_detach(self) -> None:
        if self._mono_thread != 0:
            self._mono_thread = 0

    def _mono_detect(self) -> None:
        modules = self._enumerate_modules()
        for i in range(len(modules) - 1, -1, -1):
            module_name = modules[i].get("name", '')
            if self.get_proc_address(module_name, "il2cpp_thread_attach"):
                self._mono_module = modules[i]
                self._use_il2cpp = True
                break
            if self.get_proc_address(module_name, "mono_thread_attach"):
                self._mono_module = modules[i]
                break
        if not self._mono_module:
            raise SystemError("Only support mono & il2cpp application")

    def _build_mono_func_set(self) -> MonoNativeFuncSet:
        module_name = self._mono_module["name"]
        func_set = MonoNativeFuncSet(self._use_il2cpp)
        if self._use_il2cpp:
            for fn in il2cpp_native_func_name:
                mono_name = il2cpp_mono_native_func_map[fn]
                func_set[mono_name] = self.get_proc_address(module_name, fn)
                func_set[mono_name].set_mono_injector(self)
        else:
            for fn in mono_native_func_name:
                func_set[fn] = self.get_proc_address(module_name, fn)
                func_set[fn].set_mono_injector(self)
        return func_set

    def enum_assemblies(self) -> List[MonoAssembly]:
        if self._use_il2cpp:
            return self._il2cpp_enum_assembly_impl()
        else:
            if self.bit_long == 32:
                enum_assembly_callback = b"\x00\x30\x91\xE5\xFE\x23\x00\xE3\x02\x00\x53\xE1\x03\x21\x81\x90\x01\x30\x83\x92\x04\x00\x82\x95\x00\x30\x81\x95\x1E\xFF\x2F\xE1"
            else:
                enum_assembly_callback = b"\x22\x00\x40\xB9\x5F\xF8\x07\x71\xA8\x00\x00\x54\x23\x4C\x22\x8B\x42\x04\x00\x11\x60\x04\x00\xF9\x22\x00\x00\xB9\xC0\x03\x5F\xD6"
            return self._mono_enum_assembly_impl(enum_assembly_callback)

    def guess_class_instance_address(self, klass: int, mem_writeable: bool = True) -> List[int]:
        vtable = self.get_class_vtable(klass)
        if vtable:
            pattern = struct.pack("I" if self.bit_long == 32 else "Q", vtable).rstrip(b"\x00")
            pattern = ' '.join(["%02X" % i for i in pattern])
            protection = "rw-" if mem_writeable else "r--"
            return [int(i, 16) for i in self._api.mem_scan(pattern, protection)]
        return []
