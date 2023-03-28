from uniref.mono.component import *
from uniref.util.winapi import WinApi
from uniref.util.scanner import CMemoryScanner
from uniref.util.injector.windows import WinInjector
from uniref.mono.injector.interface import MonoInjector


class WinMonoInjector(WinInjector, MonoInjector):
    """ Unity application injector for ``Windows``. """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h_mono = 0
        self._func_set = None
        self._root_domain = 0
        self._use_il2cpp = False

        self._mono_detect()
        self._mono_init()

    @property
    def h_mono(self) -> int:
        return self._h_mono

    @property
    def use_il2cpp(self) -> bool:
        return self._use_il2cpp

    @property
    def root_domain(self) -> int:
        return self._root_domain

    def _mono_detect(self) -> None:
        h_mono = self.get_module_base("mono.dll")
        if h_mono:
            self._h_mono = h_mono
        else:
            modules = WinApi.GetRemoteModules(self._h_process)
            for module in modules:
                if self.get_proc_address(module, "il2cpp_thread_attach"):
                    self._h_mono = module
                    self._use_il2cpp = True
                    break
                if self.get_proc_address(module, "mono_thread_attach"):
                    self._h_mono = module
                    break
            if self._h_mono == 0:
                raise SystemError("Only support mono & il2cpp application")

    def _find_mono_api_address(self, page_start: int, proc_name: str) -> int:
        return_address = page_start + 0x300
        proc_name_address = page_start + 0x200

        if self._bit_long == 32:
            code = f"push {hex(proc_name_address)}           \n" \
                   f"push {hex(self._h_mono)}                \n" \
                   f"mov eax, {hex(self._get_proc_address)}  \n" \
                   f"call eax                                \n" \
                   f"mov ecx, {hex(return_address)}          \n" \
                   f"mov dword ptr [ecx], eax                \n" \
                   f"ret"
        else:
            code = f"sub rsp, 28h                            \n" \
                   f"mov rcx, {hex(self._h_mono)}            \n" \
                   f"mov rdx, {hex(proc_name_address)}       \n" \
                   f"mov rax, {hex(self._get_proc_address)}  \n" \
                   f"call rax                                \n" \
                   f"mov r12, {hex(return_address)}          \n" \
                   f"mov qword ptr [r12], rax                \n" \
                   f"add rsp, 28h                            \n" \
                   f"ret"

        self._mem_write(proc_name_address, proc_name.encode() + b'\x00')
        self.code_execute(code, page_start)
        return self.mem_read_pointer(return_address)

    def _build_mono_func_set(self) -> MonoNativeFuncSet:
        func_set = MonoNativeFuncSet(self._use_il2cpp)
        page_start = self.mem_alloc()
        if self._use_il2cpp:
            for fn in il2cpp_native_func_name:
                mono_name = il2cpp_mono_native_func_map[fn]
                func_set[mono_name] = self._find_mono_api_address(page_start, fn)
                func_set[mono_name].set_mono_injector(self)
        else:
            for fn in mono_native_func_name:
                func_set[fn] = self._find_mono_api_address(page_start, fn)
                func_set[fn].set_mono_injector(self)
        self.mem_free(page_start)
        return func_set

    def enum_assemblies(self) -> List[MonoAssembly]:
        if self._use_il2cpp:
            return self._il2cpp_enum_assembly_impl()
        else:
            if self._bit_long == 32:
                enum_assembly_callback = b"\x55\x8b\xec\x8b\x4d\x0c\x8b\x11\x81\xfa\xfe\x03\x00\x00\x77\x09\x8b\x45\x08\x89\x44\x91\x04\xff\x01\x5d\xc3"
                """
                    void _cdecl enum_assembly_callback(void* domain, CUSTOM_DOMAIN_ARRAY32* v)
                    {
                        if (v->cnt <= 1022) {
                            v->domains[v->cnt] = (UINT32)domain;
                            v->cnt += 1;
                        }
                    }
                """
            else:
                enum_assembly_callback = b"\x8b\x02\x3d\xfe\x01\x00\x00\x77\x07\x48\x89\x4c\xc2\x08\xff\x02\xc3"
                """
                    void _cdecl enum_assembly_callback(void* domain, CUSTOM_DOMAIN_ARRAY64* v)
                    {
                        if (v->cnt <= 510) {
                            v->domains[v->cnt] = (UINT64)domain;
                            v->cnt += 1;
                        }
                    }
                """
            return self._mono_enum_assembly_impl(enum_assembly_callback)

    def guess_class_instance_address(self, klass: int, mem_writeable: bool = False) -> List[int]:
        vtable = self.get_class_vtable(klass)
        if vtable:
            scanner = CMemoryScanner(self._process_id, self._bit_long)
            return scanner.scan_pointer(vtable, mem_writeable)
        return []
