from capstone.x86_const import *

from uniref.mono.component import *
from uniref.util.winapi import WinApi
from uniref.util.disasm import X86Disasm
from uniref.util.scanner import CMemoryScanner
from uniref.util.injector.windows import WinInjector
from uniref.mono.injector.interface import MonoInjector


class WinMonoInjector(WinInjector, MonoInjector):
    """ Unity application injector for ``Windows``. """

    def __init__(self, *args, **kwargs):
        self._mono_thread = 0
        super().__init__(*args, **kwargs)
        self._h_mono = 0
        self._func_set = None
        self._root_domain = 0
        self._use_il2cpp = False
        self._domain_tls_idx = -1
        self._gs_access_address = -1
        self._tls_set_value = self._get_kernel32_proc_address("TlsSetValue")

        self._mono_detect()
        self._mono_attach()
        if not self._use_il2cpp:
            self._try_get_gs_check_address()

    def __del__(self):
        self._mono_detach()

    @property
    def h_mono(self) -> int:
        return self._h_mono

    @property
    def use_il2cpp(self) -> bool:
        return self._use_il2cpp

    @property
    def root_domain(self) -> int:
        return self._root_domain

    @property
    def attach_thread(self) -> int:
        return self._mono_thread

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

    def _ensure_domain_tls_idx(self) -> bool:
        if self._domain_tls_idx != -1:
            return True

        address = self._func_set["mono_domain_get"].address
        code = self._mem_read(address, 15)  # read first instruction
        ins_list = X86Disasm(self._bit_long).disassemble(code, address, 1)
        if ins_list:
            ins = ins_list[0]
            operands = ins.operands
            if ins.mnemonic == "push" and operands[0].type == X86_OP_MEM:
                self._domain_tls_idx = self.mem_read_uint32(operands[0].mem.disp)
                return True
            if ins.mnemonic == "mov" and \
                    len(operands) == 2 and \
                    ins.reg_name(operands[0].reg) in ("ecx", "rcx") and \
                    operands[1].type == X86_OP_MEM:
                target_address = address + ins.size + operands[1].mem.disp
                self._domain_tls_idx = self.mem_read_uint32(target_address)
                return True
        return False

    def _try_get_gs_check_address(self) -> None:
        if self._gs_access_address != -1:
            return

        mscorlib = self.find_image_by_name("mscorlib")
        if mscorlib:
            wait_handle = self.find_class_in_image(mscorlib.handle, "System.Threading", "WaitHandle")
            if not wait_handle:
                return
            wait_all_internal = self.find_method_in_class(wait_handle.handle, "WaitAll_internal")
            if not wait_all_internal:
                return
            code_size = self.get_method_size(wait_all_internal.handle)
            if code_size == -1:
                return
            code_start = wait_all_internal.address
            code = self._mem_read(code_start, code_size)
            instructions = X86Disasm(self._bit_long).disassemble(code, code_start)
            for ins in instructions:
                operands = ins.operands
                if ins.mnemonic == "mov" and len(operands) == 2 and \
                        operands[1].type == X86_OP_MEM and \
                        operands[1].mem.segment == X86_REG_GS:
                    self._gs_access_address = operands[1].mem.disp

    def mono_compile_method(self, method: int) -> int:
        if not self._ensure_domain_tls_idx():
            raise NotImplementedError("Can't compile method in current environment")

        bit_long = self._bit_long
        page_start = self.mem_alloc()
        return_address = page_start + 0x300
        mono_compile_method = self._func_set["mono_compile_method"].address

        code = "push ebp\n mov ebp, esp\n" if bit_long == 32 else "sub rsp, 28h\n"

        if self._gs_access_address != -1:
            gs_access_mem = self.mem_alloc(protection="rw-")
            if bit_long == 32:
                code += f"mov ecx, {hex(gs_access_mem)}            \n" \
                        f"mov eax, {hex(self._gs_access_address)}  \n" \
                        f"mov gs:[eax], ecx                        \n"
            else:
                code += f"mov r12, {hex(gs_access_mem)}            \n" \
                        f"mov r13, {hex(self._gs_access_address)}  \n" \
                        f"mov gs:[r13], r12                        \n"

        if bit_long == 32:
            code += f"push {hex(self._root_domain)}         \n" \
                    f"push {hex(self._domain_tls_idx)}      \n" \
                    f"mov eax, {hex(self._tls_set_value)}   \n" \
                    f"call eax                              \n" \
                    f"push {hex(method)}                    \n" \
                    f"mov eax, {hex(mono_compile_method)}   \n" \
                    f"call eax                              \n" \
                    f"mov ecx, {hex(return_address)}        \n" \
                    f"mov dword ptr [ecx], eax              \n" \
                    f"leave\n ret"
        else:
            code += f"mov rcx, {hex(self._domain_tls_idx)}  \n" \
                    f"mov rdx, {hex(self._root_domain)}     \n" \
                    f"mov rax, {hex(self._tls_set_value)}   \n" \
                    f"call rax                              \n" \
                    f"mov rcx, {hex(method)}                \n" \
                    f"mov rax, {hex(mono_compile_method)}   \n" \
                    f"call rax                              \n" \
                    f"mov r12, {hex(return_address)}        \n" \
                    f"mov qword ptr [r12], rax              \n" \
                    f"add rsp, 28h                          \n" \
                    f"ret"

        code = self.code_compile(code)
        self.mem_write_bytes(page_start, code)
        self._create_remote_thread(page_start)
        method_address = self.mem_read_int64(return_address)

        if self._gs_access_address != -1:
            self.mem_free(gs_access_mem)
        self.mem_free(page_start)
        return method_address

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
