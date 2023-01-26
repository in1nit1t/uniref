from uniref.define.constant import *
from uniref.util.winapi import WinApi
from uniref.util.injector import WinInjector
from tests.interface import InjectorTest


class WinInjectorTest(InjectorTest):

    mem = None
    injector = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.injector = WinInjector()
        cls.mem = cls.injector.mem_alloc(alloc_size=4096)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.mem:
            cls.injector.mem_free(cls.mem)

    def setUp(self) -> None:
        self.injector.mem_write_bytes(self.mem, b'\x00' * 4096)

    def test_exception(self) -> None:
        ...

    def test_code_execute(self) -> None:
        data_page = self.injector.mem_alloc()

        if self.injector.bit_long in (32, 64):
            code = f"mov eax, 123h                          \n" \
                   f"mov ebx, 456h                          \n" \
                   f"add eax, ebx                           \n" \
                   f"mov dword ptr [{hex(data_page)}], eax  \n" \
                   f"ret"

            code_page = self.injector.code_execute(code)
            self.assertEqual(0x579, self.injector.mem_read_uint32(data_page))
            self.injector.mem_free(code_page)

        if self.injector.bit_long == 64:
            code = f"mov rax, 0x123456789AB                  \n" \
                   f"mov rbx, 0xBA987654321                  \n" \
                   f"add rax, rbx                            \n" \
                   f"mov qword ptr [{hex(data_page)}], rax   \n" \
                   f"ret"
            code_page = self.injector.code_execute(code)
            self.assertEqual(0xCCCCCCCCCCC, self.injector.mem_read_uint64(data_page))
            self.injector.mem_free(code_page)

        self.injector.mem_free(data_page)

    def test_call_native_function(self) -> None:
        h_kernel32 = WinApi.GetModuleHandleA(b"kernel32.dll")
        address = self.injector.get_proc_address(h_kernel32, "GetModuleHandleA")
        self.assertNotEqual(0, address)
        str_kernel32 = self.injector.new_c_string("kernel32.dll")
        handle = self.injector.call_native_function(address, (str_kernel32.address,), TYPE_VOID_P, CALL_TYPE_STDCALL)
        self.assertEqual(handle, h_kernel32)
