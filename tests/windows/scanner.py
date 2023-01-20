from random import *
from unittest import *

from uniref.util.injector import WinInjector
from uniref.util.scanner import CMemoryScanner


char_random = lambda: randint(-128, 127)
uchar_random = lambda: randint(0, 255)
int16_random = lambda: randint(-32768, 32767)
uint16_random = lambda: randint(0, 65535)
int32_random = lambda: randint(-2147483648, 2147483647)
uint32_random = lambda: randint(0, 4294967295)
int64_random = lambda: randint(-9223372036854775808, 9223372036854775807)
uint64_random = lambda: randint(0, 18446744073709551615)
float_random = lambda: uniform(-1.0, 1.0)
double_random = lambda: uniform(-1.0, 1.0)


class CMemoryScannerTest(TestCase):

    mem = None
    scanner = None
    injector = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.injector = WinInjector()
        cls.mem = cls.injector.mem_alloc(alloc_size=4096)
        cls.scanner = CMemoryScanner(cls.injector.process_id, cls.injector.bit_long)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.mem:
            cls.injector.mem_free(cls.mem)

    def setUp(self) -> None:
        self.injector.mem_write_bytes(self.mem, b'\x00' * 4096)

    def _test_scan_internal(self, elem_size: int, random_func, write_func, scan_func):
        length = randint(100, 4096 // elem_size)
        index = list(set([randint(0, 4096 // elem_size - 1) for _ in range(length)]))
        addresses = []
        while True:
            value = random_func()
            if value:
                break
        for i, idx in enumerate(index):
            address = self.mem + idx * elem_size
            addresses.append(address)
            write_func(address, value)
        found = scan_func(value, True, self.mem, self.mem + 4096)
        self.assertEqual(len(index), len(found))
        self.assertListEqual(found, sorted(addresses))

    def test_scan_char(self) -> None:
        self._test_scan_internal(1, char_random, self.injector.mem_write_char, self.scanner.scan_char)

    def test_scan_uchar(self) -> None:
        self._test_scan_internal(1, uchar_random, self.injector.mem_write_uchar, self.scanner.scan_uchar)

    def test_scan_int16(self) -> None:
        self._test_scan_internal(2, int16_random, self.injector.mem_write_int16, self.scanner.scan_int16)

    def test_scan_uint16(self) -> None:
        self._test_scan_internal(2, uint16_random, self.injector.mem_write_uint16, self.scanner.scan_uint16)

    def test_scan_int32(self) -> None:
        self._test_scan_internal(4, int32_random, self.injector.mem_write_int32, self.scanner.scan_int32)

    def test_scan_uint32(self) -> None:
        self._test_scan_internal(4, uint32_random, self.injector.mem_write_uint32, self.scanner.scan_uint32)

    def test_scan_int64(self) -> None:
        self._test_scan_internal(8, int64_random, self.injector.mem_write_int64, self.scanner.scan_int64)

    def test_scan_uint64(self) -> None:
        self._test_scan_internal(8, uint64_random, self.injector.mem_write_uint64, self.scanner.scan_uint64)
