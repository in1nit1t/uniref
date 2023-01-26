import os
from typing import *
from random import *
from unittest import TestCase
from abc import ABCMeta, abstractmethod

bool_random = lambda: random() < 0.5
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
bytes_random = lambda: os.urandom(16)


class InjectorTest(TestCase, metaclass=ABCMeta):

    mem = None
    injector = None

    @classmethod
    def setUpClass(cls) -> None:
        raise NotImplementedError

    @classmethod
    def tearDownClass(cls) -> None:
        raise NotImplementedError

    @abstractmethod
    def setUp(self) -> None:
        ...

    @abstractmethod
    def test_code_execute(self) -> None:
        ...

    @abstractmethod
    def test_call_native_function(self) -> None:
        ...

    @abstractmethod
    def test_exception(self) -> None:
        ...

    def _test_rw_internal(self, elem_size: int, random_func, read_func, write_func, default: Any = 0, *args):
        length = randint(100, 4096 // elem_size)
        index = list(set([randint(0, 4096 // elem_size - 1) for _ in range(length)]))
        array = [random_func() for _ in range(len(index))]
        for i, idx in enumerate(index):
            write_func(self.mem + idx * elem_size, array[i])
        assert_func = self.assertAlmostEqual if isinstance(array[0], float) else self.assertEqual
        for i, idx in enumerate(index):
            assert_func(array[i], read_func(self.mem + idx * elem_size, *args))
        for idx in range(4096 // elem_size):
            if idx not in index:
                self.assertEqual(default, read_func(self.mem + idx * elem_size, *args))

    def _test_rw_array_internal(self, elem_size: int, random_func, read_func, write_func):
        length = randint(100, 4096 // elem_size)
        array = [random_func() for _ in range(length)]
        write_func(self.mem, array)
        read_data = read_func(self.mem, length)
        if isinstance(array[0], float):
            for i in range(length):
                self.assertAlmostEqual(array[i], read_data[i])
        else:
            self.assertListEqual(array, read_data)
        array_size = length * elem_size
        remain_size = 4096 - array_size
        self.assertEqual(b'\x00' * remain_size, self.injector.mem_read_bytes(self.mem + array_size, remain_size))

    def _test_new_internal(self, random_func, new_func):
        value = random_func()
        new_object = new_func(value)
        self.assertNotEqual(0, new_object.address)
        assert_func = self.assertAlmostEqual if isinstance(value, float) else self.assertEqual

        for i in range(10):
            assert_func(value, new_object.value)
            value = random_func()
            new_object.value = value
        assert_func(value, new_object.value)

    def _test_new_array_internal(self, elem_size: int, random_func, new_array_func):
        length = randint(100, 4096 // elem_size)
        array = [random_func() for _ in range(length)]

        new_array_object = new_array_func(array)
        self.assertNotEqual(0, new_array_object.address)
        if isinstance(array[0], float):
            for i in range(length):
                self.assertAlmostEqual(array[i], new_array_object[i])
        else:
            self.assertListEqual(array, new_array_object.elements)

        array = [random_func() for _ in range(length)]
        new_array_object.elements = array
        if isinstance(array[0], float):
            for i in range(length):
                self.assertAlmostEqual(array[i], new_array_object[i])
        else:
            self.assertListEqual(array, new_array_object.elements)

        index = list(set([randint(0, length - 1) for _ in range(randint(1, length))]))
        new_array = [random_func() for _ in range(len(index))]
        for i, idx in enumerate(index):
            new_array_object[idx] = new_array[i]
        assert_func = self.assertAlmostEqual if isinstance(new_array[0], float) else self.assertEqual
        for i, idx in enumerate(index):
            assert_func(new_array[i], new_array_object[idx])
        for idx in range(length):
            if idx not in index:
                assert_func(array[idx], new_array_object[idx])

    def test_rw_bool(self) -> None:
        self._test_rw_internal(1, bool_random, self.injector.mem_read_bool, self.injector.mem_write_bool)

    def test_rw_char(self) -> None:
        self._test_rw_internal(1, char_random, self.injector.mem_read_char, self.injector.mem_write_char)

    def test_rw_uchar(self) -> None:
        self._test_rw_internal(1, uchar_random, self.injector.mem_read_uchar, self.injector.mem_write_uchar)

    def test_rw_int16(self) -> None:
        self._test_rw_internal(2, int16_random, self.injector.mem_read_int16, self.injector.mem_write_int16)

    def test_rw_uint16(self) -> None:
        self._test_rw_internal(2, uint16_random, self.injector.mem_read_uint16, self.injector.mem_write_uint16)

    def test_rw_int32(self) -> None:
        self._test_rw_internal(4, int32_random, self.injector.mem_read_int32, self.injector.mem_write_int32)

    def test_rw_uint32(self) -> None:
        self._test_rw_internal(4, uint32_random, self.injector.mem_read_uint32, self.injector.mem_write_uint32)

    def test_rw_int64(self) -> None:
        self._test_rw_internal(8, int64_random, self.injector.mem_read_int64, self.injector.mem_write_int64)

    def test_rw_uint64(self) -> None:
        self._test_rw_internal(8, uint64_random, self.injector.mem_read_uint64, self.injector.mem_write_uint64)

    def test_rw_float(self) -> None:
        self._test_rw_internal(4, float_random, self.injector.mem_read_float, self.injector.mem_write_float)

    def test_rw_double(self) -> None:
        self._test_rw_internal(8, double_random, self.injector.mem_read_double, self.injector.mem_write_double)

    def test_rw_bytes(self) -> None:
        self._test_rw_internal(16, bytes_random, self.injector.mem_read_bytes, self.injector.mem_write_bytes, b'\x00' * 16, 16)

    def test_rw_c_string(self) -> None:
        c_string_random = lambda: ''.join([chr(choice(range(32, 127))) for _ in range(7)])
        self._test_rw_internal(8, c_string_random, self.injector.mem_read_c_string, self.injector.mem_write_c_string, '')

    def test_rw_bool_array(self):
        self._test_rw_array_internal(1, bool_random, self.injector.mem_read_bool_array, self.injector.mem_write_bool_array)

    def test_rw_char_array(self):
        self._test_rw_array_internal(1, char_random, self.injector.mem_read_char_array, self.injector.mem_write_char_array)

    def test_rw_uchar_array(self):
        self._test_rw_array_internal(1, uchar_random, self.injector.mem_read_uchar_array, self.injector.mem_write_uchar_array)

    def test_rw_int16_array(self) -> None:
        self._test_rw_array_internal(2, int16_random, self.injector.mem_read_int16_array, self.injector.mem_write_int16_array)

    def test_rw_uint16_array(self) -> None:
        self._test_rw_array_internal(2, uint16_random, self.injector.mem_read_uint16_array, self.injector.mem_write_uint16_array)

    def test_rw_int32_array(self) -> None:
        self._test_rw_array_internal(4, int32_random, self.injector.mem_read_int32_array, self.injector.mem_write_int32_array)

    def test_rw_uint32_array(self) -> None:
        self._test_rw_array_internal(4, uint32_random, self.injector.mem_read_uint32_array, self.injector.mem_write_uint32_array)

    def test_rw_int64_array(self) -> None:
        self._test_rw_array_internal(8, int64_random, self.injector.mem_read_int64_array, self.injector.mem_write_int64_array)

    def test_rw_uint64_array(self) -> None:
        self._test_rw_array_internal(8, uint64_random, self.injector.mem_read_uint64_array, self.injector.mem_write_uint64_array)

    def test_rw_float_array(self) -> None:
        self._test_rw_array_internal(4, float_random, self.injector.mem_read_float_array, self.injector.mem_write_float_array)

    def test_rw_double_array(self) -> None:
        self._test_rw_array_internal(8, double_random, self.injector.mem_read_double_array, self.injector.mem_write_double_array)

    def test_rw_pointer_array(self) -> None:
        if self.injector.bit_long == 32:
            self._test_rw_array_internal(4, uint32_random, self.injector.mem_read_pointer_array, self.injector.mem_write_pointer_array)
        else:
            self._test_rw_array_internal(8, uint32_random, self.injector.mem_read_pointer_array, self.injector.mem_write_pointer_array)

    def test_new_bool(self) -> None:
        self._test_new_internal(bool_random, self.injector.new_bool)

    def test_new_char(self) -> None:
        self._test_new_internal(char_random, self.injector.new_char)

    def test_new_uchar(self) -> None:
        self._test_new_internal(uchar_random, self.injector.new_uchar)

    def test_new_int16(self) -> None:
        self._test_new_internal(int16_random, self.injector.new_int16)

    def test_new_uint16(self) -> None:
        self._test_new_internal(uint16_random, self.injector.new_uint16)

    def test_new_int32(self) -> None:
        self._test_new_internal(int32_random, self.injector.new_int32)

    def test_new_uint32(self) -> None:
        self._test_new_internal(uint32_random, self.injector.new_uint32)

    def test_new_int64(self) -> None:
        self._test_new_internal(int64_random, self.injector.new_int64)

    def test_new_uint64(self) -> None:
        self._test_new_internal(uint64_random, self.injector.new_uint64)

    def test_new_float(self) -> None:
        self._test_new_internal(float_random, self.injector.new_float)

    def test_new_double(self) -> None:
        self._test_new_internal(double_random, self.injector.new_double)

    def test_new_pointer(self) -> None:
        if self.injector.bit_long == 32:
            self._test_new_internal(uint32_random, self.injector.new_pointer)
        else:
            self._test_new_internal(uint32_random, self.injector.new_pointer)

    def test_new_c_string(self) -> None:
        c_string_random = lambda: ''.join([chr(choice(range(32, 127))) for _ in range(randint(100, 4095))])

        for _ in range(10):
            value = c_string_random()
            string_object = self.injector.new_c_string(value)
            self.assertNotEqual(0, string_object.address)
            self.assertEqual(value, string_object.value)
            string_object.release()

    def test_new_bool_array(self) -> None:
        self._test_new_array_internal(1, bool_random, self.injector.new_bool_array)

    def test_new_char_array(self) -> None:
        self._test_new_array_internal(1, char_random, self.injector.new_char_array)

    def test_new_uchar_array(self) -> None:
        self._test_new_array_internal(1, uchar_random, self.injector.new_uchar_array)

    def test_new_int16_array(self) -> None:
        self._test_new_array_internal(2, int16_random, self.injector.new_int16_array)

    def test_new_uint16_array(self) -> None:
        self._test_new_array_internal(2, uint16_random, self.injector.new_uint16_array)

    def test_new_int32_array(self) -> None:
        self._test_new_array_internal(4, int32_random, self.injector.new_int32_array)

    def test_new_uint32_array(self) -> None:
        self._test_new_array_internal(4, uint32_random, self.injector.new_uint32_array)

    def test_new_int64_array(self) -> None:
        self._test_new_array_internal(8, int64_random, self.injector.new_int64_array)

    def test_new_uint64_array(self) -> None:
        self._test_new_array_internal(8, uint64_random, self.injector.new_uint64_array)

    def test_new_float_array(self) -> None:
        self._test_new_array_internal(4, float_random, self.injector.new_float_array)

    def test_new_double_array(self) -> None:
        self._test_new_array_internal(8, double_random, self.injector.new_double_array)

    def test_new_pointer_array(self) -> None:
        if self.injector.bit_long == 32:
            self._test_new_array_internal(4, uint32_random, self.injector.new_pointer_array)
        else:
            self._test_new_array_internal(8, uint32_random, self.injector.new_pointer_array)
