from tests.interface import InjectorTest
from uniref.util.injector import AndroidInjector


class AndroidInjectorTest(InjectorTest):

    mem = None
    injector = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.injector = AndroidInjector(None, None, None, False)
        cls.mem = cls.injector.mem_alloc(alloc_size=4096)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.mem:
            cls.injector.mem_free(cls.mem)
        cls.injector.release()

    def setUp(self) -> None:
        self.injector.mem_write_bytes(self.mem, b'\x00' * 4096)

    def test_exception(self) -> None:
        ...

    def test_code_execute(self) -> None:
        ...

    def test_call_native_function(self) -> None:
        ...
