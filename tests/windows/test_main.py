from scanner import *
from injector import *
from mono_injector import *


def test_main() -> None:
    util_suite = TestSuite()
    util_loader = TestLoader()
    util_suite.addTest(util_loader.loadTestsFromTestCase(InjectorTest))
    util_suite.addTest(util_loader.loadTestsFromTestCase(CMemoryScannerTest))

    mono_suite = TestSuite()
    mono_loader = TestLoader()
    mono_suite.addTest(mono_loader.loadTestsFromTestCase(MonoInjectorTest))
    mono_suite.addTest(mono_loader.loadTestsFromTestCase(Il2cppInjectorTest))

    test_runner = TextTestRunner(verbosity=2)
    test_runner.run(util_suite)
    test_runner.run(mono_suite)


if __name__ == "__main__":
    test_main()
