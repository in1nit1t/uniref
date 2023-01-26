from unittest import *

from injector import *


def test_main() -> None:
    util_suite = TestSuite()
    util_loader = TestLoader()
    util_suite.addTest(util_loader.loadTestsFromTestCase(AndroidInjectorTest))

    test_runner = TextTestRunner(verbosity=2)
    test_runner.run(util_suite)


if __name__ == "__main__":
    test_main()
