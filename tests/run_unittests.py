import unittest
import sys
import os


def main():
    loader = unittest.TestLoader()
    start_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'tests',
                             'classes_unit_tests')
    suite = loader.discover(start_dir)
    runner = unittest.TextTestRunner()
    res = runner.run(suite)
    # https://docs.python.org/3/library/unittest.html#unittest.TestResult
    # res.errors: A list containing 2-tuples of TestCase instances and strings holding formatted tracebacks.
    # Each tuple represents a test which raised an unexpected exception.
    # res.failures: A list containing 2-tuples of TestCase instances and strings holding formatted tracebacks.
    # Each tuple represents a test where a failure was explicitly signalled using the TestCase.assert*() methods.
    return len(res.failures) + len(res.errors)


if __name__ == "__main__":
    sys.exit(main())
