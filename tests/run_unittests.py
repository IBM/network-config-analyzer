import unittest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'network-config-analyzer'))


def main():
    loader = unittest.TestLoader()
    start_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'tests',
                             'classes_unit_tests')
    suite = loader.discover(start_dir)
    runner = unittest.TextTestRunner()
    return runner.run(suite)


if __name__ == "__main__":
    sys.exit(main())
