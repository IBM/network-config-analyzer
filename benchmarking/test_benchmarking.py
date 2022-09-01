import unittest

from benchmarking.run_benchmarks import run_benchmarks

# TODO: run tests with skip existing, the order of running the tests is important


class TestBenchmarking(unittest.TestCase):
    def setUp(self):
        self.experiment_name = 'test'

    def test_run_benchmarks_tests_only(self):
        run_benchmarks(self.experiment_name, tests_only=True, skip_existing=False)

    def test_run_benchmarks_tests_only_with_skip(self):
        run_benchmarks(self.experiment_name, tests_only=True, skip_existing=True)

    def test_run_benchmarks_tests_only_quick(self):
        run_benchmarks(self.experiment_name, tests_only=True, limit_num=10, skip_existing=False)

    def test_run_benchmarks_example_benchmark_only(self):
        run_benchmarks(self.experiment_name, example_benchmark_only=True, skip_existing=False)

    def test_run_benchmarks_example_benchmark_only_with_skip(self):
        run_benchmarks(self.experiment_name, example_benchmark_only=True, skip_existing=True)


if __name__ == '__main__':
    unittest.main()
