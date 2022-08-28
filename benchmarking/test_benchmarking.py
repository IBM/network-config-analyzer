import shutil
import unittest

from benchmarking.benchmarking_utils import get_benchmark_results_dir
from run_benchmarks import run_benchmarks


class BenchmarkingTest(unittest.TestCase):
    # TODO: add test only for creating the reports
    def setUp(self):
        self.experiment_name = 'test'
        results_dir = get_benchmark_results_dir(self.experiment_name)
        if results_dir.exists():
            shutil.rmtree(results_dir)

    def test_run_benchmarks_quick(self):
        run_benchmarks(self.experiment_name, tests_only=True, limit_num=10)

    def test_run_benchmarks(self):
        run_benchmarks(self.experiment_name, tests_only=True)


if __name__ == '__main__':
    unittest.main()
