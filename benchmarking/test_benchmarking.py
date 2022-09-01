import shutil
import unittest

from benchmarking.run_benchmarks import run_benchmarks
from benchmarking.utils import BenchmarkProcedure, get_benchmark_procedure_results_dir
from benchmarking.visualize_profiler_results import visualize_profiler_results


class TestBenchmarking(unittest.TestCase):
    def setUp(self):
        self.experiment_name = 'test'

    def test_run_benchmarks_tests_only_quick(self):
        run_benchmarks(self.experiment_name, tests_only=True, limit_num=10, skip_existing=False)

    def test_run_benchmarks_tests_only(self):
        run_benchmarks(self.experiment_name, tests_only=True, skip_existing=False)

    def test_run_benchmarks_example_benchmark_only(self):
        run_benchmarks(self.experiment_name, example_benchmark_only=True, skip_existing=False)

    def test_run_benchmarks_example_benchmark_only_with_skip(self):
        run_benchmarks(self.experiment_name, example_benchmark_only=True, skip_existing=True)

    def test_visualization(self):
        run_benchmarks(self.experiment_name, example_benchmark_only=True, skip_existing=True)
        visualization_dir = get_benchmark_procedure_results_dir(self.experiment_name, BenchmarkProcedure.VISUAL)
        if visualization_dir.exists():
            shutil.rmtree(visualization_dir)

        visualize_profiler_results(self.experiment_name)

        self.assertFalse(len(list(visualization_dir.iterdir())) > 0)


if __name__ == '__main__':
    unittest.main()
