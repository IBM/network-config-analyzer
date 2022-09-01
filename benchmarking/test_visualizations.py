import shutil
import unittest

from benchmarking.run_benchmarks import run_benchmarks
from benchmarking.utils import get_benchmark_procedure_results_dir, BenchmarkProcedure
from benchmarking.visualize_profiler_results import visualize_profiler_results


class MyTestCase(unittest.TestCase):
    def setUp(self):
        self.experiment_name = 'test'

    def test_visualization(self):
        run_benchmarks(self.experiment_name, example_benchmark_only=True, skip_existing=True)
        visualization_dir = get_benchmark_procedure_results_dir(self.experiment_name, BenchmarkProcedure.VISUAL)
        if visualization_dir.exists():
            shutil.rmtree(visualization_dir)

        visualize_profiler_results(self.experiment_name)

        self.assertFalse(len(list(visualization_dir.iterdir())) > 0)


if __name__ == '__main__':
    unittest.main()
