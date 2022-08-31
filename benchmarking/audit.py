from pathlib import Path

from benchmarking.auditor import Auditor
from benchmarking.benchmarking_utils import get_benchmark_result_file, Benchmark, \
    BenchmarkResultType

# TODO: maybe add an histogram of the number of intervals


def get_auditing_results_path(benchmark: Benchmark, experiment_name: str) -> Path:
    return get_benchmark_result_file(benchmark, experiment_name, BenchmarkResultType.AUDIT)


def audit_benchmark(benchmark: Benchmark, experiment_name: str) -> None:
    result_path = get_auditing_results_path(benchmark, experiment_name)
    if result_path.exists():
        return

    with Auditor(result_path):
        benchmark.run()
