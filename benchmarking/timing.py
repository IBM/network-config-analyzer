"""A module for timing the benchmarks"""
import json
import timeit
from pathlib import Path

from benchmarking.benchmarking_utils import Benchmark, get_benchmark_result_path


def get_timing_results_path(benchmark: Benchmark, experiment_name: str) -> Path:
    return get_benchmark_result_path(benchmark, experiment_name, 'timing', 'json')


def time_benchmark(benchmark: Benchmark, experiment_name: str) -> None:
    # TODO: maybe repeat more than once?
    n_repeat = 1
    result_path = get_timing_results_path(benchmark, experiment_name)
    if result_path.exists():
        return

    runtimes = timeit.repeat(benchmark.run, repeat=n_repeat, number=1)
    with result_path.open('w') as f:
        json.dump({'min_runtime': min(runtimes)}, f, indent=4)
