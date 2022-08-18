"""A module for timing the benchmarks"""
import json
import timeit
from pathlib import Path

from benchmarking.benchmarking_utils import iter_benchmarks, Benchmark, get_benchmark_result_path


def get_timing_results_path(benchmark: Benchmark, experiment_name: str) -> Path:
    return get_benchmark_result_path(benchmark, experiment_name, 'timing', 'json')


def time_benchmarks(experiment_name: str):
    # TODO: maybe repeat more than once?
    n_repeat = 1
    for benchmark in iter_benchmarks():
        result_path = get_timing_results_path(benchmark, experiment_name)
        if result_path.exists():
            continue

        runtimes = timeit.repeat(benchmark.run, repeat=n_repeat, number=1)
        with result_path.open('w') as f:
            json.dump({'min_runtime': min(runtimes)}, f, indent=4)


if __name__ == "__main__":
    time_benchmarks('test')
