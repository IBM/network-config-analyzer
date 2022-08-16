"""A module for timing the benchmarks"""
# TODO: add testcases to the benchmark iterator
import json
import timeit
from pathlib import Path

from benchmarking.benchmarking_utils import iter_all_benchmarks, Benchmark, get_benchmark_result_path


def get_timing_results_path(benchmark: Benchmark) -> Path:
    return get_benchmark_result_path(benchmark, 'timing', 'json')


def time_all_benchmarks():
    # TODO: maybe consider running the timing more then once
    n_repeat = 1
    for benchmark in iter_all_benchmarks():
        # TODO: refactor to a nicer way of not running the same benchmark twice
        result_path = get_timing_results_path(benchmark)
        if result_path.exists():
            continue
        # TODO: uncomment this for debugging
        # if benchmark.name != 'SCC_test_calico_resources':
        #     continue
        runtimes = timeit.repeat(benchmark.run, repeat=n_repeat, number=1)
        with result_path.open('w') as f:
            json.dump({'min_runtime': min(runtimes)}, f, indent=4)


if __name__ == "__main__":
    time_all_benchmarks()
