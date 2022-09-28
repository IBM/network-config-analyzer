"""A module for timing the benchmarks"""
import json
import timeit
from pathlib import Path

from benchmarking.utils import Benchmark


def time_benchmark(benchmark: Benchmark, result_path: Path) -> None:
    # TODO: maybe repeat more than once?
    n_repeat = 1
    runtimes = timeit.repeat(benchmark.run, repeat=n_repeat, number=1)
    with result_path.open('w') as f:
        json.dump({'min_runtime': min(runtimes)}, f, indent=4)
