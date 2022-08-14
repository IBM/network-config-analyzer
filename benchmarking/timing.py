"""A module for timing the benchmarks"""
# TODO: refactor and implement
import timeit
from itertools import product

from benchmarking.benchmarking_utils import get_all_benchmark_dirs, get_all_queries, Benchmark


def time_all_benchmarks():
    benchmark_dirs = get_all_benchmark_dirs()
    queries = get_all_queries()
    for benchmark_dir, query in product(benchmark_dirs, queries):
        benchmark = Benchmark(benchmark_dir, query)
        runtime = timeit.repeat(benchmark.run, repeat=5, number=1)
        # TODO: do something else with the result
        print(runtime)


if __name__ == "__main__":
    time_all_benchmarks()
