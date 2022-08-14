"""A module for timing the benchmarks"""
# TODO: refactor and implement
import timeit

from benchmarking.benchmarking_utils import iter_all_benchmarks


def time_all_benchmarks():
    for benchmark in iter_all_benchmarks():
        runtime = timeit.repeat(benchmark.run, repeat=5, number=1)
        # TODO: do something else with the result
        print(runtime)


if __name__ == "__main__":
    time_all_benchmarks()
