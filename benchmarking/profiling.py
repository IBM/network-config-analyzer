from cProfile import Profile
from pathlib import Path
from pstats import Stats

from benchmarking.benchmarking_utils import iter_all_benchmarks, Benchmark, get_benchmark_result_path


def get_profile_results_path(benchmark: Benchmark) -> Path:
    profile_results_file = get_benchmark_result_path(benchmark, 'profile', 'profile')
    return profile_results_file


def load_profile_results(benchmark: Benchmark) -> Stats:
    profile_results_file = get_profile_results_path(benchmark)
    return Stats(str(profile_results_file))


def profile_all_benchmarks():
    for benchmark in iter_all_benchmarks():
        result_path = get_profile_results_path(benchmark)
        # TODO: maybe refactor this skipping?
        if result_path.exists():
            continue
        with Profile() as profiler:
            benchmark.run()
        profiler.dump_stats(result_path)


if __name__ == "__main__":
    profile_all_benchmarks()
