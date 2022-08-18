from cProfile import Profile
from pathlib import Path
from pstats import Stats

from benchmarking.benchmarking_utils import iter_benchmarks, Benchmark, get_benchmark_result_path


def get_profile_results_path(benchmark: Benchmark, experiment_name: str) -> Path:
    profile_results_file = get_benchmark_result_path(benchmark, experiment_name, 'profile', 'profile')
    return profile_results_file


def load_profile_results(benchmark: Benchmark, experiment_name: str) -> Stats:
    profile_results_file = get_profile_results_path(benchmark, experiment_name)
    return Stats(str(profile_results_file))


def profile_benchmarks(experiment_name: str):
    for benchmark in iter_benchmarks():
        result_path = get_profile_results_path(benchmark, experiment_name)
        if result_path.exists():
            continue
        with Profile() as profiler:
            benchmark.run()
        profiler.dump_stats(result_path)


if __name__ == "__main__":
    profile_benchmarks('test')
