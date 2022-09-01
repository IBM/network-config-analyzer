from cProfile import Profile
from pathlib import Path

from benchmarking.utils import Benchmark


def profile_benchmark(benchmark: Benchmark, result_path: Path) -> None:
    with Profile() as profiler:
        benchmark.run()
    profiler.dump_stats(result_path)
