# TODO: maybe add an histogram of the number of intervals
from pathlib import Path

from benchmarking.auditor import Auditor
from benchmarking.utils import Benchmark


def audit_benchmark(benchmark: Benchmark, result_path: Path) -> None:
    with Auditor(result_path):
        benchmark.run()
