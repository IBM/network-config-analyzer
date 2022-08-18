from collections import defaultdict
from queue import Empty
import json
from pathlib import Path

from benchmarking.benchmarking_utils import iter_benchmarks, get_benchmark_result_path, Benchmark
import _global_logging_flag


def get_auditing_results_path(benchmark: Benchmark, experiment_name: str) -> Path:
    return get_benchmark_result_path(benchmark, experiment_name, 'auditing', 'json')


def audit_benchmarks(experiment_name: str):
    _global_logging_flag.ENABLED = True

    for benchmark in iter_benchmarks():
        result_path = get_auditing_results_path(benchmark, experiment_name)
        if result_path.exists():
            continue

        benchmark.run()

        records = defaultdict(list)
        try:
            while True:
                record = _global_logging_flag.LOGGING_QUEUE.get(block=False)
                for key, value in record.items():
                    records[key].append(value)
        except Empty:
            pass

        with result_path.open('w') as f:
            json.dump(records, f, indent=4)

    _global_logging_flag.ENABLED = False


if __name__ == "__main__":
    audit_benchmarks('test')
