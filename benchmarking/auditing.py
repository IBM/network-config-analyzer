import json
from pathlib import Path

from benchmarking.benchmarking_utils import iter_all_benchmarks, Benchmark, get_benchmark_result_path
from runtime_param_logger import global_runtime_param_logger


def get_auditing_results_path(benchmark: Benchmark) -> Path:
    return get_benchmark_result_path(benchmark, 'auditing', 'json')


def audit_all_benchmarks():
    for benchmark in iter_all_benchmarks():
        # TODO: refactor to a nicer way of not running the same benchmark twice
        result_path = get_auditing_results_path(benchmark)
        if result_path.exists():
            continue

        with global_runtime_param_logger:
            benchmark.run()

        records = global_runtime_param_logger.get_records()
        with result_path.open('w') as f:
            json.dump(records, f, indent=4)


if __name__ == "__main__":
    audit_all_benchmarks()
