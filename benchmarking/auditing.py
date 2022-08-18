from collections import defaultdict
from queue import Empty
import json
from pathlib import Path

# Note that this must come before importing `benchmarking` so it will have an effect.
import _global_logging_flag

_global_logging_flag.ENABLED = True

from benchmarking.benchmarking_utils import iter_all_benchmarks, get_benchmark_result_path, Benchmark


def get_auditing_results_path(benchmark: Benchmark) -> Path:
    return get_benchmark_result_path(benchmark, 'auditing', 'json')


def audit_all_benchmarks():
    for benchmark in iter_all_benchmarks():
        # TODO: refactor to a nicer way of not running the same benchmark twice
        result_path = get_auditing_results_path(benchmark)
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


if __name__ == "__main__":
    audit_all_benchmarks()
