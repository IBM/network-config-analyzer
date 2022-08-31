import json
from collections import defaultdict
from pathlib import Path
from queue import Empty

import _global_logging_flag
from benchmarking.benchmarking_utils import get_benchmark_result_file, Benchmark, \
    BenchmarkResultType


def get_auditing_results_path(benchmark: Benchmark, experiment_name: str) -> Path:
    return get_benchmark_result_file(benchmark, experiment_name,
                                     BenchmarkResultType.AUDIT)


def reduce_records(records: dict[list]):
    # TODO: might need to be changed if what we are collecting is being changed
    return {key: value[0] for key, value in records.items()}


def audit_benchmark(benchmark: Benchmark, experiment_name: str) -> None:
    # TODO: this global flag is a messy. Find another way to do that
    _global_logging_flag.ENABLED = True

    result_path = get_auditing_results_path(benchmark, experiment_name)
    if result_path.exists():
        return

    benchmark.run()
    records = defaultdict(list)
    try:
        while True:
            record = _global_logging_flag.LOGGING_QUEUE.get(block=False)
            for key, value in record.items():
                records[key].append(value)
    except Empty:
        pass

    records = reduce_records(records)

    with result_path.open('w') as f:
        json.dump(records, f, indent=4)

    _global_logging_flag.ENABLED = False
