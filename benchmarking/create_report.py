import json
from csv import DictWriter
from pathlib import Path

from benchmarking.auditing import get_auditing_results_path
from benchmarking.benchmarking_utils import get_benchmark_results_dir, iter_all_benchmarks
from benchmarking.timing import get_timing_results_path
from benchmarking.analyze_profile_results import get_top_n_cumtime_funcs


def get_report_path() -> Path:
    return get_benchmark_results_dir() / 'report.csv'


def create_report():
    """The report is organized as follows:
        - it is in .csv format for easy reading
    :return: None
    """
    lines = []
    for benchmark in iter_all_benchmarks():
        line = {'name': benchmark.name, 'query': benchmark.query}

        timing_results_path = get_timing_results_path(benchmark)
        with timing_results_path.open('r') as f:
            timing_results = json.load(f)
            line.update(timing_results)

        auditing_results_path = get_auditing_results_path(benchmark)
        with auditing_results_path.open('r') as f:
            auditing_results = json.load(f)
            line.update(auditing_results)

        top_n = 10
        top_n_cumtime_funcs = get_top_n_cumtime_funcs(benchmark, top_n)
        line.update(top_n_cumtime_funcs)

        lines.append(line)

    field_names = [field_name for field_name in lines[0].keys()]
    report_path = get_report_path()
    with report_path.open('w', newline='') as f:
        writer = DictWriter(f, fieldnames=field_names)
        writer.writerows(lines)

