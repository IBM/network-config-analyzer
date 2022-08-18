import json
from csv import DictWriter
from pathlib import Path

from benchmarking.auditing import get_auditing_results_path
from benchmarking.benchmarking_utils import get_benchmark_results_dir, iter_benchmarks
from benchmarking.timing import get_timing_results_path
from benchmarking.analyze_profile_results import get_top_n_cumtime_funcs


def get_report_dir(experiment_name: str) -> Path:
    report_dir = get_benchmark_results_dir(experiment_name) / 'reports'
    report_dir.mkdir(exist_ok=True)
    return report_dir


def dict_list_to_csv(lines: list[dict], path: Path):
    with path.open('w', newline='') as f:
        writer = DictWriter(f, fieldnames=lines[0].keys())
        writer.writeheader()
        writer.writerows(lines)


def create_report(experiment_name: str):
    """The report is organized as follows:
        - it is in .csv format for easy reading
    :return: None
    """
    top_n = 20
    lines = []
    report_dir = get_report_dir(experiment_name)

    for benchmark in iter_benchmarks():
        line = {'name': benchmark.name, 'query': benchmark.query}

        timing_results_path = get_timing_results_path(benchmark, experiment_name)
        with timing_results_path.open('r') as f:
            timing_results = json.load(f)
            line.update(timing_results)

        auditing_results_path = get_auditing_results_path(benchmark, experiment_name)
        with auditing_results_path.open('r') as f:
            auditing_results = json.load(f)
            line.update(auditing_results)

        lines.append(line)

        top_func_records = get_top_n_cumtime_funcs(top_n, experiment_name, benchmark)
        top_func_report_path = report_dir / f'{str(benchmark)}_top_func_report.csv'
        dict_list_to_csv(top_func_records, top_func_report_path)

    top_func_records = get_top_n_cumtime_funcs(top_n, experiment_name)
    top_func_report_path = report_dir / f'accumulated_top_func_report.csv'
    dict_list_to_csv(top_func_records, top_func_report_path)

    timing_report_path = report_dir / 'timing_report.csv'
    dict_list_to_csv(lines, timing_report_path)


if __name__ == "__main__":
    create_report('test')
