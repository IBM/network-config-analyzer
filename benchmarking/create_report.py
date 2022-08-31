import json
from csv import DictWriter
from pathlib import Path

from benchmarking.analyze_profile_results import get_function_profiles
from benchmarking.audit import get_auditing_results_path
from benchmarking.benchmarking_utils import get_experiment_results_dir, Benchmark
from benchmarking.timing import get_timing_results_path


def get_report_dir(experiment_name: str) -> Path:
    report_dir = get_experiment_results_dir(experiment_name) / 'reports'
    report_dir.mkdir(exist_ok=True)
    return report_dir


def round_all_numeric_entries(lines: list[dict]) -> list[dict]:
    new_lines = []
    for line in lines:
        new_line = {}
        for key, value in line.items():
            if isinstance(value, float):
                new_line[key] = round(value, 5)
            else:
                new_line[key] = value
        new_lines.append(new_line)
    return new_lines


def dict_list_to_csv(lines: list[dict], path: Path):
    lines = round_all_numeric_entries(lines)
    with path.open('w', newline='') as f:
        writer = DictWriter(f, fieldnames=lines[0].keys())
        writer.writeheader()
        writer.writerows(lines)


def extract_report_data_from_audit_result(audit_result: list[dict]) -> dict:
    # TODO: change this when this becomes more complicated
    return audit_result[0]


def create_report(experiment_name: str, benchmark_list: list[Benchmark]):
    """The report is organized as follows:
        - it is in .csv format for easy reading
    :return: None
    """
    top_n = 40
    lines = []
    report_dir = get_report_dir(experiment_name)

    for benchmark in benchmark_list:
        line = {'name': benchmark.name, 'query_type': benchmark.get_query_type()}

        timing_results_path = get_timing_results_path(benchmark, experiment_name)
        with timing_results_path.open('r') as f:
            timing_results = json.load(f)
            line.update(timing_results)

        auditing_results_path = get_auditing_results_path(benchmark, experiment_name)
        with auditing_results_path.open('r') as f:
            auditing_results = json.load(f)

        audit_data = extract_report_data_from_audit_result(auditing_results)
        line.update(audit_data)

        lines.append(line)

        top_func_records = get_function_profiles(experiment_name, [benchmark])[:top_n]
        top_func_report_path = report_dir / f'{benchmark.name}_top_func_report.csv'
        dict_list_to_csv(top_func_records, top_func_report_path)

    top_func_records = get_function_profiles(experiment_name, benchmark_list)[:top_n]
    top_func_report_path = report_dir / f'accumulated_top_func_report.csv'
    dict_list_to_csv(top_func_records, top_func_report_path)

    timing_report_path = report_dir / 'timing_report.csv'
    dict_list_to_csv(lines, timing_report_path)
