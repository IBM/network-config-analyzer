import json
from csv import DictWriter
from pathlib import Path

from benchmarking.analyze_profile_results import get_function_profiles
from benchmarking.utils import get_experiment_results_dir, Benchmark, get_benchmark_result_file, BenchmarkProcedure

TOP_N = 40


def _get_report_dir(experiment_name: str) -> Path:
    report_dir = get_experiment_results_dir(experiment_name) / 'reports'
    report_dir.mkdir(exist_ok=True, parents=True)
    return report_dir


def _round_all_numeric_entries(lines: list[dict]) -> list[dict]:
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


def _dict_list_to_csv(lines: list[dict], path: Path):
    lines = _round_all_numeric_entries(lines)
    with path.open('w', newline='') as f:
        writer = DictWriter(f, fieldnames=lines[0].keys())
        writer.writeheader()
        writer.writerows(lines)


def _extract_report_data_from_audit_result(audit_result: list) -> dict:
    # TODO: change this when this becomes more complicated
    return audit_result[0][0]


def create_report_per_benchmark(experiment_name: str, benchmark: Benchmark):
    report_dir = _get_report_dir(experiment_name)
    top_func_records = get_function_profiles(experiment_name, [benchmark])[:TOP_N]
    top_func_report_path = report_dir / f'{benchmark.name}_top_func_report.csv'
    _dict_list_to_csv(top_func_records, top_func_report_path)


def create_report(experiment_name: str, benchmark_list: list[Benchmark]):
    """Creates the report for the experiment, after running all the benchmarking procedures"""
    lines = []
    report_dir = _get_report_dir(experiment_name)

    for benchmark in benchmark_list:
        line = {'name': benchmark.name, 'query_type': benchmark.query_type}

        timing_results_path = get_benchmark_result_file(benchmark, experiment_name, BenchmarkProcedure.TIME)
        with timing_results_path.open('r') as f:
            timing_results = json.load(f)
            line.update(timing_results)

        auditing_results_path = get_benchmark_result_file(benchmark, experiment_name, BenchmarkProcedure.AUDIT)
        with auditing_results_path.open('r') as f:
            auditing_results = json.load(f)

        audit_data = _extract_report_data_from_audit_result(auditing_results)
        line.update(audit_data)

        lines.append(line)

    top_func_records = get_function_profiles(experiment_name, benchmark_list)[:TOP_N]
    top_func_report_path = report_dir / f'accumulated_top_func_report.csv'
    _dict_list_to_csv(top_func_records, top_func_report_path)

    timing_report_path = report_dir / 'timing_report.csv'
    _dict_list_to_csv(lines, timing_report_path)
