from enum import Enum, auto
from pathlib import Path
from typing import Union

from nca.nca_cli import nca_main


class BenchmarkProcedure(Enum):
    AUDIT = (auto(), 'json')
    PROFILE = (auto(), 'profile')
    TIME = (auto(), 'json')
    VISUAL = (auto(), 'png')

    def __init__(self, identifier: int, suffix: str):
        self.suffix = suffix


class Benchmark:
    def __init__(self, scheme_file: Path, query_type: str, original_scheme_file_relative_to_repo: Path,
                 query_name: str):
        assert str(scheme_file).endswith('-scheme.yaml')
        file_name = scheme_file.name
        self.name = file_name[:-len('-scheme.yaml')]
        self.query_type = query_type
        self._scheme_file = scheme_file
        self._argv = [
            '--scheme',
            str(scheme_file)
        ]
        self.original_scheme_file_relative_to_repo = original_scheme_file_relative_to_repo
        self.query_name = query_name

    def run(self):
        nca_main(self._argv)

    def get_original_dir_relative_to_repo(self):
        return self.original_scheme_file_relative_to_repo.parent


# ================================================= Get Paths ==========================================================


def get_repo_root_dir() -> Path:
    project_name = 'network-config-analyzer'
    cwd = Path.cwd()
    last_matching_parent = cwd if cwd.name == project_name else None

    for parent in cwd.parents:
        if parent.name == project_name:
            last_matching_parent = parent

    if last_matching_parent is None:
        raise RuntimeError(f'could not find project root directory {project_name}')

    return last_matching_parent


def get_tests_dir() -> Path:
    return get_repo_root_dir() / 'tests'


def get_benchmarks_dir() -> Path:
    return get_repo_root_dir() / 'benchmarks'


def get_temp_scheme_dir() -> Path:
    temp_scheme_dir = get_repo_root_dir() / 'temp_scheme'
    return temp_scheme_dir


def get_benchmark_results_dir() -> Path:
    return get_repo_root_dir() / 'benchmark_results'


def get_experiment_results_dir(experiment_name: str) -> Path:
    results_dir = get_benchmark_results_dir() / experiment_name
    return results_dir


def get_benchmark_procedure_results_dir(experiment_name: str, procedure: BenchmarkProcedure) -> Path:
    results_dir = get_experiment_results_dir(experiment_name) / procedure.name.lower()
    return results_dir


def get_benchmark_result_file(benchmark: Union[Benchmark, str], experiment_name: str,
                              procedure: BenchmarkProcedure) -> Path:
    if isinstance(benchmark, Benchmark):
        benchmark = benchmark.name
    results_dir = get_benchmark_procedure_results_dir(experiment_name, procedure)
    return results_dir / f'{benchmark}.{procedure.suffix}'
