from collections.abc import Iterable
from enum import Enum, auto
from pathlib import Path
from typing import Union

from benchmarking.generate_single_query_scheme_file import generate_single_query_scheme_file
from nca.nca_cli import nca_main


class BenchmarkProcedure(Enum):
    AUDIT = (auto(), 'json')
    PROFILE = (auto(), 'profile')
    TIME = (auto(), 'json')
    VISUAL = (auto(), 'png')

    def __init__(self, identifier: int, suffix: str):
        self.suffix = suffix


class Benchmark:
    def __init__(self, scheme_file: Path, query_type: str, original_scheme_file: Path, query_name: str):
        assert str(scheme_file).endswith('-scheme.yaml')
        file_name = scheme_file.name
        self.name = file_name[:-len('-scheme.yaml')]
        self.query_type = query_type
        self._scheme_file = scheme_file
        self._argv = [
            '--scheme',
            str(scheme_file)
        ]
        self.original_scheme_file = original_scheme_file
        self.query_name = query_name

    def run(self):
        nca_main(self._argv)


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


def get_source_dir() -> Path:
    return get_repo_root_dir() / 'network-config-analyzer'


# ================================================= iterating over all benchmarks ======================================


def _contains_github(scheme_file: Path) -> bool:
    text = scheme_file.read_text()
    return 'github' in text


def _is_example_benchmark(scheme_file: Path) -> bool:
    return 'example_benchmark' in str(scheme_file)


def _at_most_one_true(bool_list: list[bool]) -> bool:
    return sum(map(int, bool_list)) <= 1


def iter_benchmarks(tests_only: bool = False, real_benchmarks_only: bool = False,
                    example_benchmark_only: bool = False) -> Iterable[Benchmark]:
    assert _at_most_one_true([tests_only, real_benchmarks_only, example_benchmark_only])

    if tests_only:
        benchmarks_dir_list = [get_tests_dir()]
    elif real_benchmarks_only or example_benchmark_only:
        benchmarks_dir_list = [get_benchmarks_dir()]
    else:
        benchmarks_dir_list = [get_tests_dir(), get_benchmarks_dir()]

    temp_scheme_dir = get_temp_scheme_dir()
    temp_scheme_dir.mkdir(exist_ok=True)
    for benchmarks_dir in benchmarks_dir_list:
        for scheme_file in benchmarks_dir.rglob('*-scheme.yaml'):
            if example_benchmark_only and not _is_example_benchmark(scheme_file):
                continue

            if _contains_github(scheme_file):
                continue

            scheme_file_relative_to_repo = scheme_file.relative_to(get_repo_root_dir())
            for new_scheme_file, query_type, query_name in generate_single_query_scheme_file(scheme_file,
                                                                                             temp_scheme_dir):
                yield Benchmark(new_scheme_file, query_type, original_scheme_file=scheme_file_relative_to_repo,
                                query_name=query_name)


if __name__ == '__main__':
    print('***all benchmarks***')
    for bm in iter_benchmarks():
        print(bm.name)
    print('***only tests***')
    for bm in iter_benchmarks(tests_only=True):
        print(bm.name)
    print('***only real***')
    for bm in iter_benchmarks(real_benchmarks_only=True):
        print(bm.name)
    print('***only example***')
    for bm in iter_benchmarks(example_benchmark_only=True):
        print(bm.name)
