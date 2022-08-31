import os
from collections.abc import Iterable
from contextlib import redirect_stdout, redirect_stderr
from enum import Enum
from pathlib import Path
from typing import Union

from yaml import load, Loader

from benchmarking.generate_single_query_scheme_file import generate_single_query_scheme_file, get_query_type
from nca import nca_main

# TODO: create a sample benchmark that takes a short amount of time to run, and this will be used to test things
_ALLOWED_LABELS = ['auditing', 'profile', 'timing', 'visualization']


class BenchmarkResultType(Enum):
    AUDIT = '.json'
    PROFILE = '.profile'
    TIME = '.json'
    VISUAL = '.png'

    def __init__(self, suffix: str):
        self.suffix = suffix


class Benchmark:
    def __init__(self, scheme_file: Path):
        assert str(scheme_file).endswith('-scheme.yaml')
        file_name = scheme_file.name
        self.name = file_name[:-len('-scheme.yaml')]
        self._scheme_file = scheme_file
        self._argv = [
            '--scheme',
            str(scheme_file)
        ]

    def run(self):
        # TODO: Ask Adi if running with output redirection is the right thing todo
        # TODO: add some flag for running with or without the output
        # with open(os.devnull, 'w') as f:
        #     with redirect_stdout(f), redirect_stderr(f):
        #         nca_main(self._argv)
        nca_main(self._argv)

    def get_query_type(self) -> str:
        with self._scheme_file.open('r') as f:
            scheme = load(f, Loader)

        return get_query_type(scheme['queries'][0])


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
    temp_scheme_dir.mkdir(exist_ok=True)
    return temp_scheme_dir


def get_experiment_results_dir(experiment_name: str) -> Path:
    results_dir = get_repo_root_dir() / 'benchmark_results' / experiment_name
    results_dir.mkdir(parents=True, exist_ok=True)
    return results_dir


def get_benchmark_results_dir(experiment_name: str, result_type: BenchmarkResultType) -> Path:
    results_dir = get_experiment_results_dir(experiment_name) / result_type.name.lower()
    # TODO: I'm not sure that this is the correct place to create the directory
    results_dir.mkdir(exist_ok=True)
    return results_dir


def get_benchmark_result_file(benchmark: Union[Benchmark, str], experiment_name: str, result_type: BenchmarkResultType) -> Path:
    if isinstance(benchmark, Benchmark):
        benchmark = benchmark.name
    results_dir = get_benchmark_results_dir(experiment_name, result_type)
    return results_dir / f'{benchmark}.{result_type.suffix}'


def contains_github(scheme_file: Path) -> bool:
    text = scheme_file.read_text()
    return 'github' in text


def is_example_benchmark(scheme_file: Path) -> bool:
    return 'example_benchmark' in str(scheme_file)


def at_most_one_true(bool_list: list[bool]) -> bool:
    return sum(map(int, bool_list)) <= 1


def iter_benchmarks(tests_only: bool = False, real_benchmarks_only: bool = False,
                    example_benchmark_only: bool = False) -> Iterable[Benchmark]:
    assert at_most_one_true([tests_only, real_benchmarks_only, example_benchmark_only])

    if tests_only:
        benchmarks_dir_list = [get_tests_dir()]
    elif real_benchmarks_only or example_benchmark_only:
        benchmarks_dir_list = [get_benchmarks_dir()]
    else:
        benchmarks_dir_list = [get_tests_dir(), get_benchmarks_dir()]

    temp_scheme_dir = get_temp_scheme_dir()
    for benchmarks_dir in benchmarks_dir_list:
        for scheme_file in benchmarks_dir.rglob('*-scheme.yaml'):
            if example_benchmark_only and not is_example_benchmark(scheme_file):
                continue

            if contains_github(scheme_file):
                continue

            for new_scheme_file in generate_single_query_scheme_file(scheme_file, temp_scheme_dir):
                yield Benchmark(new_scheme_file)


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

