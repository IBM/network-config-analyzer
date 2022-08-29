import os
from collections.abc import Iterable
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

from yaml import load, Loader

from benchmarking.generate_single_query_scheme_file import generate_single_query_scheme_file, get_query_type
from nca import nca_main


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
        with open(os.devnull, 'w') as f:
            with redirect_stdout(f), redirect_stderr(f):
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


def get_benchmark_results_dir(experiment_name: str) -> Path:
    results_dir = get_repo_root_dir() / 'benchmark_results' / experiment_name
    results_dir.mkdir(parents=True, exist_ok=True)
    return results_dir


def get_benchmark_result_path(benchmark: Benchmark, experiment_name: str, label: str, suffix: str) -> Path:
    results_dir = get_benchmark_results_dir(experiment_name) / label
    results_dir.mkdir(exist_ok=True)
    return results_dir / f'{benchmark.name}.{suffix}'


def contains_github(scheme_file: Path) -> bool:
    text = scheme_file.read_text()
    return 'github' in text


def iter_benchmarks(tests_only: bool = False) -> Iterable[Benchmark]:
    benchmarks_dir_list = [get_tests_dir()]
    temp_scheme_dir = get_temp_scheme_dir()
    if not tests_only:
        benchmarks_dir_list.append(get_benchmarks_dir())
    for benchmarks_dir in benchmarks_dir_list:
        for scheme_file in benchmarks_dir.rglob('*-scheme.yaml'):
            # TODO: is that the correct thing to do? to skip the github files?
            if contains_github(scheme_file):
                continue
            # TODO: add support for this benchmark
            if scheme_file.name.startswith('FromJakeKitchener'):
                continue

            for new_scheme_file in generate_single_query_scheme_file(scheme_file, temp_scheme_dir):
                yield Benchmark(new_scheme_file)


if __name__ == '__main__':
    for bm in iter_benchmarks():
        print(bm.name)
