from pathlib import Path
from typing import Iterable

from benchmarking.create_yaml_files import create_scheme_file_for_benchmarks, create_allow_all_default_policy_file
from benchmarking.generate_single_query_scheme_file import generate_single_query_scheme_file
from benchmarking.utils import Benchmark, get_tests_dir, get_benchmarks_dir, get_temp_scheme_dir, get_repo_root_dir


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

    create_scheme_file_for_benchmarks()
    create_allow_all_default_policy_file()

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
                yield Benchmark(
                    new_scheme_file,
                    query_type,
                    original_scheme_file_relative_to_repo=scheme_file_relative_to_repo,
                    query_name=query_name
                )


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
