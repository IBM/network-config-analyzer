import cProfile
from pstats import Stats, SortKey
import shutil
import logging

from nca import nca_main
from pathlib import Path

from benchmarking.benchmarking_utils import get_repo_root_dir


logging.basicConfig(level=logging.INFO)
TESTS_DIR = get_repo_root_dir() / 'tests'
PROFILE_RESULTS_DIR = get_repo_root_dir() / 'profile_results'


def profile_all_scheme_files() -> None:
    """Run all the scheme files and save the profiler output to a file,
    with the same directory structure as in tests"""
    if PROFILE_RESULTS_DIR.exists():
        shutil.rmtree(PROFILE_RESULTS_DIR)
    PROFILE_RESULTS_DIR.mkdir()

    all_scheme_files = list(TESTS_DIR.rglob('*scheme.yaml'))
    for i, scheme_file in enumerate(all_scheme_files):

        logging.info(f'running scheme {scheme_file}')
        logging.info(f'{i + 1} out of {len(all_scheme_files)} schemes')

        with cProfile.Profile() as profiler:
            nca_main(['--scheme', str(scheme_file.absolute())])

        scheme_file_relative_to_tests_dir = scheme_file.relative_to(TESTS_DIR)
        profile_results_file = PROFILE_RESULTS_DIR / scheme_file_relative_to_tests_dir.with_suffix('.profile')
        profile_results_file.parent.mkdir(parents=True, exist_ok=True)
        profiler.dump_stats(profile_results_file)


def read_all_profile_results() -> list[tuple[Path, Stats]]:
    """Returns a list m a profile result file path to the profile result stats object"""
    profile_results = []
    for profile_result_file in PROFILE_RESULTS_DIR.rglob('*.profile'):
        stats = Stats(str(profile_result_file))
        profile_results.append((profile_result_file, stats))
    return profile_results


def get_total_runtime(entry: tuple[Path, Stats]) -> float:
    """For sorting by total runtime"""
    return entry[1].total_tt


def clear_bad_profile_dirs():
    for bad_profile_dir in TESTS_DIR.rglob('*.profile'):
        shutil.rmtree(bad_profile_dir)


if __name__ == "__main__":
    # profile_all_scheme_files()

    res = read_all_profile_results()
    res.sort(key=get_total_runtime, reverse=True)
    longest_scheme, longest_scheme_profile_result = res[0]
    print(f'The longest scheme is {str(longest_scheme.relative_to(PROFILE_RESULTS_DIR))}')

    match_only_local = 'network-config-analyzer'
    n_results_to_show = 20
    print('***** stats sorted by CUMULATIVE*****')
    longest_scheme_profile_result.sort_stats(SortKey.CUMULATIVE).print_stats(match_only_local, n_results_to_show)
    print('***** stats sorted by TIME*****')
    longest_scheme_profile_result.sort_stats(SortKey.TIME).print_stats(match_only_local, n_results_to_show)

    # clear_bad_profile_dirs()
