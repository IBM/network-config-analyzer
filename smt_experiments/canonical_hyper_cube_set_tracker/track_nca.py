# TODO: after testing, run with all of the benchmarks
import logging
import os
import traceback
from contextlib import redirect_stdout, redirect_stderr
from pprint import pformat

from smt_experiments.canonical_hyper_cube_set_tracker.trace_logger import init_benchmark_tracing
from smt_experiments.canonical_hyper_cube_set_tracker.utils import get_repo_root_dir, replace_files, \
    revert_replace_files, get_traces_dir


def get_logger():
    logger = logging.getLogger('tracing')
    logger.setLevel(logging.INFO)
    log_file = get_traces_dir() / 'progress.log'
    handler = logging.FileHandler(log_file, 'w')
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def benchmark_filter(benchmark) -> bool:
    if 'FromJakeKitchener' in benchmark.name:
        return False
    return True


def trace_benchmarks(example_benchmark_only: bool = False, tests_only: bool = False,
                     real_benchmarks_only: bool = False, limit_num: int = None, hide_output: bool = True):
    logger = get_logger()
    logger.info('tracing benchmarks...')

    file_to_replace = 'CanonicalHyperCubeSet.py'
    original_dir = get_repo_root_dir() / 'nca' / 'CoreDS'
    replacement_dir = get_repo_root_dir() / 'smt_experiments' / 'canonical_hyper_cube_set_tracker'
    logger.info(f'replacing file {file_to_replace} in {original_dir} and {replacement_dir}.')
    replace_files(file_to_replace, original_dir, replacement_dir)

    from benchmarking.create_yaml_files import create_scheme_file_for_benchmarks
    from benchmarking.create_yaml_files import create_allow_all_default_policy_file
    from benchmarking.utils import iter_benchmarks

    logger.info('creating scheme files for real benchmarks.')
    create_scheme_file_for_benchmarks()
    logger.info('creating policy for permits.')
    create_allow_all_default_policy_file()

    benchmarks = iter_benchmarks(tests_only, real_benchmarks_only, example_benchmark_only)
    benchmarks = list(filter(benchmark_filter, benchmarks))
    if limit_num is not None:
        benchmarks = benchmarks[:limit_num]

    benchmarks_with_exception = []
    for i, benchmark in enumerate(benchmarks, 1):
        logger.info(f'{i} / {len(benchmarks)} - tracing benchmark {benchmark.name}.')
        # TODO: make sure that we do not have benchmarks with duplicate names.
        init_benchmark_tracing(benchmark.name)
        try:
            if hide_output:
                with open(os.devnull, 'w') as f, redirect_stdout(f), redirect_stderr(f):
                    benchmark.run()
            else:
                benchmark.run()
        except:
            tb = traceback.format_exc()
            benchmarks_with_exception.append(benchmark)
            logger.info(f'got exception in {benchmark.name}.')
            logger.info(tb)

    logger.info('reverting file replacement.')
    revert_replace_files(file_to_replace, original_dir, replacement_dir)

    logger.info(f'finished tracing benchmark. '
                f'got exception in {len(benchmarks_with_exception)} out of {len(benchmarks)}')
    logger.info(f'benchmarks with exception: {pformat(benchmarks_with_exception)}')


if __name__ == '__main__':
    trace_benchmarks(tests_only=True, limit_num=20)
