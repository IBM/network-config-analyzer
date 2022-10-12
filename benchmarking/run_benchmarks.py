import logging
import os
from argparse import ArgumentParser
from contextlib import redirect_stdout, redirect_stderr

from benchmarking.auditing import audit_benchmark
from benchmarking.create_report import create_report, create_report_per_benchmark
from benchmarking.create_yaml_files import create_scheme_file_for_benchmarks, create_allow_all_default_policy_file
from benchmarking.profiling import profile_benchmark
from benchmarking.timing import time_benchmark
from benchmarking.utils import iter_benchmarks, get_benchmark_result_file, BenchmarkProcedure, \
    get_experiment_results_dir


# TODO: maybe add an histogram of the number of intervals
# TODO: how do we collect data about the configurations from a benchmark that has more then one policy?


def _get_logger(experiment_name: str):
    logger = logging.getLogger(experiment_name)
    logger.setLevel(logging.INFO)
    experiment_results_dir = get_experiment_results_dir(experiment_name)
    experiment_results_dir.mkdir(parents=True, exist_ok=True)
    log_file = experiment_results_dir / 'progress.log'
    handler = logging.FileHandler(log_file, 'w')
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def run_benchmarks(experiment_name: str, example_benchmark_only: bool = False, tests_only: bool = False,
                   real_benchmarks_only: bool = False, limit_num: int = None, skip_existing: bool = True,
                   hide_output: bool = True):
    logger = _get_logger(experiment_name)
    logger.info('running benchmarks...')

    logger.info('creating scheme files for real benchmarks.')
    create_scheme_file_for_benchmarks()

    logger.info('creating policy for permits.')
    create_allow_all_default_policy_file()

    benchmark_list = list(iter_benchmarks(tests_only, real_benchmarks_only, example_benchmark_only))
    if limit_num is not None:
        benchmark_list = benchmark_list[:limit_num]

    benchmark_procedure_to_func = {
        BenchmarkProcedure.TIME: time_benchmark,
        BenchmarkProcedure.PROFILE: profile_benchmark,
        BenchmarkProcedure.AUDIT: audit_benchmark
    }
    for i, benchmark in enumerate(benchmark_list, 1):
        # TODO: skip this benchmark
        if 'FromJakeKitchener' in benchmark.name:
            continue
        for benchmark_procedure, func in benchmark_procedure_to_func.items():
            logger.info(f'{i} / {len(benchmark_list)} - running {benchmark_procedure.name} on {benchmark.name}.')
            result_file = get_benchmark_result_file(benchmark, experiment_name, benchmark_procedure)
            result_file.parent.mkdir(parents=True, exist_ok=True)
            if skip_existing and result_file.exists():
                logger.info(f'{result_file} exists - skipping.')
            else:
                if hide_output:
                    with open(os.devnull, 'w') as f, redirect_stdout(f), redirect_stderr(f):
                        func(benchmark, result_file)
                else:
                    func(benchmark, result_file)
        logger.info(f'creating report for benchmark {benchmark.name}.')
        create_report_per_benchmark(experiment_name, benchmark)

    logger.info('finished running benchmarks. creating reports...')
    create_report(experiment_name, benchmark_list)
    logger.info('finished creating reports.')


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('--experiment_name', type=str, default='test', help='the name of the experiment')
    args = parser.parse_args()
    run_benchmarks(args.experiment_name)
