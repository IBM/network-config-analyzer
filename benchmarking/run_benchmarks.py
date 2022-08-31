import logging
from argparse import ArgumentParser

from benchmarking.audit import audit_benchmark
from benchmarking.benchmarking_utils import iter_benchmarks
from benchmarking.create_report import create_report
from benchmarking.create_yaml_files import create_scheme_files, create_allow_all_default_policy_file
from benchmarking.profiling import profile_benchmark
from benchmarking.timing import time_benchmark


# TODO: how do we collect data about the configurations from a benchmark that has more then one policy?

def get_logger():
    logger = logging.getLogger('run_benchmarks')
    logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler('run_benchmarks.log', 'w')
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger


def run_benchmarks(experiment_name: str, example_benchmark_only: bool = False, tests_only: bool = False,
                   real_benchmarks_only: bool = False, limit_num: int = None):
    logger = get_logger()
    logger.info('running benchmarks...')

    logger.info('creating scheme files for real benchmarks')
    create_scheme_files()

    logger.info('creating policy for permits')
    create_allow_all_default_policy_file()

    benchmark_list = list(iter_benchmarks(tests_only, real_benchmarks_only, example_benchmark_only))
    if limit_num is not None:
        benchmark_list = benchmark_list[:limit_num]

    for i, benchmark in enumerate(benchmark_list, 1):
        logger.info(f'{i} / {len(benchmark_list)} : {benchmark.name}')

        time_benchmark(benchmark, experiment_name)
        profile_benchmark(benchmark, experiment_name)
        audit_benchmark(benchmark, experiment_name)

    logger.info('finished running benchmarks. creating reports')
    create_report(experiment_name, benchmark_list)
    logger.info('finished creating reports')


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('--experiment_name', type=str, default='test',
                        help='the name of the experiment')
    args = parser.parse_args()
    run_benchmarks(args.experiment_name)
