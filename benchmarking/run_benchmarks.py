from argparse import ArgumentParser

from benchmarking.create_report import create_report
from benchmarking.profiling import profile_benchmarks
from benchmarking.timing import time_benchmarks
from benchmarking.auditing import audit_benchmarks


def run_all_benchmarks(experiment_name: str):
    time_benchmarks(experiment_name)
    profile_benchmarks(experiment_name)
    audit_benchmarks(experiment_name)
    create_report(experiment_name)


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('--experiment_name', type=str, default='test',
                        help='the name of the experiment')
    args = parser.parse_args()
    run_all_benchmarks(args.experiment_name)
