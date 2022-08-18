from benchmarking.create_report import create_report
from benchmarking.profiling import profile_all_benchmarks
from benchmarking.timing import time_all_benchmarks
from benchmarking.auditing import audit_all_benchmarks


def run_all_benchmarks():
    time_all_benchmarks()
    profile_all_benchmarks()
    audit_all_benchmarks()
    create_report()


if __name__ == '__main__':
    run_all_benchmarks()
