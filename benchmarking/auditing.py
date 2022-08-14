import sys
from abc import ABC, abstractmethod
from collections import defaultdict
from itertools import product
from types import FrameType
from typing import Any

from CanonicalIntervalSet import CanonicalIntervalSet
from benchmarking.benchmarking_utils import get_all_benchmark_dirs, get_all_queries, Benchmark


class Inspector(ABC):
    # TODO: maybe consider instead of an abstract class to be a class that
    #   takes the necessary functions in the constructor
    def __init__(self):
        self._records = defaultdict(list)

    def reset(self):
        self._records = defaultdict(list)

    def hook(self, frame: FrameType, event: str, arg: Any):
        if self._select_event(frame, event, arg):
            record = self._process_event(frame, event, arg)
            for key, value in record.items():
                self._records[key].append(value)

    def get_stats(self) -> dict:
        return self._process_records(self._records)

    @staticmethod
    @abstractmethod
    def _select_event(frame: FrameType, event: str, arg: Any) -> bool:
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def _process_event(frame: FrameType, event: str, arg: Any) -> dict:
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def _process_records(records: dict[list]) -> dict:
        raise NotImplementedError


class ContainedInInspector(Inspector):
    @staticmethod
    def _select_event(frame: FrameType, event: str, arg: Any) -> bool:
        return frame.f_code.co_name == CanonicalIntervalSet.contained_in.__name__ and \
               'self' in frame.f_locals and \
               isinstance(frame.f_locals['self'], CanonicalIntervalSet)

    @staticmethod
    def _process_event(frame: FrameType, event: str, arg: Any) -> dict:
        return {
            'n_intervals': (
                len(frame.f_locals['self']),
                len(frame.f_locals['other'])
            )
        }

    @staticmethod
    def _process_records(records: dict[list]) -> dict:
        return records


def audit_all_benchmarks():
    benchmark_dirs = get_all_benchmark_dirs()
    queries = get_all_queries()

    # TODO: add more hooks
    inspectors = [
        ContainedInInspector()
    ]
    for inspector in inspectors:
        sys.settrace(inspector.hook)

    for benchmark_dir, query in product(benchmark_dirs, queries):
        benchmark = Benchmark(benchmark_dir, query)
        for inspector in inspectors:
            inspector.reset()
        benchmark.run()
        stats = [inspector.get_stats() for inspector in inspectors]
        # TODO: do something else with the stats
        print(stats)


if __name__ == "__main__":
    audit_all_benchmarks()
