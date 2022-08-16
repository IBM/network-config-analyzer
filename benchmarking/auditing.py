import inspect
import json
import sys
from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from types import FrameType
from typing import Any

from CanonicalIntervalSet import CanonicalIntervalSet
from NetworkConfig import NetworkConfig
from SchemeRunner import SchemeRunner
from benchmarking.benchmarking_utils import iter_all_benchmarks, Benchmark, get_benchmark_result_path


class FrameFuncMatcher:
    def __init__(self, func: Callable):
        self._filename = inspect.getfile(func)
        _, self._lineno = inspect.getsourcelines(func)

    def frame_matches_func(self, frame: FrameType) -> bool:
        return frame.f_code.co_filename == self._filename and \
               frame.f_code.co_firstlineno == self._lineno


class FuncInspector(ABC):
    # TODO: maybe consider instead of an abstract class to be a class that
    #   takes the necessary functions in the constructor
    def __init__(self, func: Callable):
        self._records = defaultdict(list)
        self._func_matcher = FrameFuncMatcher(func)

    def reset(self):
        self._records = defaultdict(list)

    def hook(self, frame: FrameType, event: str, arg: Any):
        if self._func_matcher.frame_matches_func(frame):
            record = self._process_event(frame)
            for key, value in record.items():
                self._records[key].append(value)

    def get_stats(self) -> dict:
        return self._process_records(self._records)

    @staticmethod
    @abstractmethod
    def _process_event(frame: FrameType) -> dict:
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def _process_records(records: dict[list]) -> dict:
        raise NotImplementedError


class InspectorRunner:
    def __init__(self, inspectors: list[FuncInspector]):
        self.inspectors = inspectors

    def run_all_inspectors(self, frame: FrameType, event: str, arg: Any) -> None:
        for inspector in self.inspectors:
            inspector.hook(frame, event, arg)

    def reset_all_inspectors(self):
        for inspector in self.inspectors:
            inspector.reset()

    def get_stats(self):
        stats = {}
        for inspector in self.inspectors:
            stats.update(inspector.get_stats())
        return stats


class IntervalContainedIn(FuncInspector):

    def __init__(self):
        super(IntervalContainedIn, self).__init__(CanonicalIntervalSet.contained_in)

    @staticmethod
    def _process_event(frame: FrameType) -> dict:
        return {
            'n_intervals': [
                len(frame.f_locals['self']),
                len(frame.f_locals['other'])
            ]
        }

    @staticmethod
    def _process_records(records: dict[list]) -> dict:
        return records


class RunQueryInspector(FuncInspector):

    def __init__(self):
        super(RunQueryInspector, self).__init__(SchemeRunner.run_queries)

    @staticmethod
    def _process_event(frame: FrameType) -> dict:
        self: SchemeRunner = frame.f_locals['self']
        network_config: NetworkConfig = self.network_configs['network']
        return {
            'n_peers': len(network_config.peer_container.peer_set),
            'n_namespaces': len(network_config.peer_container.namespaces),
            'n_network_policies': len(network_config.policies),
            'policy_type': str(network_config.type)
        }

    @staticmethod
    def _process_records(records: dict[list]) -> dict:
        assert all(len(value_list) == 1 for value_list in records.values())
        return {key: value[0] for key, value in records.items()}


def get_auditing_results_path(benchmark: Benchmark) -> Path:
    return get_benchmark_result_path(benchmark, 'auditing', 'json')


def audit_all_benchmarks():
    # TODO: add more hooks
    inspectors = [
        # IntervalContainedIn(),
        RunQueryInspector()
    ]
    inspectors_runner = InspectorRunner(inspectors)
    # TODO: comment settrace for debugging
    sys.settrace(inspectors_runner.run_all_inspectors)

    for benchmark in iter_all_benchmarks():
        # TODO: refactor to a nicer way of not running the same benchmark twice
        result_path = get_auditing_results_path(benchmark)
        if result_path.exists():
            continue

        inspectors_runner.reset_all_inspectors()
        benchmark.run()

        stats = inspectors_runner.get_stats()
        with result_path.open('w') as f:
            json.dump(stats, f, indent=4)


if __name__ == "__main__":
    audit_all_benchmarks()
