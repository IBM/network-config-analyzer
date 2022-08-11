import sys
import timeit
from cProfile import Profile
from pathlib import Path
from pstats import Stats, FunctionProfile
from types import FrameType
from typing import Any, Type

from CanonicalIntervalSet import CanonicalIntervalSet
from nca import nca_main


def get_scheme_file_text(benchmark_name: str, query: str) -> str:
    if query not in ['connectivity', 'sanity']:
        raise NotImplementedError()

    query_to_scheme_query = {'connectivity': 'connectivityMap', 'sanity': 'sanity'}
    scheme_file_text = f"""
namespaceList: {benchmark_name}
podList: {benchmark_name}
networkConfigList:
  - name: network
    networkPolicyList:
      - {benchmark_name}
queries:
  - name: {query}
    {query_to_scheme_query[query]}:
      - network
"""
    return scheme_file_text


def get_profile_results_path(benchmark_name: str, query: str) -> Path:
    profile_results_dir = Path(f'../profile_results/{benchmark_name}').resolve()
    profile_results_file = profile_results_dir / f'{query}.profile'
    return profile_results_file


def load_profile_results(benchmark_name: str, query: str) -> Stats:
    profile_results_file = get_profile_results_path(benchmark_name, query)
    return Stats(str(profile_results_file))


def save_profile_results(benchmark_name: str, query: str, profile_stats: Stats):
    profile_results_file = get_profile_results_path(benchmark_name, query)

    if not profile_results_file.parent.exists():
        profile_results_file.parent.mkdir()

    profile_stats.dump_stats(profile_results_file)


# TODO:
#   - change this class so it can take any method / function
class FunctionTracker:
    def __init__(self, func_name: str, to_track: list[str], belongs_to_class: Type = None, source_file: str = None):
        """TODO: write docs

        :param func_name: the name of the function to track
        :param to_track: name of stats to track and a callback that calculates them from the locals()
        :param belongs_to_class: if there are different methods with the same name, this will be used in order to
            select the correct function
        :param source_file: if there are different functions with the same name, this will be used to determine the
            correct one
        """
        # TODO: implement
        # TODO: this class will not activate the `settrace`, this is only a single hook. the `settrace` will use a
        #  function that calls a list of FunctionTracker
        pass


class IntervalSizeContainedInHook:
    def __init__(self):
        self.record = {'n_intervals_self': [],
                       'n_intervals_other': []}
        sys.settrace(self.hook)

    def hook(self, frame: FrameType, event: str, arg: Any):
        if frame.f_code.co_name == 'contained_in':
            called_self = frame.f_locals['self']
            if isinstance(called_self, CanonicalIntervalSet):
                called_other: CanonicalIntervalSet = frame.f_locals['other']
                self.record['n_intervals_self'].append(len(called_self))
                self.record['n_intervals_other'].append(len(called_other))


def run_benchmark(benchmark_name: str, query: str, mode: str) -> dict:
    """Runs a specific benchmark with a specific query"""
    # TODO: maybe enable a list of modes?
    scheme_file = Path('../benchmarks/scheme.yaml').resolve()
    scheme_file_text = get_scheme_file_text(benchmark_name, query)
    scheme_file.write_text(scheme_file_text)

    argv = [
        '--scheme',
        str(scheme_file)
    ]
    result = {}
    if mode == 'timing':
        # with open(os.devnull, 'w') as f, redirect_stdout(f), redirect_stderr(f):
        runtime = timeit.repeat(lambda: nca_main(argv), repeat=5, number=1)
        result['minimum_runtime'] = min(runtime)

    elif mode == 'profile':
        with Profile() as profiler:
            nca_main(argv)
        profile_stats = Stats(profiler)
        save_profile_results(benchmark_name, query, profile_stats)
        result['profile_stats'] = profile_stats

    elif mode == 'audit':
        x = IntervalSizeContainedInHook()
        nca_main(argv)
        print(x.record)

    else:
        raise NotImplementedError

    scheme_file.unlink()

    return result


def run_all_benchmarks():
    queries = ['sanity', 'connectivity']
    benchmarks = ['dra']
    # mode = 'timing'
    # mode = 'profile'
    mode = 'audit'
    for benchmark in benchmarks:
        for query in queries:
            result = run_benchmark(benchmark, query, mode)
            print(f'benchmark={benchmark}, query={query}, result={result}')


def get_source_dir() -> Path:
    return Path('../network-config-analyzer').resolve()


def filter_local_functions(profile_stats: Stats) -> dict[str, FunctionProfile]:
    per_function_stats = profile_stats.get_stats_profile().func_profiles
    source_dir = str(get_source_dir())
    filtered_func_stats = {func_name: func_stats for func_name, func_stats in per_function_stats.items()
                           if func_stats.file_name.startswith(source_dir)}
    return filtered_func_stats


def func_stats_to_str(func_name: str, func_stats: FunctionProfile) -> str:
    func_path = Path(func_stats.file_name)
    short_func_path = str(func_path.relative_to(get_source_dir()))
    return f'ncalls={func_stats.ncalls}, ctime={func_stats.cumtime}, percall_ctime={func_stats.percall_cumtime}, ' \
           f'ttime={func_stats.tottime}, percall_ttime={func_stats.percall_tottime}, ' \
           f'function={func_name}, file={short_func_path}, line={func_stats.line_number}'


def analyze_profile_stats(profile_stats: Stats) -> dict:
    # TODO: implement
    # profiler_stats.sort_stats()
    # profiler_stats.dump_stats()
    # profiler_stats.strip_dirs()
    # profiler_stats.add()
    # profiler_stats.get_top_level_stats()
    func_stats_dict = filter_local_functions(profile_stats)

    attribute = 'cumtime'
    sorted_func_stats = sorted(
        func_stats_dict.items(),
        key=lambda item: getattr(item[1], attribute),
        reverse=True
    )
    # TODO: consider printing it into some kind of a table so it will be easier to examine
    for func_name, func_stats in sorted_func_stats:
        print(func_stats_to_str(func_name, func_stats))

    return {}


if __name__ == "__main__":
    run_all_benchmarks()

    # profile_stats = load_profile_results('dra', 'sanity')
    # analyze_profile_stats(profile_stats)
