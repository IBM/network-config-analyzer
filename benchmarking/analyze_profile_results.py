from pathlib import Path
from pprint import pprint
from pstats import Stats, FunctionProfile, SortKey

from benchmarking.benchmarking_utils import Benchmark, iter_all_benchmarks
from benchmarking.profiling import load_profile_results, get_profile_results_path


def get_source_dir() -> Path:
    return Path('../network-config-analyzer').resolve()


def filter_local_functions(profile_stats: Stats) -> dict[str, FunctionProfile]:
    per_function_stats = profile_stats.get_stats_profile().func_profiles
    source_dir = str(get_source_dir())
    filtered_func_stats = {func_name: func_stats for func_name, func_stats in per_function_stats.items()
                           if func_stats.file_name.startswith(source_dir)}
    return filtered_func_stats


def filter_non_interesting_funcs(func_stats_dict: dict[str, FunctionProfile]) -> dict[str, FunctionProfile]:
    # TODO: it might be possible to target those by detecting which functions are called only once
    funcs_to_filter = [
        'nca_main',
        'run_args',
        'run_scheme',
        'run_queries',
        'run_query',
        '_execute_one_config_query',
        '_run_query_for_each_config',
    ]
    return {key: value for key, value in func_stats_dict.items() if key not in funcs_to_filter}


def get_short_func_path(func_stats: FunctionProfile) -> str:
    func_path = Path(func_stats.file_name)
    short_func_path = str(func_path.relative_to(get_source_dir()))
    return short_func_path


def get_top_n_cumtime_funcs(n: int, benchmark: Benchmark = None) -> list[dict]:
    """Returns a list of the top n functions that have the largest cumulative time,
    after filtering the python library functions, and not interesting functions
    """
    if benchmark is None:
        profile_results_paths = [str(get_profile_results_path(benchmark)) for benchmark in iter_all_benchmarks()]
        profile_stats = Stats(*profile_results_paths)
    else:
        profile_stats = load_profile_results(benchmark)

    func_stats_dict = filter_local_functions(profile_stats)
    func_stats_dict = filter_non_interesting_funcs(func_stats_dict)

    attribute = 'cumtime'
    func_stats_list = list(sorted(
        func_stats_dict.items(),
        key=lambda item: getattr(item[1], attribute),
        reverse=True
    ))

    result = []
    for i, (func_name, func_stats) in enumerate(func_stats_list[:n], start=1):
        func_stats: FunctionProfile
        result.append({
            'function': func_name,
            'file': get_short_func_path(func_stats),
            'line': func_stats.line_number,
            'cumulative_time': func_stats.cumtime,
            'n_calls': func_stats.ncalls
        })

    return result


def get_accumulated_stats():
    profile_results_paths = [str(get_profile_results_path(benchmark)) for benchmark in iter_all_benchmarks()]
    accumulated_stats = Stats(profile_results_paths)
    accumulated_stats = filter_local_functions(accumulated_stats)
    attribute = 'cumtime'
    func_stats_list = list(sorted(
        accumulated_stats.items(),
        key=lambda item: getattr(item[1], attribute),
        reverse=True
    ))
    pprint(func_stats_list[:30])


if __name__ == "__main__":
    get_accumulated_stats()
