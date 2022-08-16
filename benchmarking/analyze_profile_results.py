from pathlib import Path
from pstats import Stats, FunctionProfile

from benchmarking.benchmarking_utils import Benchmark
from benchmarking.profiling import load_profile_results


def get_source_dir() -> Path:
    return Path('../network-config-analyzer').resolve()


def filter_local_functions(profile_stats: Stats) -> dict[str, FunctionProfile]:
    per_function_stats = profile_stats.get_stats_profile().func_profiles
    source_dir = str(get_source_dir())
    filtered_func_stats = {func_name: func_stats for func_name, func_stats in per_function_stats.items()
                           if func_stats.file_name.startswith(source_dir)}
    return filtered_func_stats


def get_func_str_descriptor(func_name: str, func_stats: FunctionProfile) -> str:
    func_path = Path(func_stats.file_name)
    short_func_path = str(func_path.relative_to(get_source_dir()))
    return f'file={short_func_path}:name={func_name}:line={func_stats.line_number}'


def get_top_n_cumtime_funcs(benchmark: Benchmark, n: int) -> dict:
    """Returns a list of the top n functions that have the largest cumulative time,
    after filtering the python library functions

    :param benchmark:
    :param n: number of entries to return
    :return: a dictionary of size 2*n with entries {'top_{n}_func': func_name, 'top_{n}_cumtime': cumtime}
    """
    profile_stats = load_profile_results(benchmark)
    func_stats_dict = filter_local_functions(profile_stats)

    attribute = 'cumtime'
    func_stats_list = list(sorted(
        func_stats_dict.items(),
        key=lambda item: getattr(item[1], attribute),
        reverse=True
    ))

    result = {}
    for i, (func_name, func_stats) in enumerate(func_stats_list[:n], start=1):
        result[f'top_{i}_func'] = get_func_str_descriptor(func_name, func_stats)
        result[f'top_{i}_{attribute}'] = getattr(func_stats, attribute)

    return result
