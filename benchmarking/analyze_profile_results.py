from operator import itemgetter
from pathlib import Path
from pstats import Stats, FunctionProfile

from benchmarking.benchmarking_utils import Benchmark, iter_benchmarks, get_repo_root_dir
from benchmarking.profiling import load_profile_results, get_profile_results_path


def get_source_dir() -> Path:
    return get_repo_root_dir() / 'network-config-analyzer'


def is_local_function(func_profile: FunctionProfile) -> bool:
    source_dir = str(get_source_dir())
    return func_profile.file_name.startswith(source_dir)


def is_called_more_than(func_profile: FunctionProfile, times: int) -> bool:
    try:
        return int(func_profile.ncalls) > times
    except ValueError:
        return True


def get_short_func_path(func_stats: FunctionProfile) -> str:
    func_path = Path(func_stats.file_name)
    short_func_path = str(func_path.relative_to(get_source_dir()))
    return short_func_path


def get_function_profiles(experiment_name: str, benchmark: Benchmark = None) -> list[dict]:
    """Returns a list of the top n functions that have the largest cumulative time,
    after filtering the python library functions, and not interesting functions
    """
    if benchmark is None:
        profile_results_paths = [str(get_profile_results_path(benchmark, experiment_name))
                                 for benchmark in iter_benchmarks()]
        n_runs = len(profile_results_paths)
        profile_stats = Stats(*profile_results_paths)
    else:
        n_runs = 1
        profile_stats = load_profile_results(benchmark, experiment_name)

    stats_profile = profile_stats.get_stats_profile()
    total_time = stats_profile.total_tt
    func_profiles = stats_profile.func_profiles

    # filter
    func_profiles = {func_name: func_profile for func_name, func_profile in func_profiles.items()
                     if is_local_function(func_profile)}
    # TODO: I think that it is better not to remove those, since it might give us useful information
    # and is_called_more_than(func_profile, n_runs)}

    # map
    result = []
    for func_name, func_profile in func_profiles.items():
        func_profile: FunctionProfile
        result.append({
            'func_name': func_name,
            'file': get_short_func_path(func_profile),
            'line': func_profile.line_number,
            'cumtime': func_profile.cumtime,
            'tottime': func_profile.tottime,
            'n_calls': func_profile.ncalls,
            'percall_cumtime': func_profile.percall_cumtime,
            'percall_tottime': func_profile.percall_tottime,
            'percent_cumtime': (func_profile.cumtime / total_time) * 100,
            'percent_tottime': (func_profile.tottime / total_time) * 100,
        })

        # sort
        result.sort(key=itemgetter('func_name'))
        result.sort(key=itemgetter('cumtime'), reverse=True)

    return result
