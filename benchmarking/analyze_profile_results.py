from operator import itemgetter
from pathlib import Path
from pstats import Stats, FunctionProfile
from typing import Optional

from benchmarking.utils import Benchmark, BenchmarkProcedure, get_benchmark_result_file


def _is_local_function(func_profile: FunctionProfile) -> bool:
    function_path = Path(func_profile.file_name)
    repo_name = 'network-config-analyzer'
    source_dir_name = 'network-config-analyzer'
    for parent in function_path.parents[:-1]:
        if parent.name == source_dir_name and parent.parent.name == repo_name:
            return True
    return False


def _get_path_relative_to_source_dir(func_stats: FunctionProfile) -> Optional[str]:
    function_path = Path(func_stats.file_name)
    source_dir_name = 'network-config-analyzer'
    for parent in function_path.parents:
        if parent.name == source_dir_name:
            return str(function_path.relative_to(parent))
    return None


def get_function_profiles(experiment_name: str, benchmark_list: list[Benchmark]) -> list[dict]:
    """Returns a list of function descriptors, after filtering the python library functions
     and sorting by cumulative time and name
    """
    profile_results_paths = [str(get_benchmark_result_file(benchmark, experiment_name, BenchmarkProcedure.PROFILE))
                             for benchmark in benchmark_list]
    profile_stats = Stats(*profile_results_paths)

    stats_profile = profile_stats.get_stats_profile()
    total_time = stats_profile.total_tt
    func_profiles = stats_profile.func_profiles

    func_profiles = {func_name: func_profile for func_name, func_profile in func_profiles.items()
                     if _is_local_function(func_profile)}

    result = []
    for func_name, func_profile in func_profiles.items():
        func_profile: FunctionProfile
        result.append({
            'func_name': func_name,
            'file': _get_path_relative_to_source_dir(func_profile),
            'line': func_profile.line_number,
            'cumtime': func_profile.cumtime,
            'tottime': func_profile.tottime,
            'n_calls': func_profile.ncalls,
            'percall_cumtime': func_profile.percall_cumtime,
            'percall_tottime': func_profile.percall_tottime,
            'percent_cumtime': (func_profile.cumtime / total_time) * 100,
            'percent_tottime': (func_profile.tottime / total_time) * 100,
        })

        result.sort(key=itemgetter('func_name'))
        result.sort(key=itemgetter('cumtime'), reverse=True)

    return result
