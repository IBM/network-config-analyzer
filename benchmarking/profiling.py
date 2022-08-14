from cProfile import Profile
from pathlib import Path
from pstats import Stats, FunctionProfile

from benchmarking.benchmarking_utils import iter_all_benchmarks


def load_profile_results(benchmark_name: str, query: str) -> Stats:
    profile_results_file = get_profile_results_path(benchmark_name, query)
    return Stats(str(profile_results_file))


def get_profile_results_path(benchmark_name: str, query: str) -> Path:
    profile_results_dir = Path(f'../profile_results/{benchmark_name}').resolve()
    profile_results_file = profile_results_dir / f'{query}.profile'
    return profile_results_file


def save_profile_results(benchmark_name: str, query: str, profile_stats: Stats):
    profile_results_file = get_profile_results_path(benchmark_name, query)

    if not profile_results_file.parent.exists():
        profile_results_file.parent.mkdir()

    profile_stats.dump_stats(profile_results_file)


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


def get_source_dir() -> Path:
    return Path('../network-config-analyzer').resolve()


def profile_all_benchmarks():
    for benchmark in iter_all_benchmarks():
        with Profile() as profiler:
            benchmark.run()
        profile_stats = Stats(profiler)
        # TODO: do something else with the stats
        save_profile_results(benchmark.name, benchmark.query, profile_stats)
        profile_stats.print_stats()


if __name__ == "__main__":
    profile_all_benchmarks()
