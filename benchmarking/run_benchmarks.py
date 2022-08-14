import timeit
from cProfile import Profile
from pathlib import Path
from pstats import Stats

from benchmarking.benchmarking_utils import get_scheme_file_text
from benchmarking.profiling import save_profile_results

from nca import nca_main


# TODO: delete this file
def run_benchmark_to_delete(benchmark_name: str, query: str, mode: str) -> dict:
    """Runs a specific benchmark with a specific query"""
    # TODO: delete this after I finish,
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

    scheme_file.unlink()

    return result
