import timeit
from cProfile import Profile
from pathlib import Path
from pstats import Stats

from benchmark_code.profile_utils import save_profile_results

from benchmark_code.auditing import IntervalSizeContainedInHook
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


def get_source_dir() -> Path:
    return Path('../network-config-analyzer').resolve()


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


if __name__ == "__main__":
    run_all_benchmarks()

    # profile_stats = load_profile_results('dra', 'sanity')
    # analyze_profile_stats(profile_stats)
