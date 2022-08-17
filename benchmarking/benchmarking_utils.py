from itertools import product
from pathlib import Path

from nca import nca_main


class Benchmark:
    def __init__(self, benchmark_dir: Path, query: str):
        self.path = benchmark_dir
        self.query = query
        self.name = benchmark_dir.name
        self._argv = [
            '--scheme',
            str(get_scheme_file_path(self))
        ]

    def run(self):
        nca_main(self._argv)

    def __str__(self):
        return f'{self.name}-{self.query}'


def get_benchmarks_dir() -> Path:
    return Path('../benchmarks').resolve()


def get_benchmark_results_dir() -> Path:
    results_dir = Path('../benchmark_results').resolve()
    results_dir.mkdir(parents=True, exist_ok=True)
    return results_dir


def get_benchmark_result_path(benchmark: Benchmark, label: str, suffix: str) -> Path:
    results_dir = get_benchmark_results_dir()
    return results_dir / f'{str(benchmark)}-{label}.{suffix}'


def get_scheme_file_text(benchmark: Benchmark) -> str:
    if benchmark.query not in ['connectivity', 'sanity']:
        raise NotImplementedError()

    query_to_scheme_query = {'connectivity': 'connectivityMap', 'sanity': 'sanity'}
    scheme_file_text = f"""
namespaceList: {benchmark.name}
podList: {benchmark.name}
networkConfigList:
  - name: network
    networkPolicyList:
      - {benchmark.name}
queries:
  - name: {benchmark.query}
    {query_to_scheme_query[benchmark.query]}:
      - network
"""
    return scheme_file_text


def get_all_benchmark_dirs() -> list[Path]:
    benchmarks_dir = get_benchmarks_dir()
    return [path for path in benchmarks_dir.iterdir() if path.is_dir()]


def get_all_queries() -> list[str]:
    return ['sanity', 'connectivity']


def get_scheme_file_path(benchmark: Benchmark) -> Path:
    return get_benchmarks_dir() / f'{benchmark}-scheme.yaml'


def write_all_scheme_files():
    for benchmark in iter_all_benchmarks():
        scheme_file = get_scheme_file_path(benchmark)
        scheme_file_text = get_scheme_file_text(benchmark)
        scheme_file.write_text(scheme_file_text)


def iter_all_benchmarks():
    # TODO: add the tests as benchmarks to the iterator, I also want to create a report for that
    benchmark_dirs = get_all_benchmark_dirs()
    queries = get_all_queries()
    for benchmark_dir, query in product(benchmark_dirs, queries):
        # TODO: currently, I skip this benchmark. I need to work on it to make it run
        if benchmark_dir.name == 'FromJakeKitchener':
            continue
        yield Benchmark(benchmark_dir, query)


if __name__ == "__main__":
    write_all_scheme_files()
