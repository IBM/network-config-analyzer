from itertools import product
from pathlib import Path

from nca import nca_main


def get_benchmarks_dir() -> Path:
    return Path('../benchmarks').resolve()


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


def get_all_benchmark_dirs() -> list[Path]:
    benchmarks_dir = get_benchmarks_dir()
    return [path for path in benchmarks_dir.iterdir() if path.is_dir()]


def get_all_queries() -> list[str]:
    return ['sanity', 'connectivity']


class Benchmark:
    def __init__(self, benchmark_dir: Path, query: str):
        self.path = benchmark_dir
        self.query = query
        self.name = benchmark_dir.name

        self._scheme_file = get_benchmarks_dir() / f'{self.name}-{query}-scheme.yaml'
        scheme_file_text = get_scheme_file_text(self.name, query)
        self._scheme_file.write_text(scheme_file_text)
        self._argv = [
            '--scheme',
            str(self._scheme_file)
        ]

    def run(self):
        nca_main(self._argv)

    def __del__(self):
        self._scheme_file.unlink()


def iter_all_benchmarks():
    benchmark_dirs = get_all_benchmark_dirs()
    queries = get_all_queries()
    for benchmark_dir, query in product(benchmark_dirs, queries):
        yield Benchmark(benchmark_dir, query)


