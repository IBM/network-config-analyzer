from collections.abc import Iterable
from pathlib import Path

from benchmarking.benchmarking_utils import get_benchmarks_dir

def get_queries() -> list[str]:
    return ['sanity', 'connectivity']


def get_scheme_file_path(benchmark_dir: Path, query: str) -> Path:
    return get_benchmarks_dir() / f'{benchmark_dir.name}-{query}-scheme.yaml'


def get_scheme_file_text(benchmark_dir: Path, query: str) -> str:
    if query not in ['connectivity', 'sanity']:
        raise NotImplementedError()

    query_to_scheme_query = {'connectivity': 'connectivityMap', 'sanity': 'sanity'}
    scheme_file_text = f"""
namespaceList: {benchmark_dir.name}
podList: {benchmark_dir.name}
networkConfigList:
  - name: network
    networkPolicyList:
      - {benchmark_dir.name}
queries:
  - name: {query}
    {query_to_scheme_query[query]}:
      - network
"""
    return scheme_file_text


def iter_benchmark_dirs() -> Iterable[Path]:
    return filter(lambda file: file.is_dir(), get_benchmarks_dir().iterdir())


def create_scheme_files():
    # TODO: test this
    for benchmark_dir in iter_benchmark_dirs():
        for query in get_queries():
            scheme_file = get_scheme_file_path(benchmark_dir, query)
            if not scheme_file.exists():
                scheme_file_text = get_scheme_file_text(benchmark_dir, query)
                scheme_file.write_text(scheme_file_text)


if __name__ == "__main__":
    create_scheme_files()


