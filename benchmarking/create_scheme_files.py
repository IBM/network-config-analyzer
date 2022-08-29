from collections.abc import Iterable
from pathlib import Path

from benchmarking.benchmarking_utils import get_benchmarks_dir


def get_queries() -> list[str]:
    return ['sanity', 'connectivity']


def get_scheme_file_path(benchmark_dir: Path) -> Path:
    return get_benchmarks_dir() / f'{benchmark_dir.name}-scheme.yaml'


def get_scheme_file_text(benchmark_dir: Path) -> str:
    query_to_scheme_query = {'connectivity': 'connectivityMap', 'sanity': 'sanity'}
    scheme_file_text = f"""
namespaceList: {benchmark_dir.name}
podList: {benchmark_dir.name}
networkConfigList:
  - name: network
    networkPolicyList:
      - {benchmark_dir.name}

queries:
"""
    for query_name, query_cmd in query_to_scheme_query.items():
        scheme_file_text += f"""
  - name: {query_name}
    {query_cmd}:
      - network
"""
    return scheme_file_text


def iter_benchmark_dirs() -> Iterable[Path]:
    return filter(lambda file: file.is_dir(), get_benchmarks_dir().iterdir())


def create_scheme_files():
    for benchmark_dir in iter_benchmark_dirs():
        scheme_file = get_scheme_file_path(benchmark_dir)
        if not scheme_file.exists():
            scheme_file_text = get_scheme_file_text(benchmark_dir)
            scheme_file.write_text(scheme_file_text)


if __name__ == "__main__":
    create_scheme_files()


