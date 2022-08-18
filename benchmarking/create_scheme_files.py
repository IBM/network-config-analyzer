from benchmarking.benchmarking_utils import Benchmark, iter_benchmarks, get_scheme_file_path


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


def create_scheme_files():
    for benchmark in iter_benchmarks():
        scheme_file = get_scheme_file_path(benchmark)
        if not scheme_file.exists():
            scheme_file_text = get_scheme_file_text(benchmark)
            scheme_file.write_text(scheme_file_text)


if __name__ == "__main__":
    create_scheme_files()
