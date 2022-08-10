import json
import timeit
from pathlib import Path
from statistics import mean, quantiles

from ConnectivityGraph import ConnectivityGraph
from Peer import PeerSet, Peer
from OutputConfiguration import OutputConfiguration
from NetworkConfig import NetworkConfig
from ConnectionSet import ConnectionSet
from nca import nca_main


def run_scheme(scheme_abs_path: str):
    argv = [
        '--scheme',
        scheme_abs_path
    ]
    retval = nca_main(argv)


def example_1():
    peer1 = Peer(name="1", namespace="default")
    peer1.set_label(key="key", value="1")

    peer2 = Peer(name="2", namespace="default")
    peer2.set_label(key="key", value="2")

    all_peers = PeerSet({peer1, peer2})

    # TODO: are those the labels values that are allowed, or the labels keys that are allowed?
    #   I assume that those are the keys
    allowed_labels = {"key"}
    output_config = OutputConfiguration()
    config_type = NetworkConfig.ConfigType.Unknown

    connectivity_graph = ConnectivityGraph(
        all_peers=all_peers,  # PeerSet
        allowed_labels=allowed_labels,  # set of strings
        output_config=output_config,  # OutputConfiguration
        config_type=config_type,  # TODO: missing from the docs
    )
    dot_format_str1 = connectivity_graph.get_connectivity_dot_format_str()
    print(dot_format_str1)

    connection_set = ConnectionSet()
    connection_set.add_all_connections()

    connectivity_graph.add_edge(
        source_peer=peer1,
        dest_peer=peer2,
        connections=connection_set
    )

    dot_format_str2 = connectivity_graph.get_connectivity_dot_format_str()
    print(dot_format_str2)

    connectivity_graph.add_edge(
        source_peer=peer2,
        dest_peer=peer1,
        connections=connection_set
    )

    dot_format_str3 = connectivity_graph.get_connectivity_dot_format_str()
    print(dot_format_str3)

    x = connectivity_graph.get_minimized_firewall_rules()
    print(x)


def call_scheme():
    scheme_file = r'C:\Users\018130756\repos\network-config-analyzer\tests\k8s_testcases\example_policies\tests' \
                  r'-different-topologies\copy-semanticDiff-IpBlocks-different-topologies-scheme.yaml '
    run_scheme(scheme_file)


def analyze_input_parameters():
    logs_file = Path('CanonicalIntervalSetLogs.json')
    with logs_file.open('r') as f:
        logs = json.load(f)

    size_1_list = [record["num_intervals_1"] for record in logs]
    size_2_list = [record["num_intervals_2"] for record in logs]
    size_list = size_1_list + size_2_list
    print(f'max size: {max(size_list)}')
    print(f'avg size: {mean(size_list)}')
    print(f'quantiles: {quantiles(size_list)}')


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


def run_benchmark(benchmark_name: str, query: str) -> dict:
    """Runs a specific benchmark with a specific query"""
    scheme_file = Path('../benchmarks/scheme.yaml').resolve()
    scheme_file_text = get_scheme_file_text(benchmark_name, query)
    scheme_file.write_text(scheme_file_text)
    # with scheme_file.open('w') as f:
    #     f.write(scheme_file_text)

    argv = [
        '--scheme',
        str(scheme_file)
    ]
    runtime = timeit.repeat(lambda: nca_main(argv), repeat=5, number=1)
    # retval = nca_main(argv)

    scheme_file.unlink()

    # TODO: give a more detailed result
    return {'runtime': runtime}


def run_sanity_benchmark():
    scheme_file = Path('../benchmark/dra/sanity-scheme.yaml').resolve()
    scheme_file_str = str(scheme_file)
    argv = [
        '--scheme',
        scheme_file_str
    ]
    retval = nca_main(argv)


def run_connectivity_benchmark():
    scheme_file = Path('../benchmark/dra/connectivity-scheme.yaml').resolve()
    scheme_file_str = str(scheme_file)
    argv = [
        '--scheme',
        scheme_file_str
    ]
    retval = nca_main(argv)


if __name__ == "__main__":
    # call_scheme()
    # analyze_input_parameters()

    # Benchmarking
    # TODO: refactor - move code to somewhere else
    queries = ['sanity', 'connectivity']
    benchmarks = ['dra']
    for benchmark in benchmarks:
        for query in queries:
            result = run_benchmark(benchmark, query)
            print(f'benchmark={benchmark}, query={query}, result={result}')
