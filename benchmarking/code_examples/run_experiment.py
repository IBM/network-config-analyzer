import json
from pathlib import Path
from statistics import mean, quantiles

from ConnectionSet import ConnectionSet
from ConnectivityGraph import ConnectivityGraph
from NetworkConfig import NetworkConfig
from OutputConfiguration import OutputConfiguration
from Peer import PeerSet, Peer
from nca import nca_main


def run_scheme(scheme_abs_path: str) -> int:
    argv = [
        '--scheme',
        scheme_abs_path
    ]
    return nca_main(argv)


def call_scheme():
    scheme_file = r'C:\Users\018130756\repos\network-config-analyzer\benchmarks\SCC_test_calico_resources-connectivity-scheme.yaml'
    run_scheme(scheme_file)


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


if __name__ == "__main__":
    call_scheme()
    # analyze_input_parameters()
