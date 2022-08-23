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
    scheme_file = r'C:\Users\018130756\repos\network-config-analyzer\benchmarks\dra-sanity-scheme.yaml'
    run_scheme(scheme_file)


if __name__ == "__main__":
    call_scheme()
    # analyze_input_parameters()
