from dataclasses import dataclass
from enum import Enum, auto

from nca.CoreDS.CanonicalHyperCubeSet import CanonicalHyperCubeSet
from nca.CoreDS.CanonicalIntervalSet import CanonicalIntervalSet
from nca.CoreDS.DimensionsManager import DimensionsManager
from nca.CoreDS.MethodSet import MethodSet
from nca.CoreDS.MinDFA import MinDFA


def run_experiment():
    # TODO: I want to run comparison between
    pass
# TODO: figure out how to make an interesting benchmark here.
# TODO: start by finding the real dimensions and possible values that we might get.
# ports (source / dest):
#   - protocol (TCP, UDP, SCTP)
#   - port numbers (0 - 2 ** 16)
# peers (numbers)
# methods: [PUT, ...]
# paths: [/info*, /data, ...]
# hosts string[]
# There is also notMethods, notPaths, notHosts, notPorts
# https://istio.io/latest/docs/reference/config/security/authorization-policy/#Operation
# TODO: enable deny, allow.


@dataclass
class PolicyAttributes:
    """If a certain attribute is None, it means that all
    values are allowed."""
    peers: list[int] = None
    src_ports: list[tuple[int, int]] = None
    negate_src_ports: bool = False
    dst_ports: list[tuple[int, int]] = None
    negate_dst_ports: bool = False
    methods: list[str] = None
    negate_methods: bool = False
    paths: list[str] = None
    negate_paths = False
    hosts: list[str] = None
    negate_hosts: bool = False

    def to_canonical_cube(self):
        cube = []
        active_dims = []

        if self.peers is not None:
            peers = CanonicalIntervalSet()
            for peer in self.peers:
                peers |= CanonicalIntervalSet.get_interval_set(peer, peer)
            active_dims.append('peers')
            cube.append(peers)

        if self.src_ports is not None:
            ports = CanonicalIntervalSet()
            for start, end in self.src_ports:
                ports |= CanonicalIntervalSet.get_interval_set(start, end)
            if self.negate_src_ports:
                domain = DimensionsManager().get_dimension_domain_by_name('src_ports')
                ports = domain - ports
            active_dims.append('src_ports')
            cube.append(ports)

        if self.dst_ports is not None:
            ports = CanonicalIntervalSet()
            for start, end in self.dst_ports:
                ports |= CanonicalIntervalSet.get_interval_set(start, end)
            if self.negate_dst_ports:
                domain = DimensionsManager().get_dimension_domain_by_name('dst_ports')
                ports = domain - ports
            active_dims.append('dst_ports')
            cube.append(ports)

        if self.methods is not None:
            methods = CanonicalIntervalSet()
            for method in self.methods:
                method_index = MethodSet.all_methods_list.index(method)
                methods = methods | CanonicalIntervalSet.get_interval_set(method_index, method_index)
            if self.negate_methods:
                domain = DimensionsManager().get_dimension_domain_by_name('methods')
                methods = domain - methods
            active_dims.append('methods')
            cube.append(methods)

        if self.paths is not None:
            paths = MinDFA.from_wildcard(self.paths[0])
            for path in self.paths[1:]:
                paths = paths | MinDFA.from_wildcard(path)
            if self.negate_paths:
                domain = DimensionsManager().get_dimension_domain_by_name('paths')
                paths = domain - paths
            active_dims.append('paths')
            cube.append(paths)

        if self.hosts is not None:
            hosts = MinDFA.from_wildcard(self.hosts[0])
            for host in self.hosts[1:]:
                hosts = hosts | MinDFA.from_wildcard(host)
            if self.negate_hosts:
                domain = DimensionsManager().get_dimension_domain_by_name('hosts')
                hosts = domain - hosts
            active_dims.append('hosts')
            cube.append(hosts)

        return cube, active_dims


def main():
    all_dims = ['peers', 'src_ports', 'dst_ports', 'methods', 'paths', 'hosts']
    s = CanonicalHyperCubeSet(all_dims)

    policy_attr = PolicyAttributes(
        peers=[0, 2, 10],
        src_ports=[(0, 10), (20, 500), (1234, 2345)],
        methods=['POST'],
        negate_methods=True,
        paths=['bla/bla/*'],
    )
    cube, active_dims = policy_attr.to_canonical_cube()
    s.add_cube(cube, active_dims)
    print(cube, active_dims)


if __name__ == '__main__':
    main()