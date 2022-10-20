from dataclasses import dataclass
from typing import Union

from nca.CoreDS.CanonicalHyperCubeSet import CanonicalHyperCubeSet
from nca.CoreDS.CanonicalIntervalSet import CanonicalIntervalSet
from nca.CoreDS.DimensionsManager import DimensionsManager
from nca.CoreDS.MethodSet import MethodSet
from nca.CoreDS.MinDFA import MinDFA


@dataclass
class ConnectionAttributes:
    """If a certain attribute is None, it means that all
    values are allowed."""
    peers: list[Union[tuple[int, int], int]] = None
    src_ports: list[Union[tuple[int, int], int]] = None
    negate_src_ports: bool = False
    dst_ports: list[Union[tuple[int, int], int]] = None
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

        self.convert_integer_dim('peers', active_dims, cube)
        self.convert_integer_dim('src_ports', active_dims, cube)
        self.convert_integer_dim('dst_ports', active_dims, cube)

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

    def convert_integer_dim(self, attr_name: str, active_dims: list, cube: list):
        attr_value = getattr(self, attr_name)

        negate_attr_name = 'negate_' + attr_name
        negate = False
        if hasattr(self, negate_attr_name):
            negate = getattr(self, negate_attr_name)

        if attr_value is not None:
            s = CanonicalIntervalSet()
            for value in attr_value:
                if isinstance(value, tuple):
                    start, end = value
                    s |= CanonicalIntervalSet.get_interval_set(start, end)
                elif isinstance(value, int):
                    s |= CanonicalIntervalSet.get_interval_set(value, value)
                else:
                    raise RuntimeError

            if negate:
                domain = DimensionsManager().get_dimension_domain_by_name(attr_name)
                s = domain - s
            active_dims.append(attr_name)
            cube.append(s)


def main():
    all_dims = ['peers', 'src_ports', 'dst_ports', 'methods', 'paths', 'hosts']
    s = CanonicalHyperCubeSet(all_dims)

    policy_attr = ConnectionAttributes(
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
