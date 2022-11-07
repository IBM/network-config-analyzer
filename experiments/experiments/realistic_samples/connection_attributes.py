from dataclasses import dataclass
from typing import Union, Type

from nca.CoreDS.CanonicalHyperCubeSet import CanonicalHyperCubeSet
from nca.CoreDS.CanonicalIntervalSet import CanonicalIntervalSet
from nca.CoreDS.DimensionsManager import DimensionsManager
from nca.CoreDS.MethodSet import MethodSet
from nca.CoreDS.MinDFA import MinDFA
from z3_sets.z3_integer_set import Z3IntegerSet
from z3_sets.z3_product_set import Z3ProductSet
from z3_sets.z3_simple_string_set import Z3SimpleStringSet


@dataclass
class ConnectionAttributes:
    """If a certain attribute is None, it means that all
    values are allowed."""
    src_ports: list[Union[tuple[int, int], int]] = None
    negate_src_ports: bool = False
    dst_ports: list[Union[tuple[int, int], int]] = None
    negate_dst_ports: bool = False
    methods: list[str] = None
    negate_methods: bool = False
    paths: list[str] = None
    negate_paths: bool = False
    hosts: list[str] = None
    negate_hosts: bool = False

    @staticmethod
    def _cls_to_integer_cls(cls):
        if cls == CanonicalHyperCubeSet:
            return CanonicalIntervalSet
        else:
            return Z3IntegerSet

    @staticmethod
    def _cls_to_str_cls(cls):
        if cls == CanonicalHyperCubeSet:
            return MinDFA
        else:
            return Z3SimpleStringSet

    @staticmethod
    def _get_domain(attr_name: str, cls):
        domain = DimensionsManager().get_dimension_domain_by_name(attr_name)
        if cls == CanonicalHyperCubeSet:
            return domain

        if isinstance(domain, CanonicalIntervalSet):
            interval = domain.interval_set[0]
            domain = Z3IntegerSet.get_interval_set(interval.start, interval.end)
            return domain
        else:   # MinDFA
            return Z3SimpleStringSet.get_universal_set()

    def to_cube(self, cls: Type):
        assert cls in [CanonicalHyperCubeSet, Z3ProductSet]
        cube = []
        active_dims = []

        self._convert_integer_dim('src_ports', active_dims, cube, cls)
        self._convert_integer_dim('dst_ports', active_dims, cube, cls)

        if self.methods is not None:
            integer_cls = self._cls_to_integer_cls(cls)
            methods = integer_cls()
            for method in self.methods:
                method_index = MethodSet.all_methods_list.index(method)
                methods = methods | integer_cls.get_interval_set(method_index, method_index)
            if self.negate_methods:
                domain = self._get_domain('methods', cls)
                methods = domain - methods
            active_dims.append('methods')
            cube.append(methods)

        self._convert_str_dim('paths', active_dims, cube, cls)
        self._convert_str_dim('hosts', active_dims, cube, cls)

        return cube, active_dims

    def _convert_integer_dim(self, attr_name: str, active_dims: list, cube: list, cls):
        attr_value = getattr(self, attr_name)
        negate_attr_name = 'negate_' + attr_name
        negate = False
        if hasattr(self, negate_attr_name):
            negate = getattr(self, negate_attr_name)

        integer_cls = self._cls_to_integer_cls(cls)
        if attr_value is not None:
            s = integer_cls()
            for value in attr_value:
                if isinstance(value, tuple):
                    start, end = value
                    s |= integer_cls.get_interval_set(start, end)
                elif isinstance(value, int):
                    s |= integer_cls.get_interval_set(value, value)
                else:
                    raise RuntimeError
            if negate:
                domain = self._get_domain(attr_name, cls)
                s = domain - s
            active_dims.append(attr_name)
            cube.append(s)

    def _convert_str_dim(self, attr_name: str, active_dims: list, cube: list, cls):
        attr_value = getattr(self, attr_name)
        negate_attr_name = 'negate_' + attr_name
        negate = False
        if hasattr(self, negate_attr_name):
            negate = getattr(self, negate_attr_name)

        str_cls = self._cls_to_str_cls(cls)
        if attr_value is not None:
            s = str_cls.from_wildcard(attr_value[0])
            for v in attr_value[1:]:
                s = s | str_cls.from_wildcard(v)
            if negate:
                domain = self._get_domain(attr_name, cls)
                s = domain - s
            active_dims.append(attr_name)
            cube.append(s)


def main():
    all_dims = ['peers', 'src_ports', 'dst_ports', 'methods', 'paths', 'hosts']
    s = CanonicalHyperCubeSet(all_dims)

    policy_attr = ConnectionAttributes(
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
