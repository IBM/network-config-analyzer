#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from CanonicalIntervalSet import CanonicalIntervalSet
from CanonicalHyperCubeSet import CanonicalHyperCubeSet
from DimensionsManager import DimensionsManager
from PortSet import PortSet


class TcpLikeProperties:
    """
    A class for holding a set of cubes, each defined over dimensions from TcpLikeProperties.dimensions_list
    For UDP, SCTP protocols, the actual used dimensions are only [source ports, dest ports]
    for TCP, it may be any of the dimensions from dimensions_list.
    """

    dimensions_list = ["src_ports", "dst_ports", "methods", "paths", "hosts"]

    # TODO: change constructor defaults? either all arguments in "allow all" by default, or "empty" by default
    def __init__(self, source_ports=PortSet(), dest_ports=PortSet(), methods=None, paths=None, hosts=None):
        """
        This will create all cubes made of the input arguments ranges/regex values.
        :param PortSet source_ports: The set of source ports (as a set of intervals/ranges)
        :param PortSet dest_ports: The set of target ports (as a set of intervals/ranges)
        :param MinDFA methods: the dfa of http request methods
        :param MinDFA paths: The dfa of http request paths
        :param MinDFA hosts: The dfa of http request hosts
        """
        self.cubes_set = CanonicalHyperCubeSet(TcpLikeProperties.dimensions_list)

        # create the cube from input arguments
        cube = []
        active_dims = []
        if not source_ports.is_all():
            cube.append(source_ports.port_set)
            active_dims.append("src_ports")
        if not dest_ports.is_all():
            cube.append(dest_ports.port_set)
            active_dims.append("dst_ports")
        if methods is not None:
            cube.append(methods)
            active_dims.append("methods")
        if paths is not None:
            cube.append(paths)
            active_dims.append("paths")
        if hosts is not None:
            cube.append(hosts)
            active_dims.append("hosts")
        if not active_dims:
            self.cubes_set.set_all()
        else:
            has_empty_dim_value = False
            for dim_val in cube:
                if not dim_val:
                    has_empty_dim_value = True
                    break
            if not has_empty_dim_value:
                self.cubes_set.add_cube(cube, active_dims)

        self.named_ports = {}  # a mapping from dst named port (String) to src ports interval set
        self.excluded_named_ports = {}  # a mapping from dst named port (String) to src ports interval set
        # assuming named ports are only in dest, not src
        all_ports = PortSet.all_ports_interval.copy()
        for port_name in dest_ports.named_ports:
            self.named_ports[port_name] = source_ports.port_set
        for port_name in dest_ports.excluded_named_ports:
            # self.excluded_named_ports[port_name] = all_ports - source_ports.port_set
            self.excluded_named_ports[port_name] = all_ports

    def __bool__(self):
        return bool(self.cubes_set) or bool(self.named_ports)

    def __str__(self):
        if self.cubes_set.is_all():
            return ''
        if not self.cubes_set:
            return 'Empty'
        if self.cubes_set.active_dimensions == ['dst_ports']:
            assert (len(self.cubes_set) == 1)
            for cube in self.cubes_set:
                ports_list = self.get_interval_set_list_obj(cube[0])
                ports_str = ','.join(ports_interval for ports_interval in ports_list)
                return ports_str

        cubes_dict_list = [self.get_cube_dict(cube, self.cubes_set.active_dimensions, True) for cube in self.cubes_set]
        return ','.join(str(cube_dict) for cube_dict in cubes_dict_list)

    @staticmethod
    def get_interval_set_list_obj(interval_set):
        res = []
        for interval in interval_set:
            if interval.start == interval.end:
                res.append(str(interval.start))
            else:
                res.append(f'{interval.start}-{interval.end}')
        return res

    @staticmethod
    def get_cube_dict(cube, dims_list, is_txt=False):
        cube_dict = {}
        for i, dim in enumerate(dims_list):
            dim_values = cube[i]
            dim_type = DimensionsManager().get_dimension_type_by_name(dim)
            dim_domain = DimensionsManager().get_dimension_domain_by_name(dim)
            if dim_domain == dim_values:
                continue  # skip dimensions with all values allowed in a cube
            if dim_type == DimensionsManager.DimensionType.IntervalSet:
                values_list = TcpLikeProperties.get_interval_set_list_obj(dim_values)
                if is_txt:
                    values_list = ','.join(interval for interval in values_list)
            else:
                # TODO: should be a list of words for a finite len DFA?
                values_list = DimensionsManager().get_dim_values_str(dim_values, dim)
            cube_dict[dim] = values_list
        return cube_dict

    def get_properties_obj(self):
        """
        get an object for a yaml representation of the protocol's properties
        """
        if self.cubes_set.is_all():
            return {}
        cubs_dict_list = []
        for cube in self.cubes_set:
            cube_dict = self.get_cube_dict(cube, self.cubes_set.active_dimensions)
            cubs_dict_list.append(cube_dict)
        if self.cubes_set.active_dimensions == ['dst_ports']:
            assert len(cubs_dict_list) == 1
            return {'Ports': cubs_dict_list[0]['dst_ports']}
        return {'properties': cubs_dict_list}

    def __eq__(self, other):
        if isinstance(other, TcpLikeProperties):
            res = self.cubes_set == other.cubes_set and self.named_ports == other.named_ports and \
                  self.excluded_named_ports == other.excluded_named_ports
            return res
        return NotImplemented

    def __and__(self, other):
        res = TcpLikeProperties()
        res.cubes_set = self.cubes_set & other.cubes_set

        res.named_ports = dict({})
        for port_name in self.named_ports:
            if port_name in other.named_ports:
                src_interval_res = self.named_ports[port_name] & other.named_ports[port_name]
                res.named_ports[port_name] = src_interval_res

        res.excluded_named_ports = dict({})
        for port_name in self.excluded_named_ports:
            res.excluded_named_ports[port_name] = self.excluded_named_ports[port_name]
        for port_name in other.excluded_named_ports:
            if port_name in res.excluded_named_ports:
                res.excluded_named_ports[port_name] |= other.excluded_named_ports[port_name]
            else:
                res.excluded_named_ports[port_name] = other.excluded_named_ports[port_name]

        return res

    def __or__(self, other):
        res = TcpLikeProperties()
        res.cubes_set = self.cubes_set | other.cubes_set

        res.named_ports = dict({})
        for port_name in self.named_ports:
            res.named_ports[port_name] = self.named_ports[port_name]
        for port_name in other.named_ports:
            if port_name in res.named_ports:
                res.named_ports[port_name] |= other.named_ports[port_name]
            else:
                res.named_ports[port_name] = other.named_ports[port_name]

        res.excluded_named_ports = dict({})
        for port_name in self.excluded_named_ports:
            res.excluded_named_ports[port_name] = self.excluded_named_ports[port_name]
        for port_name in other.named_ports:
            if port_name in res.excluded_named_ports:
                res.excluded_named_ports[port_name] -= other.named_ports[port_name]

        return res

    def __sub__(self, other):
        res = TcpLikeProperties()
        res.cubes_set = self.cubes_set - other.cubes_set

        res.named_ports = dict({})
        for port_name in self.named_ports:
            res.named_ports[port_name] = self.named_ports[port_name]
        for port_name in other.named_ports:
            if port_name in res.named_ports:
                res.named_ports[port_name] -= other.named_ports[port_name]

        res.excluded_named_ports = dict({})
        for port_name in self.excluded_named_ports:
            res.excluded_named_ports[port_name] = self.excluded_named_ports[port_name]
        for port_name in other.named_ports:
            if port_name in res.excluded_named_ports:
                res.excluded_named_ports[port_name] |= other.named_ports[port_name]
            else:
                res.excluded_named_ports[port_name] = other.named_ports[port_name]

        return res

    def __iand__(self, other):
        self.cubes_set &= other.cubes_set

        res_named_ports = dict({})
        for port_name in self.named_ports:
            if port_name in other.named_ports:
                src_interval_res = self.named_ports[port_name] & other.named_ports[port_name]
                res_named_ports[port_name] = src_interval_res
        self.named_ports = res_named_ports

        res_excluded_named_ports = dict({})
        for port_name in self.excluded_named_ports:
            res_excluded_named_ports[port_name] = self.excluded_named_ports[port_name]
        for port_name in other.excluded_named_ports:
            if port_name in res_excluded_named_ports:
                res_excluded_named_ports[port_name] |= other.excluded_named_ports[port_name]
            else:
                res_excluded_named_ports[port_name] = other.excluded_named_ports[port_name]
        self.excluded_named_ports = res_excluded_named_ports

        return self

    def __ior__(self, other):
        self.cubes_set |= other.cubes_set

        res_named_ports = dict({})
        for port_name in self.named_ports:
            res_named_ports[port_name] = self.named_ports[port_name]
        for port_name in other.named_ports:
            if port_name in res_named_ports:
                res_named_ports[port_name] |= other.named_ports[port_name]
            else:
                res_named_ports[port_name] = other.named_ports[port_name]
        self.named_ports = res_named_ports

        res_excluded_named_ports = dict({})
        for port_name in self.excluded_named_ports:
            res_excluded_named_ports[port_name] = self.excluded_named_ports[port_name]
        for port_name in other.named_ports:
            if port_name in res_excluded_named_ports:
                res_excluded_named_ports[port_name] -= other.named_ports[port_name]
        self.excluded_named_ports = res_excluded_named_ports

        return self

    def __isub__(self, other):
        self.cubes_set -= other.cubes_set

        res_named_ports = dict({})
        for port_name in self.named_ports:
            res_named_ports[port_name] = self.named_ports[port_name]
        for port_name in other.named_ports:
            if port_name in res_named_ports:
                res_named_ports[port_name] -= other.named_ports[port_name]
        self.named_ports = res_named_ports

        res_excluded_named_ports = dict({})
        for port_name in self.excluded_named_ports:
            res_excluded_named_ports[port_name] = self.excluded_named_ports[port_name]
        for port_name in other.named_ports:
            if port_name in res_excluded_named_ports:
                res_excluded_named_ports[port_name] |= other.named_ports[port_name]
            else:
                res_excluded_named_ports[port_name] = other.named_ports[port_name]
        self.excluded_named_ports = res_excluded_named_ports

        return self

    def contained_in(self, other):
        """
        :param TcpLikeProperties other: Another PortSetPair
        :return: Whether all (source port, target port) pairs in self also appear in other
        :rtype: bool
        """
        if not self.cubes_set.contained_in(other.cubes_set):
            return False
        for port_name in self.named_ports:
            if port_name not in other.named_ports:
                return False
            if not self.named_ports[port_name].contained_in(other.named_ports[port_name]):
                return False
        for port_name in other.excluded_named_ports:
            if port_name not in self.excluded_named_ports:
                return False
            if not other.excluded_named_ports[port_name].contained_in(self.excluded_named_ports[port_name]):
                return False
        return True

    def has_named_ports(self):
        return self.named_ports or self.excluded_named_ports

    def get_named_ports(self):
        res = set()
        res |= set(self.named_ports.keys())
        return res

    def convert_named_ports(self, named_ports, protocol):
        """
        Replaces all references to named ports with actual ports, given a mapping
        NOTE: that this function modifies self
        :param dict[str, (int, int)] named_ports: The mapping from a named to port (str) to the actual port number
        :param int protocol: The relevant protocol
        :return: None
        """
        if not named_ports:
            named_ports = {}

        for port in self.named_ports:
            real_port = named_ports.get(port)
            if real_port and real_port[1] == protocol:
                real_port_number = real_port[0]
                rectangle = [self.named_ports[port],
                             CanonicalIntervalSet.get_interval_set(real_port_number, real_port_number)]
                self.cubes_set.add_cube(rectangle)
        for port in self.excluded_named_ports:
            real_port = named_ports.get(port)
            if real_port and real_port[1] == protocol:
                real_port_number = real_port[0]
                rectangle = [self.excluded_named_ports[port],
                             CanonicalIntervalSet.get_interval_set(real_port_number, real_port_number)]
                self.cubes_set.add_hole(rectangle)

        self.named_ports = {}
        self.excluded_named_ports = {}

    def copy(self):
        res = TcpLikeProperties()
        res.cubes_set = self.cubes_set.copy()
        res.named_ports = self.named_ports.copy()
        res.excluded_named_ports = self.excluded_named_ports.copy()
        return res

    # TODO: update this function: a diff item is not necessarily a [source-destination pair] as used to be on PortSetPair
    def print_diff(self, other, self_name, other_name):
        """
        :param TcpLikeProperties other: Another PortSetPair object
        :param str self_name: A name for 'self'
        :param str other_name: A name for 'other'
        :return: If self!=other, return a string showing a (source, target) pair that appears in only one of them
        :rtype: str
        """
        self_minus_other = self.cubes_set - other.cubes_set
        other_minus_self = other.cubes_set - self.cubes_set
        diff_str = self_name if self_minus_other else other_name
        if self_minus_other:
            item = self_minus_other.get_first_item()
            diff_str += f' allows communication on {item} while {other_name} does not [source-destination pair] '
            return diff_str
        if other_minus_self:
            item = other_minus_self.get_first_item()
            diff_str += f' allows communication on {item} while {self_name} does not [source-destination pair] '
            return diff_str
        return 'No diff.'
