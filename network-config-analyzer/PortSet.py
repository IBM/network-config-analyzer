#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from CanonicalIntervalSet import CanonicalIntervalSet
from CanonicalHyperCubeSet import CanonicalHyperCubeSet
from DimensionsManager import DimensionsManager


class PortSet:
    """
    A class for holding a set of ports, including support for (included and excluded) named ports
    """

    all_ports_interval = DimensionsManager().get_dimension_domain_by_name("dst_ports")

    def __init__(self, all_ports=False):
        # type: (bool) -> None
        self.port_set = CanonicalIntervalSet()
        self.named_ports = set()
        self.excluded_named_ports = set()
        if all_ports:
            self.port_set = PortSet.all_ports_interval.copy()

    def __eq__(self, other):
        if isinstance(other, PortSet):
            return self.port_set == other.port_set and self.named_ports == other.named_ports and \
                   self.excluded_named_ports == other.excluded_named_ports
        return NotImplemented

    def __bool__(self):
        return bool(self.port_set) or bool(self.named_ports)

    def __str__(self):
        if not self.port_set:
            if self.named_ports:
                return 'some named ports'
            return 'no ports'

        if self.port_set == PortSet.all_ports_interval:
            return 'all ports'
        return 'ports ' + str(self.port_set)

    def copy(self):
        res = PortSet()
        res.port_set = self.port_set.copy()
        res.named_ports = self.named_ports.copy()
        res.excluded_named_ports = self.excluded_named_ports.copy()
        return res

    def add_port(self, port):
        if isinstance(port, str):
            self.named_ports.add(port)
            self.excluded_named_ports.discard(port)
        else:
            interval = CanonicalIntervalSet.Interval(port, port)
            self.port_set.add_interval(interval)

    def remove_port(self, port):
        if isinstance(port, str):
            self.named_ports.discard(port)
            self.excluded_named_ports.add(port)
        else:
            interval = CanonicalIntervalSet.Interval(port, port)
            self.port_set.add_hole(interval)

    def add_port_range(self, min_port, max_port):
        interval = CanonicalIntervalSet.Interval(min_port, max_port)
        self.port_set.add_interval(interval)

    def __ior__(self, other):
        self.port_set |= other.port_set
        self.named_ports |= other.named_ports
        self.excluded_named_ports -= other.named_ports
        return self

    def __isub__(self, other):
        self.port_set -= other.port_set
        self.named_ports -= other.named_ports
        self.excluded_named_ports |= other.named_ports
        return self


# TODO: move to a separate file ?
# TODO: currently using TcpProperties as properties for all port-supported-protocols (UDP and SCTP as well)
class TcpProperties(CanonicalHyperCubeSet):
    """
    A class for holding a set of cubes_set, each defined over a range of source ports X a range of target ports
    """

    dimensions_list = ["src_ports", "dst_ports", "methods", "paths", "hosts"]
    #dimensions_list = ["src_ports", "dst_ports"]

    # TODO: change constructor defaults? either all arguments in "allow all" by default, or "empty" by default
    def __init__(self, source_ports=PortSet(), dest_ports=PortSet(), methods=None, paths=None, hosts=None):
        """
        This will create all cubes_set made of a range in source_ports and a range in dest_ports
        :param PortSet source_ports: The set of source ports (as a set of intervals/ranges)
        :param PortSet dest_ports: The set of target ports (as a set of intervals/ranges)
        """
        super().__init__(TcpProperties.dimensions_list)

        self.named_ports = {}  # a mapping from dst named port (String) to src ports interval set
        self.excluded_named_ports = {}  # a mapping from dst named port (String) to src ports interval set
        # assuming named ports are only in dest, not src
        all_ports = PortSet.all_ports_interval.copy()
        for port_name in dest_ports.named_ports:
            self.named_ports[port_name] = source_ports.port_set
        for port_name in dest_ports.excluded_named_ports:
            # self.excluded_named_ports[port_name] = all_ports - source_ports.port_set
            self.excluded_named_ports[port_name] = all_ports

        # create the cube from input arguments
        cube = [source_ports.port_set, dest_ports.port_set]
        active_dims = ["src_ports", "dst_ports"]
        if methods is not None:
            cube.append(methods)
            active_dims.append("methods")
        if paths is not None:
            cube.append(paths)
            active_dims.append("paths")
        if hosts is not None:
            cube.append(hosts)
            active_dims.append("hosts")
        self.add_cube(cube, active_dims)

    def __bool__(self):
        assert not self.named_ports
        return super().__bool__()

    def get_simplified_str(self):
        return super().__str__()

    def __str__(self):
        if not super().__bool__():
            if self.named_ports:
                return 'some named ports'
            return 'no ports'
        return self.get_simplified_str()

    def get_properties_obj(self):
        if self.is_all():
            return {}
        dimensions_header = ",".join(dim for dim in self.active_dimensions)
        cubes_str_list = []
        for cube in self:
            cubes_str_list.append(self.get_cube_str(cube))
        return {dimensions_header: sorted(cubes_str_list)}

    def __eq__(self, other):
        if isinstance(other, TcpProperties):
            res = super().__eq__(other) and self.named_ports == other.named_ports and \
                  self.excluded_named_ports == other.excluded_named_ports
            return res
        return NotImplemented

    def __and__(self, other):
        res = self.copy()
        res &= other
        return res

    def __or__(self, other):
        res = self.copy()
        res |= other
        return res

    def __sub__(self, other):
        res = self.copy()
        res -= other
        return res

    def __iand__(self, other):
        assert not self.excluded_named_ports
        assert not isinstance(other, TcpProperties) or not other.named_ports
        assert not isinstance(other, TcpProperties) or not other.excluded_named_ports
        super().__iand__(other)
        return self

    def __ior__(self, other):
        assert not isinstance(other, TcpProperties) or not other.excluded_named_ports
        super().__ior__(other)
        if isinstance(other, TcpProperties):
            res_named_ports = dict({})
            for port_name in self.named_ports:
                res_named_ports[port_name] = self.named_ports[port_name]
            for port_name in other.named_ports:
                if port_name in res_named_ports:
                    res_named_ports[port_name] |= other.named_ports[port_name]
                else:
                    res_named_ports[port_name] = other.named_ports[port_name]
            self.named_ports = res_named_ports
        return self

    def __isub__(self, other):
        assert not self.excluded_named_ports
        assert not isinstance(other, TcpProperties) or not other.named_ports
        assert not isinstance(other, TcpProperties) or not other.excluded_named_ports
        super().__isub__(other)
        return self

    def contained_in(self, other):
        """
        :param TcpProperties other: Another PortSetPair
        :return: Whether all (source port, target port) pairs in self also appear in other
        :rtype: bool
        """
        assert not self.named_ports
        assert not other.named_ports
        assert not self.excluded_named_ports
        assert not other.excluded_named_ports
        return super().contained_in(other)

    def has_named_ports(self):
        return self.named_ports or self.excluded_named_ports

    def get_named_ports(self):
        res = set()
        res |= set(self.named_ports.keys())
        # res |= set(self.excluded_named_ports.keys())
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

        my_named_ports = self.named_ports
        self.named_ports = {}
        my_excluded_named_ports = self.excluded_named_ports
        self.excluded_named_ports = {}

        for port in my_named_ports:
            real_port = named_ports.get(port)
            if real_port and real_port[1] == protocol:
                real_port_number = real_port[0]
                rectangle = [my_named_ports[port], CanonicalIntervalSet.get_interval_set(real_port_number, real_port_number)]
                self.add_cube(rectangle)
        for port in my_excluded_named_ports:
            real_port = named_ports.get(port)
            if real_port and real_port[1] == protocol:
                real_port_number = real_port[0]
                rectangle = [my_excluded_named_ports[port], CanonicalIntervalSet.get_interval_set(real_port_number, real_port_number)]
                self.add_hole(rectangle)

    def copy(self):
        res = TcpProperties()
        # from CanonicalHyperCubeSet.copy():
        for layer in self.layers:
            res.layers[layer.copy()] = self.layers[layer].copy()
        res.active_dimensions = self.active_dimensions.copy()

        res.named_ports = self.named_ports.copy()
        res.excluded_named_ports = self.excluded_named_ports.copy()
        return res

    # TODO: update this function: a diff item is not necessarily a [source-destination pair] as used to be on PortSetPair
    def print_diff(self, other, self_name, other_name):
        """
        :param TcpProperties other: Another PortSetPair object
        :param str self_name: A name for 'self'
        :param str other_name: A name for 'other'
        :return: If self!=other, return a string showing a (source, target) pair that appears in only one of them
        :rtype: str
        """
        self_minus_other = self - other
        other_minus_self = other - self
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
