#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from CanonicalIntervalSet import CanonicalIntervalSet
from CanonicalHyperCubeSet import CanonicalHyperCubeSet


class PortSet:
    """
    A class for holding a set of ports, including support for (included and excluded) named ports
    """

    def __init__(self, all_ports=False):
        # type: (bool) -> None
        self.port_set = CanonicalIntervalSet()
        self.named_ports = set()
        self.excluded_named_ports = set()
        if all_ports:
            self.port_set.add_interval(CanonicalIntervalSet.Interval(1, 65536))

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

        if self.port_set.interval_set[0].start == 1 and self.port_set.interval_set[0].end == 65536:
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


class PortSetPair:
    """
    A class for holding a set of rectangles, each defined over a range of source ports X a range of target ports
    """

    def __init__(self, source_ports=PortSet(), dest_ports=PortSet()):
        """
        This will create all rectangles made of a range in source_ports and a range in dest_ports
        :param PortSet source_ports: The set of source ports (as a set of intervals/ranges)
        :param PortSet dest_ports: The set of target ports (as a set of intervals/ranges)
        """
        self.rectangles = CanonicalHyperCubeSet(2)
        for src in source_ports.port_set:
            for dst in dest_ports.port_set:
                rectangle_intervals = [src, dst]
                self.rectangles.add_interval(rectangle_intervals)
        self.named_ports = {}  # a mapping from dst named port (String) to src ports interval set
        self.excluded_named_ports = {}  # a mapping from dst named port (String) to src ports interval set
        # assuming named ports are only in dest, not src
        all_ports = CanonicalIntervalSet()
        all_ports.add_interval(CanonicalIntervalSet.Interval(1, 65536))
        for port_name in dest_ports.named_ports:
            self.named_ports[port_name] = source_ports.port_set
        for port_name in dest_ports.excluded_named_ports:
            # self.excluded_named_ports[port_name] = all_ports - source_ports.port_set
            self.excluded_named_ports[port_name] = all_ports

    def __bool__(self):
        return bool(self.rectangles) or bool(self.named_ports)

    def get_simplified_str(self):
        if len(self.rectangles.layers) == 1:
            src_ports = self.rectangles.layers[0][0]
            dst_ports = self.rectangles.layers[0][1]
            if src_ports == CanonicalIntervalSet.Interval(1, 65536):
                return str(dst_ports)
        return str(self.rectangles)

    def __str__(self):
        if not self.rectangles:
            if self.named_ports:
                return 'some named ports'
            return 'no ports'
        return self.get_simplified_str()

    def get_properties_list(self):
        return sorted(str(self).split(','))

    def __eq__(self, other):
        if isinstance(other, PortSetPair):
            res = self.rectangles == other.rectangles and self.named_ports == other.named_ports and \
                  self.excluded_named_ports == other.excluded_named_ports
            return res
        return NotImplemented

    def __and__(self, other):
        res = PortSetPair()
        res.rectangles = self.rectangles & other.rectangles

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
        res = PortSetPair()
        res.rectangles = self.rectangles | other.rectangles

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
        res = PortSetPair()
        res.rectangles = self.rectangles - other.rectangles

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
        self.rectangles &= other.rectangles

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
        self.rectangles |= other.rectangles

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
        self.rectangles -= other.rectangles

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
        :param PortSetPair other: Another PortSetPair
        :return: Whether all (source port, target port) pairs in self also appear in other
        :rtype: bool
        """
        if not self.rectangles.contained_in(other.rectangles):
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
        for port in self.named_ports:
            real_port = named_ports.get(port)
            if real_port and real_port[1] == protocol:
                real_port_number = real_port[0]
                for src_interval in self.named_ports[port]:
                    rectangle = [src_interval, CanonicalIntervalSet.Interval(real_port_number, real_port_number)]
                    self.rectangles.add_interval(rectangle)
        for port in self.excluded_named_ports:
            real_port = named_ports.get(port)
            if real_port and real_port[1] == protocol:
                real_port_number = real_port[0]
                for src_interval in self.excluded_named_ports[port]:
                    rectangle = [src_interval, CanonicalIntervalSet.Interval(real_port_number, real_port_number)]
                    self.rectangles.add_hole(rectangle)

        self.named_ports = {}
        self.excluded_named_ports = {}

    def copy(self):
        res = PortSetPair()
        res.rectangles = self.rectangles.copy()
        res.named_ports = self.named_ports.copy()
        res.excluded_named_ports = self.excluded_named_ports.copy()
        return res

    def print_diff(self, other, self_name, other_name):
        """
        :param PortSetPair other: Another PortSetPair object
        :param str self_name: A name for 'self'
        :param str other_name: A name for 'other'
        :return: If self!=other, return a string showing a (source, target) pair that appears in only one of them
        :rtype: str
        """
        self_minus_other = self.rectangles - other.rectangles
        other_minus_self = other.rectangles - self.rectangles
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
