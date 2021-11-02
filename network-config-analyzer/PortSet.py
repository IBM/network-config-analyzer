#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from CanonicalIntervalSet import CanonicalIntervalSet
from CanonicalHyperCubeSet import CanonicalHyperCubeSet

def singleton(class_):
    instances = {}
    def getinstance(*args, **kwargs):
        if class_ not in instances:
            instances[class_] = class_(*args, **kwargs)
        return instances[class_]
    return getinstance

class PortSet(CanonicalIntervalSet):
    """
    A class for holding a set of ports, including support for named ports
    Named ports are represented by indices higher than 65536
    A mapping between name and index of named ports is handled by NamedPortDB singleton
    """
    MIN_PORT_NUM = 1
    MAX_PORT_NUM = 65536
    MIN_NAMED_PORT_NUM = MAX_PORT_NUM + 10          # make a gap to avoid uniting named and unnamed port ranges
    MAX_NAMED_PORT_NUM = MIN_NAMED_PORT_NUM + 10000 # make enough place for named ports

    @singleton
    class NamedPortDB:
        """
        A class for holding a mapping between name and faked number (index) of named ports is handled by NamedPortDB singleton
        """

        def __init__(self):
            self._names = []

        def nameToIndex(self, name):
            if self._names.count(name) == 0:
                self._names.append(name)
            return PortSet.MIN_NAMED_PORT_NUM + self._names.index(name)

        def indexToName(self, index):
            if not PortSet.is_named_port(index) or index >= PortSet.MIN_NAMED_PORT_NUM + len(self._names):
                raise Exception('Named port index out of range')
            return self._names[index-PortSet.MIN_NAMED_PORT_NUM]

    @staticmethod
    def is_named_port(port):
        return port >= PortSet.MIN_NAMED_PORT_NUM and port < PortSet.MAX_NAMED_PORT_NUM

    def __init__(self, all_ports=False):
        # type: (bool) -> None
        super().__init__()
        if all_ports:
            self.add_interval(CanonicalIntervalSet.Interval(PortSet.MIN_PORT_NUM, PortSet.MAX_PORT_NUM))
#        self.add_interval(CanonicalIntervalSet.Interval(PortSet.MIN_NAMED_PORT_NUM, PortSet.MAX_NAMED_PORT_NUM))

    def has_real_ports(self):
        for port_range in self:
            if not self.is_named_port(port_range.start):
                return True
        return False

    def has_named_ports(self):
        for port_range in self.interval_set:
            if PortSet.is_named_port(port_range.start):
                return True
        return False

    def __str__(self):
        if not self:
            return 'no ports'

        if self.interval_set[0].start == self.MIN_PORT_NUM and self.interval_set[0].end == self.MAX_PORT_NUM:
            return 'all ports'

        hasNamedPort = False
        res = ''
        for port_range in self.interval_set:
            if PortSet.is_named_port(port_range.start):
                hasNamedPort = True
            else:
                res += str(port_range.start)
                if port_range.start != port_range.end:
                    res += '-' + str(port_range.end)
                res += ','
        if res:
            return res
        assert hasNamedPort
        return 'some named ports'

    def copy(self):
        res = PortSet(super().copy())
        return res

    def add_port(self, port):
        if isinstance(port, str):
            ind = PortSet.NamedPortDB().nameToIndex(port)
            interval = CanonicalIntervalSet.Interval(ind, ind)
        else:
            interval = CanonicalIntervalSet.Interval(port, port)
        self.add_interval(interval)

    def remove_port(self, port):
        if isinstance(port, str):
            ind = PortSet.NamedPortDB().nameToIndex(port)
            interval = CanonicalIntervalSet.Interval(ind, ind)
        else:
            interval = CanonicalIntervalSet.Interval(port, port)
        self.add_hole(interval)

    def add_port_range(self, min_port, max_port):
        assert not PortSet.is_named_port(min_port)
        assert not PortSet.is_named_port(max_port)
        interval = CanonicalIntervalSet.Interval(min_port, max_port)
        self.add_interval(interval)

class PortSetPair(CanonicalHyperCubeSet):
    """
    A class for holding a set of rectangles, each defined over a range of source ports X a range of target ports
    """

    def __init__(self, source_ports=PortSet(), dest_ports=PortSet()):
        """
        This will create all rectangles made of a range in source_ports and a range in dest_ports
        :param PortSet source_ports: The set of source ports (as a set of intervals/ranges)
        :param PortSet dest_ports: The set of target ports (as a set of intervals/ranges)
        assuming named ports are only in dest, not src
        """
        super().__init__(2)
        for src in source_ports:
            for dst in dest_ports:
                rectangle_intervals = [dst, src]
                self.add_interval(rectangle_intervals)

    def get_simplified_str(self):
        if len(self.layers) == 1:
            src_ports = self.layers[0][1]
            dst_ports = self.layers[0][0]
            if dst_ports == CanonicalIntervalSet.Interval(PortSet.MIN_PORT_NUM, PortSet.MAX_PORT_NUM):
                return str(src_ports)
        return super().__str__() # includes dst ports real numbers and faked numbers (for named ports)

    def __str__(self):
        if not self.layers:
            return 'no ports'
        return self.get_simplified_str()

    def get_properties_obj(self):
        return {'Ports': sorted(str(self).split(','))}

    def __and__(self, other):
        assert not self.has_named_ports()
        assert not other.has_named_ports()
        return super().__and__(other)

    def __or__(self, other):
        assert not self.has_named_ports()
        assert not other.has_named_ports()
        return super().__or__(other)

    def __sub__(self, other):
        assert not self.has_named_ports()
        assert not other.has_named_ports()
        return super().__sub__(other)

    def __iand__(self, other):
        assert not self.has_named_ports()
        assert not other.has_named_ports()
        return super().__iand__(other)

    def __ior__(self, other):
        assert not self.has_named_ports()
        assert not other.has_named_ports()
        return super().__ior__(other)

    def __isub__(self, other):
        assert not self.has_named_ports()
        assert not other.has_named_ports()
        return super.__isub__(other)

    def has_named_ports(self):
        for layer in self.layers:
            if PortSet.is_named_port(layer[0].start):
                return True
        return False

    def get_named_ports(self):
        res = set()
        for layer in self.layers:
            if PortSet.is_named_port(layer[0].start):
                res.add(PortSet.NamedPortDB().indexToName(layer[0].start))
                res.add(PortSet.NamedPortDB().indexToName(layer[0].end))
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

        # First, pick all named port ranges
        named_port_layers = []
        for layer in self.layers:
            if PortSet.is_named_port(layer[0].start):
                named_port_layers.append(layer.copy())

        # Next, remove faked named ports and add real ports corresponding to the named ones
        for layer in named_port_layers:
            for port in range(layer[0].start, layer[0].end + 1):
                removedFakedPort = False
                real_port = named_ports.get(PortSet.NamedPortDB().indexToName(port))
                if real_port and real_port[1] == protocol:
                    real_port_number = real_port[0]
                    layer_sub_element = layer[1]
                    assert layer_sub_element.dimensions == 1
                    interval_list = layer_sub_element.get_list_of_all_intervals_paths()
                    for src_interval in interval_list:
                        new_rectangle = [CanonicalIntervalSet.Interval(real_port_number, real_port_number), src_interval]
                        self.add_interval(new_rectangle)
                        if not removedFakedPort:
                            old_rectangle = [layer[0], src_interval]
                            self.add_hole(old_rectangle)
                            removedFakedPort = True

    def copy(self):
        res = PortSetPair(super().copy())
        return res

    def print_diff(self, other, self_name, other_name):
        """
        :param PortSetPair other: Another PortSetPair object
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
