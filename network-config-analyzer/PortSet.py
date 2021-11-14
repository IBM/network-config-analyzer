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
    MIN_POS_NAMED_PORT_NUM = MAX_PORT_NUM + 10                      # make a gap to avoid uniting named and unnamed port ranges
    MAX_POS_NAMED_PORT_NUM = MIN_POS_NAMED_PORT_NUM + 10000             # make enough place for named ports
    MIN_NEG_NAMED_PORT_NUM = MAX_POS_NAMED_PORT_NUM + 10            # make a gap to avoid uniting named positive ang negative port ranges
    MAX_NEG_NAMED_PORT_NUM = MIN_NEG_NAMED_PORT_NUM + 10000     # make enough place for named ports

    @singleton
    class NamedPortDB:
        """
        A singleton class for holding a mapping between name and faked number (index) of named ports
        Two sets are kept: positive ports (appearing under 'ports:' in policies)
        and negative ports (appearing under 'notPorts:' in policies).
        """

        def __init__(self):
            self._pos_port_names = []
            self._neg_port_names = []

        def name_to_pos_index(self, name):
            if self._pos_port_names.count(name) == 0:
                self._pos_port_names.append(name)
            return PortSet.MIN_POS_NAMED_PORT_NUM + self._pos_port_names.index(name)

        def name_to_neg_index(self, name):
            if self._neg_port_names.count(name) == 0:
                self._neg_port_names.append(name)
            return PortSet.MIN_NEG_NAMED_PORT_NUM + self._neg_port_names.index(name)

        def index_to_name(self, index):
            if PortSet.is_pos_named_port(index):
                return self._pos_port_names[index - PortSet.MIN_POS_NAMED_PORT_NUM]
            if PortSet.is_neg_named_port(index):
                return self._neg_port_names[index - PortSet.MIN_NEG_NAMED_PORT_NUM]
            return ""

        def pos_named_ports_num(self):
            return len(self._pos_port_names)

        def neg_named_ports_num(self):
            return len(self._neg_port_names)

    @staticmethod
    def is_pos_named_port(port):
        return port >= PortSet.MIN_POS_NAMED_PORT_NUM and port < PortSet.MIN_POS_NAMED_PORT_NUM + PortSet.NamedPortDB().pos_named_ports_num()

    @staticmethod
    def is_neg_named_port(port):
        return port >= PortSet.MIN_NEG_NAMED_PORT_NUM and port < PortSet.MIN_NEG_NAMED_PORT_NUM + PortSet.NamedPortDB().neg_named_ports_num()

    @staticmethod
    def is_named_port(port):
        return PortSet.is_pos_named_port(port) or PortSet.is_neg_named_port(port)

    def __init__(self, all_ports=False):
        # type: (bool) -> None
        super().__init__()
        if all_ports:
            self.add_interval(CanonicalIntervalSet.Interval(PortSet.MIN_PORT_NUM, PortSet.MAX_PORT_NUM))

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

        if self.interval_set[0].start == self.MIN_PORT_NUM and self.interval_set[0].end == self.MAX_PORT_NUM \
                and not self.has_named_ports():
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

    def add_port(self, port, is_pos=True):
        if isinstance(port, str):
            ind = PortSet.NamedPortDB().name_to_pos_index(port) if is_pos else PortSet.NamedPortDB().name_to_neg_index(port)
            interval = CanonicalIntervalSet.Interval(ind, ind)
        else:
            interval = CanonicalIntervalSet.Interval(port, port)
        self.add_interval(interval)

    def remove_port(self, port, is_pos=True):
        if isinstance(port, str):
            ind = PortSet.NamedPortDB().name_to_pos_index(port) if is_pos else PortSet.NamedPortDB().name_to_neg_index(port)
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
    A class for holding a set of rectangles, each defined over a range of source ports X a range of dest ports
    All ports are divided to 3 domains:
    - MIN_PORT_NUM .. MAX_PORT_NUM: a domain for real ports (provided as numbers in policies),
    - MIN_POS_NAMED_PORT_NUM .. MAX_POS_NAMED_PORT_NUM: a domain for positive named ports (named ports provided under 'ports:' in policies)
    - MIN_NEG_NAMED_PORT_NUM .. MAX_NEG_NAMED_PORT_NUM: a domain for negative named ports (named ports provided under 'notPorts:' in policies)

    Note, only destination ports may contain named ports.
    This class makes the following assumption (embodied in assert statements below):
    since for each rule convert_named_ports is applied, no named ports exist at the moment when logical operations are applied
    between PortSetPairs (i.e., Allow/Deny logic of rules is executed after all named ports are converted to real ones in the rules)

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
        return super().__isub__(other)

    def has_named_ports(self):
        for layer in self.layers:
            if PortSet.is_named_port(layer[0].start):
                return True
        return False

    def get_named_ports(self):
        res = set()
        for layer in self.layers:
            if PortSet.is_named_port(layer[0].start):
                startPortName = PortSet.NamedPortDB().index_to_name(layer[0].start)
                if startPortName:
                    res.add(startPortName)
                endPortName = PortSet.NamedPortDB().index_to_name(layer[0].end)
                if endPortName:
                    res.add(endPortName)
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
        pos_named_port_layers = []
        neg_named_port_layers = []
        for layer in self.layers:
            if PortSet.is_pos_named_port(layer[0].start):
                pos_named_port_layers.append((layer[0].copy(), layer[1].copy()))
            elif PortSet.is_neg_named_port(layer[0].start):
                neg_named_port_layers.append((layer[0].copy(), layer[1].copy()))

        # Next, remove faked named ports and remove real ports corresponding to the negative named ports
        for layer in neg_named_port_layers:
            layer_sub_element = layer[1]
            assert layer_sub_element.dimensions == 1
            interval_list = layer_sub_element.baseIntervalSet

            # remove faked named ports
            for src_interval in interval_list:
                old_rectangle = [layer[0], src_interval]
                self.add_hole(old_rectangle)

            # remove real ports corresponding to the negative named ones
            for port in range(layer[0].start, min(layer[0].end + 1, \
                                                  PortSet.MIN_NEG_NAMED_PORT_NUM + PortSet.NamedPortDB().neg_named_ports_num())):
                real_port = named_ports.get(PortSet.NamedPortDB().index_to_name(port))
                if real_port and real_port[1] == protocol:
                    real_port_number = real_port[0]
                    for src_interval in interval_list:
                        new_rectangle = [CanonicalIntervalSet.Interval(real_port_number, real_port_number), src_interval]
                        self.add_hole(new_rectangle)

        # Finally, remove faked named ports and add real ports corresponding to the positive named ports
        for layer in pos_named_port_layers:
            layer_sub_element = layer[1]
            assert layer_sub_element.dimensions == 1
            interval_list = layer_sub_element.baseIntervalSet

            # remove faked named ports
            for src_interval in interval_list:
                old_rectangle = [layer[0], src_interval]
                self.add_hole(old_rectangle)

            # add real ports corresponding to the positive named ones
            for port in range(layer[0].start, min(layer[0].end + 1, \
                                                  PortSet.MIN_POS_NAMED_PORT_NUM + PortSet.NamedPortDB().pos_named_ports_num())):
                real_port = named_ports.get(PortSet.NamedPortDB().index_to_name(port))
                if real_port and real_port[1] == protocol:
                    real_port_number = real_port[0]
                    for src_interval in interval_list:
                        new_rectangle = [CanonicalIntervalSet.Interval(real_port_number, real_port_number), src_interval]
                        self.add_interval(new_rectangle)

    def copy(self):
        res = PortSetPair()
        # From CanonicalHuperCubeSet.copy (did not find a way to write a decent copy c'tor)
        for layer in self.layers:
            res.layers.append((layer[0].copy(), layer[1].copy()))
        res.baseIntervalSet = self.baseIntervalSet.copy()
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
