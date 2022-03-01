#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from CanonicalIntervalSet import CanonicalIntervalSet
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

    def is_all(self):
        return self.port_set == PortSet.all_ports_interval
