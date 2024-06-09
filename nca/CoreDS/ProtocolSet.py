#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from .CanonicalIntervalSet import CanonicalIntervalSet
from .ProtocolNameResolver import ProtocolNameResolver


class ProtocolSet(CanonicalIntervalSet):
    """
    A class for holding a set of protocols
    """
    min_protocol_num = 0
    max_protocol_num = 255
    port_supporting_protocols = {6, 17, 132}
    icmp_protocols = {1, 58}

    def __init__(self, all_protocols=False):
        """
        :param bool all_protocols: whether to create the object holding all protocols
        """
        super().__init__()
        if all_protocols:  # the whole range
            self.add_interval(self._whole_range_interval())

    @staticmethod
    def get_non_tcp_protocols():
        res = ProtocolSet(True)
        res.remove_protocol('TCP')
        return res

    @staticmethod
    def get_protocol_set_with_single_protocol(protocol):
        res = ProtocolSet()
        res.add_protocol(protocol)
        return res

    def __contains__(self, protocol):
        if isinstance(protocol, str):
            protocol_num = ProtocolNameResolver.get_protocol_number(protocol)
        else:
            protocol_num = protocol
        return super().__contains__(protocol_num)

    def add_protocol(self, protocol):
        """
        Adds a given protocol to the ProtocolSet if the protocol is one of the eligible protocols
         (i.e., protocol in [min_protocol_num...max_protocol_num]);
        otherwise raises exception
        :param Union[int, str] protocol: the protocol to add
        """
        if isinstance(protocol, str):
            protocol_num = ProtocolNameResolver.get_protocol_number(protocol)
        else:
            protocol_num = protocol
        if not ProtocolNameResolver.is_valid_protocol(protocol_num):
            raise Exception('Protocol must be in the range 0-255')
        self.add_interval(self.Interval(protocol_num, protocol_num))

    def remove_protocol(self, protocol):
        """
        Removes a given protocol from the ProtocolSet if the protocol is one of the eligible protocols
        (i.e., protocol in [min_protocol_num...max_protocol_num]);
        otherwise raises exception
        :param Union[int,str] protocol: the protocol to remove
        """
        if isinstance(protocol, str):
            protocol_num = ProtocolNameResolver.get_protocol_number(protocol)
        else:
            protocol_num = protocol
        if not ProtocolNameResolver.is_valid_protocol(protocol_num):
            raise Exception('Protocol must be in the range 0-255')
        self.add_hole(self.Interval(protocol_num, protocol_num))

    def set_protocols(self, protocols):
        """
        Sets all protocols from the given parameter
        :param CanonicalIntervalSet protocols: the protocols to set
        """
        for interval in protocols:
            self.add_interval(interval)

    @staticmethod
    def _whole_range_interval():
        """
        :return: the interval representing the whole range (all protocols)
        """
        return CanonicalIntervalSet.Interval(ProtocolSet.min_protocol_num, ProtocolSet.max_protocol_num)

    @staticmethod
    def _whole_range_interval_set():
        """
        :return: the interval set representing the whole range (all protocols)
        """
        interval = ProtocolSet._whole_range_interval()
        return CanonicalIntervalSet.get_interval_set(interval.start, interval.end)

    def is_whole_range(self):
        """
        :return: True if the ProtocolSet contains all protocols, False otherwise
        """
        return self == self._whole_range_interval_set()

    @staticmethod
    def get_protocol_names_from_interval_set(interval_set):
        """
        Returns names of protocols represented by a given interval set
        :param CanonicalIntervalSet interval_set: the interval set
        :return: the list of protocol names
        """
        res = []
        for interval in interval_set:
            assert interval.start >= ProtocolSet.min_protocol_num and interval.end <= ProtocolSet.max_protocol_num
            for index in range(interval.start, interval.end + 1):
                name = ProtocolNameResolver.get_protocol_name(index)
                res.append(name if name else str(index))
        return res

    @staticmethod
    def _get_compl_protocol_names_from_interval_set(interval_set):
        """
        Returns names of protocols not included in a given interval set
        :param CanonicalIntervalSet interval_set: the interval set
        :return: the list of complement protocol names
        """
        res_interval_set = ProtocolSet._whole_range_interval_set() - interval_set
        return ProtocolSet.get_protocol_names_from_interval_set(res_interval_set)

    def __str__(self):
        """
        :return: Compact string representation of the ProtocolSet
        """
        if self.is_whole_range():
            return '*'
        if not self:
            return 'Empty'
        protocol_names = self.get_protocol_names_from_interval_set(self)
        compl_protocol_names = self._get_compl_protocol_names_from_interval_set(self)
        if len(protocol_names) <= len(compl_protocol_names):
            values_list = ', '.join(protocol for protocol in protocol_names)
        else:
            values_list = 'all but ' + ', '.join(protocol for protocol in compl_protocol_names)

        return values_list

    def copy(self):
        # new_copy = copy.copy(self)  # the copy.copy() keeps the same reference to the interlval_set attribute
        new_copy = ProtocolSet()
        for interval in self.interval_set:
            new_copy.interval_set.append(interval.copy())
        return new_copy

    @staticmethod
    def protocol_supports_ports(protocol):
        """
        :param protocol: Protocol number or name
        :return: Whether the given protocol has ports
        :rtype: bool
        """
        prot = protocol
        if isinstance(protocol, str):
            prot = ProtocolNameResolver.get_protocol_number(protocol)
        return prot in ProtocolSet.port_supporting_protocols

    @staticmethod
    def protocol_is_icmp(protocol):
        """
        :param protocol: Protocol number or name
        :return: Whether the protocol is icmp or icmpv6
        :rtype: bool
        """
        prot = protocol
        if isinstance(protocol, str):
            prot = ProtocolNameResolver.get_protocol_number(protocol)
        return prot in ProtocolSet.icmp_protocols
