#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from .CanonicalIntervalSet import CanonicalIntervalSet
from .ProtocolNameResolver import ProtocolNameResolver


class ProtocolSet(CanonicalIntervalSet):
    """
    A class for holding a set of HTTP methods
    """

    # According to https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    all_protocols_list = ProtocolNameResolver.get_all_protocols_list()

    def __init__(self, all_protocols=False):
        """
        :param bool all_protocols: whether to create the object holding all protocols
        """
        super().__init__()
        if all_protocols:  # the whole range
            self.add_interval(self._whole_range_interval())

    def add_protocol(self, protocol):
        """
        Adds a given protocol to the ProtocolSet if the method is one of the eligible protocols (in all_protocols_list);
        otherwise raises ValueError exception
        :param str protocol: the protocol to add
        """
        index = self.all_protocols_list.index(protocol)
        self.add_interval(self.Interval(index, index))

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
        return CanonicalIntervalSet.Interval(0, len(ProtocolSet.all_protocols_list) - 1)

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
            assert interval.start >= 0 and interval.end < len(ProtocolSet.all_protocols_list)
            for index in range(interval.start, interval.end + 1):
                res.append(ProtocolSet.all_protocols_list[index])
        return res

    @staticmethod
    def _get_compl_protocol_names_from_interval_set(interval_set):
        """
        Returns names of protocols not included in a given interval set
        :param CanonicalIntervalSet interval_set: the interval set
        :return: the list of complement protocol names
        """
        res = ProtocolSet.all_protocols_list.copy()
        for protocol in ProtocolSet.get_protocol_names_from_interval_set(interval_set):
            res.remove(protocol)
        return res

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
