#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import copy
from CanonicalHyperCubeSet import CanonicalHyperCubeSet
from CanonicalIntervalSet import CanonicalIntervalSet


class ICMPDataSet(CanonicalHyperCubeSet):
    """
    A class holding the set of allowed ICMP connections. Each such connection has a type and code properties.
    The class uses the CanonicalHyperCubeSet to compactly represent a set of (type,code) pairs.
    """
    def __init__(self, add_all=False):
        super().__init__(2)
        if add_all:
            self.add_all()

    def __str__(self):
        if not self:
            return 'no types'
        return super().__str__()

    def copy(self):
        new_copy = copy.copy(self)
        return new_copy

    @staticmethod
    def check_code_type_validity(icmp_type, icmp_code):
        """
        Checks that the type,code pair is a valid combination for an ICMP connection
        :param int icmp_type: Connection type
        :param int icmp_code: Connection code
        :return: A string with an error if the pair is invalid. An empty string otherwise
        :rtype: str
        """
        if icmp_code is not None and icmp_type is None:
            return 'ICMP code cannot be specified without a type'
        if icmp_type < 0 or icmp_type > 254:
            return 'ICMP type must be in the range 0-254'
        if icmp_code is not None and (icmp_code < 0 or icmp_code > 255):
            return 'ICMP code must be in the range 0-255'
        return ''

    def add_to_set(self, icmp_type, icmp_code):
        """
        Add a new connection to the set of allowed connection
        :param int icmp_type: connection type
        :param int icmp_code: connection code
        :return: None
        """
        if icmp_type is None:
            self.add_all()
            return

        if icmp_code is None:
            self.add_interval(
                [CanonicalIntervalSet.Interval(icmp_type, icmp_type), CanonicalIntervalSet.Interval(0, 255)])
            return

        self.add_interval(
            [CanonicalIntervalSet.Interval(icmp_type, icmp_type), CanonicalIntervalSet.Interval(icmp_code, icmp_code)])

    def add_all_but_given_pair(self, icmp_type, icmp_code):
        """
        Add all possible ICMP connections except for the given (type,code) pair
        :param int icmp_type: connection type
        :param int icmp_code: connection code
        :return: None
        """
        if icmp_type is None:
            self.clear()  # all but everything == nothing
            return

        self.add_all()
        if icmp_code is None:
            self.add_hole(
                [CanonicalIntervalSet.Interval(icmp_type, icmp_type), CanonicalIntervalSet.Interval(0, 255)])
        else:
            self.add_hole(
                [CanonicalIntervalSet.Interval(icmp_type, icmp_type),
                 CanonicalIntervalSet.Interval(icmp_code, icmp_code)])

    def add_all(self):
        """
        Add all possible ICMP connections to the set
        :return: None
        """
        self.add_interval(
            [CanonicalIntervalSet.Interval(0, 254), CanonicalIntervalSet.Interval(0, 255)])

    def print_diff(self, other, self_name, other_name):
        """
        Print the diff between two sets of ICMP connections
        :param ICMPDataSet other: The set of ICMP connections to compare against
        :param self_name: the name of the self set of connections
        :param other_name: the name of the other set of connections
        :return: a string showing one diff in connections (if exists).
        :rtype: str
        """
        self_does_not = ' while ' + self_name + ' does not.'
        other_does_not = ' while ' + other_name + ' does not.'
        self_minus_other = self - other
        other_minus_self = other - self
        if self_minus_other:
            item = self_minus_other.get_first_item()
            return self_name + ' allows code ' + str(item[1]) + ' for type ' + str(item[0]) + other_does_not
        if other_minus_self:
            item = other_minus_self.get_first_item()
            return other_name + ' allows code ' + str(item[1]) + ' for type ' + str(item[0]) + self_does_not
        return 'No diff.'
