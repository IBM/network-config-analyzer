#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import copy

from CanonicalIntervalSet import CanonicalIntervalSet


class MethodSet(CanonicalIntervalSet):
    """
    A class for holding a set of HTTP methods
    """
    all_methods_list = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']

    def __init__(self, all_methods=False):
        """
        :param bool all_methods: whether to create the object holding all methods
        """
        super().__init__()
        if all_methods:  # the whole range
            self.add_interval(self._whole_range_interval())

    @staticmethod
    def _whole_range_interval():
        """
        :return: the interval representing the whole range (all methods)
        """
        return CanonicalIntervalSet.Interval(0, len(MethodSet.all_methods_list) - 1)

    @staticmethod
    def _whole_range_interval_set():
        """
        :return: the interval set representing the whole range (all methods)
        """
        interval = MethodSet._whole_range_interval()
        return CanonicalIntervalSet.get_interval_set(interval.start, interval.end)

    def is_whole_range(self):
        """
        :return: True if the MethodSet contains all methods, False otherwise
        """
        return self == self._whole_range_interval_set()

    @staticmethod
    def _get_method_names_from_interval_set(interval_set):
        """
        Returns names of methods represented by a given interval set
        :param CanonicalIntervalSet interval_set: the interval set
        :return: the list of method names
        """
        res = []
        for interval in interval_set:
            assert interval.start >= 0 and interval.end < len(MethodSet.all_methods_list)
            for index in range(interval.start, interval.end + 1):
                res.append(MethodSet.all_methods_list[index])
        return res

    @staticmethod
    def _get_compl_method_names_from_interval_set(interval_set):
        """
        Returns names of methods not included in a given interval set
        :param CanonicalIntervalSet interval_set: the interval set
        :return: the list of complement method names
        """
        res = MethodSet.all_methods_list.copy()
        for method in MethodSet._get_method_names_from_interval_set(interval_set):
            res.remove(method)
        return res

    def __str__(self):
        """
        :return: Compact string representation of the MethodSet
        """
        if self.is_whole_range():
            return '*'
        if not self:
            return 'Empty'
        method_names = self._get_method_names_from_interval_set(self)
        compl_method_names = self._get_compl_method_names_from_interval_set(self)
        if len(method_names) <= len(compl_method_names):
            values_list = ', '.join(method for method in method_names)
        else:
            values_list = 'all but ' + ', '.join(method for method in compl_method_names)

        return values_list

    def copy(self):
        new_copy = copy.copy(self)
        return new_copy
