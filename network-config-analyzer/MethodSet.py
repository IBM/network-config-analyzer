#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from CanonicalIntervalSet import CanonicalIntervalSet
from MinDFA import MinDFA

class MethodSet(CanonicalIntervalSet):
    """
    A class for holding a set of HTTP methods
    """
    all_methods_list = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']

    def __init__(self, methods_dfa=None):
        super().__init__()
        if not methods_dfa: # the whole range
            self.add_interval(self.whole_range_interval())
            return
        index = 0
        for method in MethodSet.all_methods_list:
            if method in methods_dfa:
                self.add_interval(CanonicalIntervalSet.Interval(index, index))
            index = index + 1

    @staticmethod
    def all_methods_regex():
        return "|".join(method for method in MethodSet.all_methods_list)

    @staticmethod
    def whole_range_interval():
        return CanonicalIntervalSet.Interval(0, len(MethodSet.all_methods_list)-1)

    @staticmethod
    def whole_range_interval_set():
        interval = MethodSet.whole_range_interval()
        return CanonicalIntervalSet.get_interval_set(interval.start, interval.end)

    def is_whole_range(self):
        return self == self.whole_range_interval_set()

    @staticmethod
    def get_method_names_from_interval_set(interval_set):
        res = []
        for interval in interval_set:
            assert interval.start >= 0 and interval.end < len(MethodSet.all_methods_list)
            for index in range(interval.start, interval.end+1):
                res.append(MethodSet.all_methods_list[index])
        return res

    def get_methods_names(self):
        return MethodSet.get_method_names_from_interval_set(self)
