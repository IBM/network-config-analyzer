#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from CanonicalIntervalSet import CanonicalIntervalSet

class MethodSet(CanonicalIntervalSet):
    """
    A class for holding a set of HTTP methods
    """
    all_methods_list = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']

    def __init__(self, all_methods=False):
        super().__init__()
        if all_methods: # the whole range
            self.add_interval(self.whole_range_interval())

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
    def get_interval_from_method_name(method):
        index = MethodSet.all_methods_list.index(method) if MethodSet.all_methods_list.count(method) > 0 else -1
        return CanonicalIntervalSet.Interval(index, index)

    @staticmethod
    def get_method_names_from_interval_set(interval_set):
        res = []
        for interval in interval_set:
            assert interval.start >= 0 and interval.end < len(MethodSet.all_methods_list)
            for index in range(interval.start, interval.end+1):
                res.append(MethodSet.all_methods_list[index])
        return res
    @staticmethod

    def get_compl_method_names_from_interval_set(interval_set):
        res = MethodSet.all_methods_list.copy()
        for method in MethodSet.get_method_names_from_interval_set(interval_set):
            res.remove(method)
        return res

    def get_methods_names(self):
        return MethodSet.get_method_names_from_interval_set(self)
