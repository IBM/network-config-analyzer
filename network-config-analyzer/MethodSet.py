#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from CanonicalIntervalSet import CanonicalIntervalSet
from DimensionsManager import DimensionsManager
from MinDFA import MinDFA

class MethodSet(CanonicalIntervalSet):
    """
    A class for holding a set of HTTP methods
    """
    all_methods_list = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']

    def __init__(self, methods_dfa):
        super().__init__()
        methods_list = methods_dfa._get_strings_set_str()
        index = 0
        for method in self.all_methods_list:
            if method in methods_list:
                self.add_interval(CanonicalIntervalSet.Interval(index, index))
                methods_list.remove(method)
            index = index + 1
        assert not methods_list

    def get_methods_names(self):
        res = []
        for interval in self.interval_set:
            assert interval.start >= 0 and interval.end < len(self.all_methods_list)
            for index in range(interval.start, interval.end):
                res.append(self.all_methods_list[index])
        return res
