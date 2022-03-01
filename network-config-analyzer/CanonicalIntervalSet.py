#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

class CanonicalIntervalSet:
    """
    This class provides canonical representation for a set of intervals (e.g., ip ranges, ports), allowing comparison.
    This representation is defined by a sorted array interval_set, where each interval is a pair <start, end>.
    In addition no two intervals in interval_set overlap/touch. Formally:
       foreach <s1, e1>, <s2, e2> in interval_set: either e1+1 < s2 OR e2+1 < s1
    """

    def __init__(self):
        self.interval_set = []

    def __bool__(self):
        return bool(self.interval_set)

    def __eq__(self, other):
        if isinstance(other, CanonicalIntervalSet):
            return self.interval_set == other.interval_set
        return False

    def __len__(self):
        return len(self.interval_set)

    def __lt__(self, other):
        return self.interval_set < other.interval_set

    def __hash__(self):
        return hash(frozenset(self.interval_set))

    def __iter__(self):
        return iter(self.interval_set)

    def __str__(self):
        if not self.interval_set:
            return "Empty"
        res = ''
        for interval in self.interval_set:
            res += str(interval.start)
            if interval.start != interval.end:
                res += '-' + str(interval.end)
            res += ','
        return res[0:-1]

    def __repr__(self):
        if not self.interval_set:
            return "Empty"
        res = ''
        for interval in self.interval_set:
            res += str(interval.start)
            if interval.start != interval.end:
                res += '-' + str(interval.end)
            res += ','
        return res[0:-1]

    def __contains__(self, item):
        for interval in self.interval_set:
            if item in interval:
                return True
        return False

    def __and__(self, other):
        res = self.__class__()
        for self_interval in self.interval_set:
            for other_interval in other.interval_set:
                res.interval_set += self_interval & other_interval
        return res

    def __or__(self, other):
        res = self.copy()
        res |= other
        return res

    def __sub__(self, other):
        res = self.copy()
        res -= other
        return res

    def __iand__(self, other):
        new_interval_set = []
        for self_interval in self.interval_set:
            for other_interval in other.interval_set:
                new_interval_set += self_interval & other_interval
        self.interval_set = new_interval_set
        return self

    def __ior__(self, other):
        for interval in other.interval_set:
            self.add_interval(interval)
        return self

    def __isub__(self, other):
        for interval in other.interval_set:
            self.add_hole(interval)
        return self

    def copy(self):
        """
        :return: A deep copy of self
        :rtype: CanonicalIntervalSet
        """
        res = CanonicalIntervalSet()
        for interval in self.interval_set:
            res.interval_set.append(interval.copy())
        return res

    def contained_in(self, other):
        """
        :param CanonicalIntervalSet other: another interval set
        :return: Whether every internal in 'self' is contained in an interval in 'other'
        :rtype: bool
        """
        for self_interval in self.interval_set:
            for other_interval in other.interval_set:
                if self_interval.is_subset(other_interval):
                    break
            else:  # executed if inner loop did not break, i.e., we found self_interval not in any other_interval
                return False
        return True

    def overlaps(self, other):
        """
        :param CanonicalIntervalSet other: another interval set
        :return: Whether any internal in 'self' overlaps with an interval in 'other'
        :rtype: bool
        """
        for self_interval in self.interval_set:
            for other_interval in other.interval_set:
                if self_interval.overlaps(other_interval):
                    return True
        return False

    def rep(self):
        """
        :return: A representative element in the interval set (the first element in the first interval)
        """
        return self.interval_set[0].start

    class Interval:
        """
        A class representing a single interval.
        start and end should be of any type that supports equality and lt operators as well as '+1' and '-1'
        """

        def __init__(self, start, end):
            self.start = start
            self.end = end

        def __eq__(self, other):
            return self.start == other.start and self.end == other.end

        def __lt__(self, other):
            return self.start < other.start or \
                (self.start == other.start and self.end < other.end)

        def __hash__(self):
            return hash((self.start, self.end))

        def __contains__(self, item):
            return self.start <= item <= self.end

        def __str__(self):
            return '[' + str(self.start) + '-' + str(self.end) + ']'

        def __and__(self, other):  # Note: returns a list to be compatible with __or__ and __sub__
            max_start = max(self.start, other.start)
            min_end = min(self.end, other.end)
            if min_end < max_start:
                return []
            return [CanonicalIntervalSet.Interval(max_start, min_end)]

        def __or__(self, other):  # Note: returns a list with up to 2 intervals
            if self.is_subset(other):
                return [other.copy()]
            if other.is_subset(self):
                return [self.copy()]
            if self.overlaps(other) or self.touches(other):
                min_start = min(self.start, other.start)
                max_end = max(self.end, other.end)
                return [CanonicalIntervalSet.Interval(min_start, max_end)]
            return [self.copy(), other.copy()]

        def __sub__(self, other):  # Note: returns a list with up to 2 intervals
            if not self.overlaps(other):
                return [self]
            if self.is_subset(other):
                return []
            if self.start < other.start and self.end > other.end:  # self is split into two ranges by other
                return [CanonicalIntervalSet.Interval(self.start, other.start - 1),
                        CanonicalIntervalSet.Interval(other.end + 1, self.end)]
            if self.start < other.start:
                return [CanonicalIntervalSet.Interval(self.start, min(self.end, other.start - 1))]
            return [CanonicalIntervalSet.Interval(max(self.start, other.end + 1), self.end)]

        def copy(self):
            """
            :return: A shallow copy of self
            :rtype: CanonicalIntervalSet.Interval
            """
            return CanonicalIntervalSet.Interval(self.start, self.end)

        def overlaps(self, other):
            """
            :param other: another interval
            :return: Whether the two intervals overlap
            :rtype: bool
            """
            return other.end >= self.start and other.start <= self.end

        def touches(self, other):
            """
            :param other: another interval
            :return: Whether the two intervals touch each other (without overlapping)
            :rtype: bool
            """
            if self.start > other.end:
                return self.start == other.end + 1
            if other.start > self.end:
                return other.start == self.end + 1
            return False

        def is_subset(self, other):
            """
            :param other: another interval
            :return: Whether 'self' is a subset of 'other'
            :rtype: bool
            """
            return other.start <= self.start and other.end >= self.end

    def add_interval(self, interval_to_add):
        """
        Add an interval to the set of intervals, while keeping the canonicity of the set
        :param CanonicalIntervalSet.Interval interval_to_add: The interval to add
        :return: None
        """
        new_interval_set = []
        new_interval = interval_to_add.copy()  # so we don't change the original
        new_interval_added = False
        for interval in self.interval_set:
            if not new_interval_added and (new_interval.overlaps(interval) or new_interval.touches(interval)):
                # new_interval "swallows" existing interval (and will replace it)
                new_interval = (interval | new_interval)[0]
            else:
                if not new_interval_added and new_interval.end < interval.start:
                    new_interval_set.append(new_interval)
                    new_interval_added = True
                new_interval_set.append(interval)
        if not new_interval_added:
            new_interval_set.append(new_interval)
        self.interval_set = new_interval_set

    def add_hole(self, hole):
        """
        Remove all values represented by the hole interval, while keeping the canonicity of the set
        :param CanonicalIntervalSet.Interval hole: The range of values to remove
        :return: None
        """
        new_interval_set = []
        for interval in self.interval_set:
            new_interval_set += (interval - hole)
        self.interval_set = new_interval_set

    @staticmethod
    def get_interval_set(start, end):
        """
        create a CanonicalIntervalSet object with a single interval as given by input
        :param start: the input interval start point
        :param end: the input interval end point
        :return: CanonicalIntervalSet object with one interval: [start, end]
        """
        res = CanonicalIntervalSet()
        interval = CanonicalIntervalSet.Interval(start, end)
        res.add_interval(interval)
        return res

    def get_interval_set_list_numbers_and_ranges(self):
        """
        get a list representation of self which may contain int values (for single numbers) and
        str values (for ranges)
        :return: list of intervals strings or int values from self
        :rtype: list
        """
        res = []
        for interval in self:
            if interval.start == interval.end:
                res.append(interval.start)
            else:
                res.append(f'{interval.start}-{interval.end}')
        return res
