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
        return self.__str__()

    def __contains__(self, item):
        item_interval_set = CanonicalIntervalSet.get_interval_set(item, item)
        return item_interval_set.contained_in(self)

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

        if len(self) == 1 and len(other) == 1:
            return self.interval_set[0].is_subset(other.interval_set[0])
        for self_interval in self.interval_set:
            left = other.find_interval_left(self_interval)
            if left == len(other.interval_set) - 1:
                return False  # all intervals are lower than self_interval
            # the first interval which is not lower than self_interval has to fully contain self_interval
            if not self_interval.is_subset(other.interval_set[left + 1]):
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
            return self.start < other.start or (self.start == other.start and self.end < other.end)

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

    def find_interval_left(self, interval):
        """
        find from left to right the last interval which is lower than the input interval,
        without overlapping/touching it
        :param CanonicalIntervalSet.Interval interval: the input interval to search for
        :return: the index of the interval in the interval set if found or -1 if not found
        :rtype: int
        """
        if not self:
            return -1
        low = 0
        high = len(self.interval_set)
        while low != high:
            mid = (low + high) // 2
            if self.interval_set[mid].end < interval.start - 1:
                if mid == len(self.interval_set) - 1 or self.interval_set[mid + 1].end >= interval.start - 1:
                    return mid
                low = mid + 1
            else:
                high = mid
        if low == len(self.interval_set):
            low -= 1
        if self.interval_set[low].end >= interval.start - 1:
            return -1  # there is no such interval in self
        return low

    def find_interval_right(self, interval):
        """
        find from right to left the last interval which is higher than the input interval,
        without overlapping/touching it
        :param CanonicalIntervalSet.Interval interval: the input interval to search for
        :return: the index of the interval in the interval set if found or -1 if not found
        :rtype: int
        """
        if not self:
            return -1
        low = 0
        high = len(self.interval_set)
        while low != high:
            mid = (low + high) // 2
            if self.interval_set[mid].start > interval.end + 1:
                if mid == 0 or self.interval_set[mid - 1].start <= interval.end + 1:
                    return mid
                high = mid
            else:
                low = mid + 1
        if low == len(self.interval_set):
            low -= 1
        if self.interval_set[low].start <= interval.end + 1:
            return -1  # there is no such interval in self
        return low

    def add_interval(self, interval_to_add):
        """
        Add an interval to the set of intervals, while keeping the canonicity of the set
        :param CanonicalIntervalSet.Interval interval_to_add: The interval to add
        :return: None
        """
        if not self:
            self.interval_set.append(interval_to_add)
            return
        left = self.find_interval_left(interval_to_add)
        right = self.find_interval_right(interval_to_add)

        # interval_to_add has no overlapping/touching intervals between left to right
        if left >= 0 and right >= 0 and right - left == 1:
            self.interval_set.insert(left + 1, interval_to_add)
            return

        # interval_to_add has no overlapping/touching intervals and is smaller than first interval
        if left == -1 and right == 0:
            self.interval_set.insert(0, interval_to_add)
            return

        # interval_to_add has no overlapping/touching intervals and is greater than last interval
        if right == -1 and left == len(self.interval_set) - 1:
            self.interval_set.append(interval_to_add)
            return

        # update left/right indexes to be the first potential overlapping/touching intervals from left/right
        left += 1
        right = right - 1 if right >= 0 else len(self.interval_set) - 1
        # check which of left/right is overlapping/touching interval_to_add
        left_overlaps = self.interval_set[left].overlaps(interval_to_add) or self.interval_set[left].touches(
            interval_to_add)
        right_overlaps = self.interval_set[right].overlaps(interval_to_add) or self.interval_set[right].touches(
            interval_to_add)
        # the interval_to_add has to be "merged" with overlapping/touching intervals
        new_interval_start = min(interval_to_add.start,
                                 self.interval_set[left].start) if left_overlaps else interval_to_add.start
        new_interval_end = max(interval_to_add.end,
                               self.interval_set[right].end) if right_overlaps else interval_to_add.end
        new_interval = CanonicalIntervalSet.Interval(new_interval_start, new_interval_end)
        del self.interval_set[left:right + 1]
        self.interval_set.insert(left, new_interval)

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
