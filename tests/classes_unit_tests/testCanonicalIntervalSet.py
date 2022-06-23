import sys
import os

sys.path.append(
    os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), '..', 'network-config-analyzer'))

import unittest
from CanonicalIntervalSet import CanonicalIntervalSet


class TestCanonicalIntervalSetMethods(unittest.TestCase):

    def test_find_interval_left(self):
        a = CanonicalIntervalSet()
        a.interval_set = [CanonicalIntervalSet.Interval(2, 2), CanonicalIntervalSet.Interval(5, 7),
                          CanonicalIntervalSet.Interval(9, 11), CanonicalIntervalSet.Interval(16, 16)]
        res = a.find_interval_left(CanonicalIntervalSet.Interval(0, 0))
        self.assertEqual(res, -1)
        res = a.find_interval_left(CanonicalIntervalSet.Interval(0, 1))
        self.assertEqual(res, -1)
        res = a.find_interval_left(CanonicalIntervalSet.Interval(0, 2))
        self.assertEqual(res, -1)
        res = a.find_interval_left(CanonicalIntervalSet.Interval(3, 4))
        self.assertEqual(res, -1)
        res = a.find_interval_left(CanonicalIntervalSet.Interval(4, 4))
        self.assertEqual(res, 0)
        res = a.find_interval_left(CanonicalIntervalSet.Interval(4, 5))
        self.assertEqual(res, 0)
        res = a.find_interval_left(CanonicalIntervalSet.Interval(5, 5))
        self.assertEqual(res, 0)
        res = a.find_interval_left(CanonicalIntervalSet.Interval(5, 6))
        self.assertEqual(res, 0)
        res = a.find_interval_left(CanonicalIntervalSet.Interval(7, 7))
        self.assertEqual(res, 0)
        res = a.find_interval_left(CanonicalIntervalSet.Interval(8, 8))
        self.assertEqual(res, 0)
        res = a.find_interval_left(CanonicalIntervalSet.Interval(9, 9))
        self.assertEqual(res, 1)
        res = a.find_interval_left(CanonicalIntervalSet.Interval(90, 90))
        self.assertEqual(res, 3)
        res = a.find_interval_left(CanonicalIntervalSet.Interval(12, 18))
        self.assertEqual(res, 1)
        res = a.find_interval_left(CanonicalIntervalSet.Interval(13, 14))
        self.assertEqual(res, 2)
        b = CanonicalIntervalSet()
        b.interval_set = [CanonicalIntervalSet.Interval(2, 2), CanonicalIntervalSet.Interval(6, 7),
                          CanonicalIntervalSet.Interval(9, 11), CanonicalIntervalSet.Interval(16, 16)]

        res = b.find_interval_left(CanonicalIntervalSet.Interval(4, 4))
        self.assertEqual(res, 0)
        res = b.find_interval_left(CanonicalIntervalSet.Interval(4, 5))
        self.assertEqual(res, 0)
        res = b.find_interval_left(CanonicalIntervalSet.Interval(3, 5))
        self.assertEqual(res, -1)

        c = CanonicalIntervalSet()
        c.interval_set = [CanonicalIntervalSet.Interval(2, 2), CanonicalIntervalSet.Interval(6, 6),
                          CanonicalIntervalSet.Interval(11, 11), CanonicalIntervalSet.Interval(16, 16)]
        res = c.find_interval_left(CanonicalIntervalSet.Interval(12, 15))
        self.assertEqual(res, 1)
        d = CanonicalIntervalSet()
        res = d.find_interval_left(CanonicalIntervalSet.Interval(0, 0))
        self.assertEqual(res, -1)



    def test_find_interval_right(self):
        a = CanonicalIntervalSet()
        a.interval_set = [CanonicalIntervalSet.Interval(2, 2), CanonicalIntervalSet.Interval(5, 7),
                          CanonicalIntervalSet.Interval(9, 11), CanonicalIntervalSet.Interval(16, 16)]
        res = a.find_interval_right(CanonicalIntervalSet.Interval(0, 0))
        self.assertEqual(res, 0)
        res = a.find_interval_right(CanonicalIntervalSet.Interval(20, 20))
        self.assertEqual(res, -1)
        res = a.find_interval_right(CanonicalIntervalSet.Interval(17, 17))
        self.assertEqual(res, -1)
        res = a.find_interval_right(CanonicalIntervalSet.Interval(16, 17))
        self.assertEqual(res, -1)
        res = a.find_interval_right(CanonicalIntervalSet.Interval(16, 16))
        self.assertEqual(res, -1)
        res = a.find_interval_right(CanonicalIntervalSet.Interval(15, 16))
        self.assertEqual(res, -1)
        res = a.find_interval_right(CanonicalIntervalSet.Interval(15, 18))
        self.assertEqual(res, -1)
        res = a.find_interval_right(CanonicalIntervalSet.Interval(14, 14))
        self.assertEqual(res, 3)
        res = a.find_interval_right(CanonicalIntervalSet.Interval(9, 9))
        self.assertEqual(res, 3)
        res = a.find_interval_right(CanonicalIntervalSet.Interval(8, 8))
        self.assertEqual(res, 3)
        res = a.find_interval_right(CanonicalIntervalSet.Interval(12, 12))
        self.assertEqual(res, 3)
        res = a.find_interval_right(CanonicalIntervalSet.Interval(12, 15))
        self.assertEqual(res, -1)
        res = a.find_interval_right(CanonicalIntervalSet.Interval(13, 15))
        self.assertEqual(res, -1)
        res = a.find_interval_right(CanonicalIntervalSet.Interval(12, 18))
        self.assertEqual(res, -1)

    def test_add_interval_all(self):
        intervals_list = [CanonicalIntervalSet.Interval(0, 0), CanonicalIntervalSet.Interval(20, 20),
                          CanonicalIntervalSet.Interval(13, 14), CanonicalIntervalSet.Interval(13, 15),
                          CanonicalIntervalSet.Interval(13, 18), CanonicalIntervalSet.Interval(12, 18),
                          CanonicalIntervalSet.Interval(0, 1), CanonicalIntervalSet.Interval(0, 2),
                          CanonicalIntervalSet.Interval(0, 4), CanonicalIntervalSet.Interval(0, 8),
                          CanonicalIntervalSet.Interval(0, 15), CanonicalIntervalSet.Interval(0, 12),
                          CanonicalIntervalSet.Interval(0, 20), CanonicalIntervalSet.Interval(0, 3),
                          CanonicalIntervalSet.Interval(5, 8), CanonicalIntervalSet.Interval(17, 17),
                          CanonicalIntervalSet.Interval(16, 16), CanonicalIntervalSet.Interval(15, 18),
                          CanonicalIntervalSet.Interval(16, 18), CanonicalIntervalSet.Interval(8, 9),
                          CanonicalIntervalSet.Interval(8, 12)]
        for interval in intervals_list:
            self.add_interval_test(interval)

    @staticmethod
    def add_interval_old(interval_set_obj, interval_to_add):
        new_interval_set = []
        new_interval = interval_to_add.copy()  # so we don't change the original
        new_interval_added = False
        for interval in interval_set_obj.interval_set:
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
        interval_set_obj.interval_set = new_interval_set

    def add_interval_test(self, interval):
        a = CanonicalIntervalSet()
        a.add_interval(CanonicalIntervalSet.Interval(2, 2))
        a.add_interval(CanonicalIntervalSet.Interval(5, 7))
        a.add_interval(CanonicalIntervalSet.Interval(9, 11))
        a.add_interval(CanonicalIntervalSet.Interval(16, 16))
        # a.interval_set = [CanonicalIntervalSet.Interval(2, 2), CanonicalIntervalSet.Interval(5, 7), CanonicalIntervalSet.Interval(9, 11), CanonicalIntervalSet.Interval(16, 16)]
        b = a.copy()
        a.add_interval(interval)
        self.add_interval_old(b, interval)
        self.assertEqual(a, b)

    def test_contained_in(self):
        intervals_list = [CanonicalIntervalSet.get_interval_set(31, 32)]
        x = CanonicalIntervalSet.get_interval_set(31, 32)
        x.add_interval(CanonicalIntervalSet.Interval(81, 82))
        y = x.copy()
        y.add_interval(CanonicalIntervalSet.Interval(81, 88))
        intervals_list.append(x)
        intervals_list.append(y)
        intervals_list.append(CanonicalIntervalSet.get_interval_set(0, 0))
        intervals_list.append(CanonicalIntervalSet.get_interval_set(16, 16))
        for interval in intervals_list:
            self.contained_in_test(interval)

    @staticmethod
    def contained_in_old(interval_set_obj_1, interval_set_obj_2):
        for self_interval in interval_set_obj_1:
            for other_interval in interval_set_obj_2:
                if self_interval.is_subset(other_interval):
                    break
            else:  # executed if inner loop did not break, i.e., we found self_interval not in any other_interval
                return False
        return True

    def contained_in_test(self, interval):
        a = CanonicalIntervalSet()
        a.add_interval(CanonicalIntervalSet.Interval(2, 2))
        a.add_interval(CanonicalIntervalSet.Interval(5, 7))
        a.add_interval(CanonicalIntervalSet.Interval(9, 11))
        a.add_interval(CanonicalIntervalSet.Interval(16, 16))
        a.add_interval(CanonicalIntervalSet.Interval(30, 40))
        a.add_interval(CanonicalIntervalSet.Interval(80, 85))
        res1 = interval.contained_in(a)
        res2 = self.contained_in_old(interval, a)
        self.assertEqual(res1, res2)
