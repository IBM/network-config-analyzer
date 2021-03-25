from CanonicalHyperCubeSet import CanonicalHyperCubeSet
from CanonicalIntervalSet import CanonicalIntervalSet
import unittest


class TestCanonicalHyperCubeSetMethods(unittest.TestCase):

    def test_eq(self):
        a = CanonicalHyperCubeSet(1)
        a.add_interval([CanonicalIntervalSet.Interval(1, 2)])
        b = CanonicalHyperCubeSet(1)
        b.add_interval([CanonicalIntervalSet.Interval(1, 2)])
        self.assertEqual(a, b)
        c = CanonicalHyperCubeSet(2)
        d = CanonicalHyperCubeSet(2)
        c.add_interval([CanonicalIntervalSet.Interval(1, 2), CanonicalIntervalSet.Interval(1, 5)])
        d.add_interval([CanonicalIntervalSet.Interval(1, 2), CanonicalIntervalSet.Interval(1, 5)])
        self.assertEqual(c, d)

    def test_contains(self):
        c = CanonicalHyperCubeSet(2)
        c.add_interval([CanonicalIntervalSet.Interval(1, 2), CanonicalIntervalSet.Interval(1, 5)])
        item = [1, 3]
        self.assertTrue(item in c)

    def test_copy(self):
        c = CanonicalHyperCubeSet(2)
        c.add_interval([CanonicalIntervalSet.Interval(1, 100), CanonicalIntervalSet.Interval(200, 300)])
        d = c.copy()
        self.assertEqual(c, d)

    def test_len(self):
        c = CanonicalHyperCubeSet(2)
        c.add_interval([CanonicalIntervalSet.Interval(1, 100), CanonicalIntervalSet.Interval(200, 300)])
        self.assertEqual(len(c), 1)
        d = CanonicalHyperCubeSet(1)
        d.add_interval([CanonicalIntervalSet.Interval(1, 2)])
        d.add_interval([CanonicalIntervalSet.Interval(4, 5)])
        d.add_interval([CanonicalIntervalSet.Interval(7, 9)])
        self.assertEqual(len(d), 3)
        c.add_interval([CanonicalIntervalSet.Interval(200, 300), CanonicalIntervalSet.Interval(200, 300)])
        self.assertEqual(len(c), 2)

    def test_apply_intervals_union(self):
        c = CanonicalHyperCubeSet(2)
        c.add_interval([CanonicalIntervalSet.Interval(1, 100), CanonicalIntervalSet.Interval(200, 300)])
        c.add_interval([CanonicalIntervalSet.Interval(101, 200), CanonicalIntervalSet.Interval(200, 300)])
        d = CanonicalHyperCubeSet(2)
        d.add_interval([CanonicalIntervalSet.Interval(1, 200), CanonicalIntervalSet.Interval(200, 300)])
        self.assertEqual(c, d)
        self.assertEqual(str(c), str(d))

    def test_apply_intervals_union_2(self):
        c = CanonicalHyperCubeSet(2)
        c.add_interval([CanonicalIntervalSet.Interval(1, 100), CanonicalIntervalSet.Interval(200, 300)])
        c.add_interval([CanonicalIntervalSet.Interval(101, 200), CanonicalIntervalSet.Interval(200, 300)])
        c.add_interval([CanonicalIntervalSet.Interval(201, 300), CanonicalIntervalSet.Interval(200, 300)])
        c.add_interval([CanonicalIntervalSet.Interval(301, 400), CanonicalIntervalSet.Interval(200, 300)])
        c.add_interval([CanonicalIntervalSet.Interval(402, 500), CanonicalIntervalSet.Interval(200, 300)])
        c.add_interval([CanonicalIntervalSet.Interval(500, 600), CanonicalIntervalSet.Interval(200, 700)])
        c.add_interval([CanonicalIntervalSet.Interval(601, 700), CanonicalIntervalSet.Interval(200, 700)])

        d = c.copy()
        d.add_interval([CanonicalIntervalSet.Interval(702, 800), CanonicalIntervalSet.Interval(200, 700)])
        c_expected = CanonicalHyperCubeSet(2)
        c_expected.add_interval([CanonicalIntervalSet.Interval(1, 400), CanonicalIntervalSet.Interval(200, 300)])
        c_expected.add_interval([CanonicalIntervalSet.Interval(402, 500), CanonicalIntervalSet.Interval(200, 300)])
        c_expected.add_interval([CanonicalIntervalSet.Interval(500, 700), CanonicalIntervalSet.Interval(200, 700)])
        d_expected = c_expected.copy()
        d_expected.add_interval([CanonicalIntervalSet.Interval(702, 800), CanonicalIntervalSet.Interval(200, 700)])
        self.assertEqual(c, c_expected)
        self.assertEqual(d, d_expected)

    def test_contained_in(self):
        c = CanonicalHyperCubeSet(2)
        d = CanonicalHyperCubeSet(2)
        c.add_interval([CanonicalIntervalSet.Interval(1, 100), CanonicalIntervalSet.Interval(200, 300)])
        d.add_interval([CanonicalIntervalSet.Interval(10, 80), CanonicalIntervalSet.Interval(210, 280)])
        self.assertTrue(d.contained_in(c))
        d.add_interval([CanonicalIntervalSet.Interval(10, 200), CanonicalIntervalSet.Interval(210, 280)])
        self.assertFalse(d.contained_in(c))

    def test_contained_in_2(self):
        a = CanonicalHyperCubeSet(2)
        c = CanonicalHyperCubeSet(2)
        d = CanonicalHyperCubeSet(2)
        e = CanonicalHyperCubeSet(2)
        f = CanonicalHyperCubeSet(2)
        f1 = CanonicalHyperCubeSet(2)
        f2 = CanonicalHyperCubeSet(2)
        c.add_interval([CanonicalIntervalSet.Interval(1, 100), CanonicalIntervalSet.Interval(200, 300)])
        c.add_interval([CanonicalIntervalSet.Interval(150, 180), CanonicalIntervalSet.Interval(20, 300)])
        c.add_interval([CanonicalIntervalSet.Interval(200, 240), CanonicalIntervalSet.Interval(200, 300)])
        c.add_interval([CanonicalIntervalSet.Interval(241, 300), CanonicalIntervalSet.Interval(200, 350)])

        a.add_interval([CanonicalIntervalSet.Interval(1, 100), CanonicalIntervalSet.Interval(200, 300)])
        a.add_interval([CanonicalIntervalSet.Interval(150, 180), CanonicalIntervalSet.Interval(20, 300)])
        a.add_interval([CanonicalIntervalSet.Interval(200, 240), CanonicalIntervalSet.Interval(200, 300)])
        a.add_interval([CanonicalIntervalSet.Interval(242, 300), CanonicalIntervalSet.Interval(200, 350)])

        d.add_interval([CanonicalIntervalSet.Interval(210, 220), CanonicalIntervalSet.Interval(210, 280)])
        e.add_interval([CanonicalIntervalSet.Interval(210, 310), CanonicalIntervalSet.Interval(210, 280)])
        f.add_interval([CanonicalIntervalSet.Interval(210, 250), CanonicalIntervalSet.Interval(210, 280)])
        f1.add_interval([CanonicalIntervalSet.Interval(210, 240), CanonicalIntervalSet.Interval(210, 280)])
        f2.add_interval([CanonicalIntervalSet.Interval(241, 250), CanonicalIntervalSet.Interval(210, 280)])

        self.assertTrue(d.contained_in(c))
        self.assertFalse(e.contained_in(c))
        self.assertTrue(f1.contained_in(c))
        self.assertTrue(f2.contained_in(c))
        self.assertTrue(f.contained_in(c))
        self.assertFalse(f.contained_in(a))

    def test_overlaps(self):
        c = CanonicalHyperCubeSet(2)
        d = CanonicalHyperCubeSet(2)
        c.add_interval([CanonicalIntervalSet.Interval(1, 100), CanonicalIntervalSet.Interval(200, 300)])
        d.add_interval([CanonicalIntervalSet.Interval(10, 200), CanonicalIntervalSet.Interval(210, 280)])
        self.assertTrue(d.overlaps(c))

    def test_bool(self):
        a = CanonicalHyperCubeSet(1)
        self.assertFalse(bool(a))
        b = CanonicalHyperCubeSet(1)
        b.add_interval([CanonicalIntervalSet.Interval(1, 2)])
        self.assertTrue(bool(b))
        c = CanonicalHyperCubeSet(2)
        self.assertFalse(bool(c))
        d = CanonicalHyperCubeSet(2)
        d.add_interval([CanonicalIntervalSet.Interval(10, 200), CanonicalIntervalSet.Interval(210, 280)])
        self.assertTrue(bool(d))

    def test_or_2(self):
        a = CanonicalHyperCubeSet(2)
        a.add_interval([CanonicalIntervalSet.Interval(80, 100), CanonicalIntervalSet.Interval(10053, 10053)])
        b = CanonicalHyperCubeSet(2)
        b.add_interval([CanonicalIntervalSet.Interval(1, 65536), CanonicalIntervalSet.Interval(10054, 10054)])
        a |= b
        expected_res = CanonicalHyperCubeSet(2)
        expected_res.add_interval([CanonicalIntervalSet.Interval(1, 79), CanonicalIntervalSet.Interval(10054, 10054)])
        expected_res.add_interval([CanonicalIntervalSet.Interval(80, 100), CanonicalIntervalSet.Interval(10053, 10054)])
        expected_res.add_interval([CanonicalIntervalSet.Interval(101, 65536),
                                   CanonicalIntervalSet.Interval(10054, 10054)])
        self.assertEqual(a, expected_res)

    def test_and_sub_or(self):
        a = CanonicalHyperCubeSet(2)
        a.add_interval([CanonicalIntervalSet.Interval(5, 15), CanonicalIntervalSet.Interval(3, 10)])
        b = CanonicalHyperCubeSet(2)
        b.add_interval([CanonicalIntervalSet.Interval(8, 30), CanonicalIntervalSet.Interval(7, 20)])
        c = a & b
        d = CanonicalHyperCubeSet(2)
        d.add_interval([CanonicalIntervalSet.Interval(8, 15), CanonicalIntervalSet.Interval(7, 10)])
        self.assertEqual(c, d)
        f = a | b
        e = CanonicalHyperCubeSet(2)
        e.add_interval([CanonicalIntervalSet.Interval(5, 15), CanonicalIntervalSet.Interval(3, 6)])
        e.add_interval([CanonicalIntervalSet.Interval(5, 30), CanonicalIntervalSet.Interval(7, 10)])
        e.add_interval([CanonicalIntervalSet.Interval(8, 30), CanonicalIntervalSet.Interval(11, 20)])
        self.assertEqual(e, f)
        # print(f)
        # print(e)
        g = a - b
        h = CanonicalHyperCubeSet(2)
        h.add_interval([CanonicalIntervalSet.Interval(5, 7), CanonicalIntervalSet.Interval(3, 10)])
        h.add_interval([CanonicalIntervalSet.Interval(8, 15), CanonicalIntervalSet.Interval(3, 6)])
        # print(g)
        # print(h)
        self.assertEqual(g, h)

    def test_add_interval(self):
        a = CanonicalHyperCubeSet(2)
        a.add_interval([CanonicalIntervalSet.Interval(5, 15), CanonicalIntervalSet.Interval(3, 10)])
        a.add_interval([CanonicalIntervalSet.Interval(5, 15), CanonicalIntervalSet.Interval(11, 20)])

        b = CanonicalHyperCubeSet(2)
        b.add_interval([CanonicalIntervalSet.Interval(5, 15), CanonicalIntervalSet.Interval(3, 20)])
        self.assertEqual(a, b)

        a.add_interval([CanonicalIntervalSet.Interval(16, 40), CanonicalIntervalSet.Interval(3, 20)])
        b = CanonicalHyperCubeSet(2)
        b.add_interval([CanonicalIntervalSet.Interval(5, 40), CanonicalIntervalSet.Interval(3, 20)])
        self.assertEqual(a, b)

        a.add_interval([CanonicalIntervalSet.Interval(20, 40), CanonicalIntervalSet.Interval(3, 20)])
        self.assertEqual(a, b)

        a.add_interval([CanonicalIntervalSet.Interval(20, 40), CanonicalIntervalSet.Interval(10, 30)])
        b.add_interval([CanonicalIntervalSet.Interval(20, 40), CanonicalIntervalSet.Interval(21, 30)])
        self.assertEqual(a, b)

    def test_add_hole(self):
        c = CanonicalHyperCubeSet(2)
        c.add_interval([CanonicalIntervalSet.Interval(1, 100), CanonicalIntervalSet.Interval(200, 300)])
        c.add_hole([CanonicalIntervalSet.Interval(50, 60), CanonicalIntervalSet.Interval(220, 300)])
        d = CanonicalHyperCubeSet(2)
        d.add_interval([CanonicalIntervalSet.Interval(1, 49), CanonicalIntervalSet.Interval(200, 300)])
        d.add_interval([CanonicalIntervalSet.Interval(50, 60), CanonicalIntervalSet.Interval(200, 219)])
        d.add_interval([CanonicalIntervalSet.Interval(61, 100), CanonicalIntervalSet.Interval(200, 300)])
        self.assertEqual(c, d)

    def test_add_hole_2(self):
        c = CanonicalHyperCubeSet(2)
        c.add_interval([CanonicalIntervalSet.Interval(80, 100), CanonicalIntervalSet.Interval(20, 300)])
        c.add_interval([CanonicalIntervalSet.Interval(250, 400), CanonicalIntervalSet.Interval(20, 300)])
        c.add_hole([CanonicalIntervalSet.Interval(30, 300), CanonicalIntervalSet.Interval(100, 102)])
        d = CanonicalHyperCubeSet(2)
        d.add_interval([CanonicalIntervalSet.Interval(80, 100), CanonicalIntervalSet.Interval(20, 99)])
        d.add_interval([CanonicalIntervalSet.Interval(80, 100), CanonicalIntervalSet.Interval(103, 300)])
        d.add_interval([CanonicalIntervalSet.Interval(250, 300), CanonicalIntervalSet.Interval(20, 99)])
        d.add_interval([CanonicalIntervalSet.Interval(250, 300), CanonicalIntervalSet.Interval(103, 300)])
        d.add_interval([CanonicalIntervalSet.Interval(301, 400), CanonicalIntervalSet.Interval(20, 300)])
        self.assertEqual(c, d)

    def test_contained_in_3(self):
        a = CanonicalHyperCubeSet(2)
        a.add_interval([CanonicalIntervalSet.Interval(105, 105), CanonicalIntervalSet.Interval(54, 54)])
        b = CanonicalHyperCubeSet(2)
        b.add_interval([CanonicalIntervalSet.Interval(0, 204), CanonicalIntervalSet.Interval(0, 255)])
        b.add_interval([CanonicalIntervalSet.Interval(205, 205), CanonicalIntervalSet.Interval(0, 53)])
        b.add_interval([CanonicalIntervalSet.Interval(205, 205), CanonicalIntervalSet.Interval(55, 255)])
        b.add_interval([CanonicalIntervalSet.Interval(206, 254), CanonicalIntervalSet.Interval(0, 255)])
        res = a.contained_in(b)
        self.assertTrue(res)


if __name__ == '__main__':
    unittest.main()
