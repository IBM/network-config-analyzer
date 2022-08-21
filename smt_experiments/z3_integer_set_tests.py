import unittest
from smt_experiments.z3_integer_set import Z3IntegerSet


class TestZ3IntegerSetBasic(unittest.TestCase):
    def test_get_interval_set(self):
        z3_set = Z3IntegerSet.get_interval_set(0, 100)
        self.assertIsNotNone(z3_set)

    def test_contains(self):
        z3_set = Z3IntegerSet.get_interval_set(0, 100)
        self.assertIn(10, z3_set)
        self.assertNotIn(200, z3_set)

    def test_contained_in(self):
        z3_set_1 = Z3IntegerSet.get_interval_set(0, 100)
        z3_set_2 = Z3IntegerSet.get_interval_set(10, 90)
        z3_set_3 = Z3IntegerSet.get_interval_set(-10, 90)

        self.assertTrue(z3_set_2.contained_in(z3_set_1))
        self.assertFalse(z3_set_1.contained_in(z3_set_2))

        self.assertFalse(z3_set_1.contained_in(z3_set_3))
        self.assertFalse(z3_set_3.contained_in(z3_set_1))

        self.assertTrue(z3_set_2.contained_in(z3_set_3))
        self.assertFalse(z3_set_3.contained_in(z3_set_2))

    def test_eq(self):
        z3_set_1 = Z3IntegerSet.get_interval_set(0, 100)
        z3_set_2 = Z3IntegerSet.get_interval_set(50, 90)
        z3_set_3 = Z3IntegerSet.get_interval_set(50, 90)

        self.assertFalse(z3_set_1 == z3_set_2)
        self.assertFalse(z3_set_1 == z3_set_3)
        self.assertTrue(z3_set_2 == z3_set_3)

    def test_iand(self):
        z3_set_1 = Z3IntegerSet.get_interval_set(50, 100)
        z3_set_2 = Z3IntegerSet.get_interval_set(0, 55)
        intersection = Z3IntegerSet.get_interval_set(50, 55)

        z3_set_1 &= z3_set_2

        self.assertEqual(intersection, z3_set_1)

    def test_ior(self):
        z3_set_1 = Z3IntegerSet.get_interval_set(50, 100)
        z3_set_2 = Z3IntegerSet.get_interval_set(0, 55)
        union = Z3IntegerSet.get_interval_set(0, 100)

        z3_set_1 |= z3_set_2

        self.assertEqual(union, z3_set_1)

    def test_isub(self):
        z3_set_1 = Z3IntegerSet.get_interval_set(50, 100)
        z3_set_2 = Z3IntegerSet.get_interval_set(0, 55)
        difference = Z3IntegerSet.get_interval_set(56, 100)

        z3_set_1 -= z3_set_2

        self.assertEqual(difference, z3_set_1)

    def test_copy(self):
        z3_set_1 = Z3IntegerSet.get_interval_set(50, 100)
        z3_set_1_copy = z3_set_1.copy()
        z3_set_2 = Z3IntegerSet.get_interval_set(0, 55)
        copy = Z3IntegerSet.get_interval_set(50, 100)

        z3_set_1 -= z3_set_2

        self.assertEqual(copy, z3_set_1_copy)


if __name__ == '__main__':
    unittest.main()
