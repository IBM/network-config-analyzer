import unittest

from smt_experiments.z3_sets.z3_integer_set import Z3IntegerSet
from smt_experiments.z3_sets.z3_product_set import Z3ProductSet


class TestZ3HyperCube(unittest.TestCase):
    def test_contains_0(self):
        dim_types = (int, int, int)
        product_set = Z3ProductSet(dim_types)
        cube = (
            Z3IntegerSet.get_interval_set(0, 100),
            Z3IntegerSet.get_interval_set(200, 300),
            Z3IntegerSet.get_interval_set(400, 500)
        )
        product_set.add_cube(cube)

        in_element = (50, 250, 450)
        self.assertTrue(in_element in product_set)

        not_in_element = (50, 250, 300)
        self.assertFalse(not_in_element in product_set)

        not_in_element = (-3, 500, 222)
        self.assertFalse(not_in_element in product_set)

    def test_contains_1(self):
        dim_types = (int, int, int)
        product_set = Z3ProductSet(dim_types)
        cube = (
            Z3IntegerSet.get_interval_set(0, 100),
            Z3IntegerSet.get_interval_set(200, 300),
            Z3IntegerSet.get_interval_set(400, 500)
        )
        product_set.add_cube(cube)

        cube = (
           Z3IntegerSet.get_interval_set(400, 500),
           Z3IntegerSet.get_interval_set(200, 300),
           Z3IntegerSet.get_interval_set(0, 100)
        )
        product_set.add_cube(cube)

        in_element = (50, 250, 450)
        self.assertTrue(in_element in product_set)

        in_element = (444, 250, 50)
        self.assertTrue(in_element in product_set)

        not_in_element = (450, 250, 450)
        self.assertFalse(not_in_element in product_set)

        not_in_element = (300, 500, 222)
        self.assertFalse(not_in_element in product_set)

    def test_contained_in(self):
        dim_types = (int, int, int)
        hyper_cube_0 = Z3ProductSet(dim_types)
        cube = (
            Z3IntegerSet.get_interval_set(0, 100),
            Z3IntegerSet.get_interval_set(200, 300),
            Z3IntegerSet.get_interval_set(400, 500)
        )
        hyper_cube_0.add_cube(cube)

        hyper_cube_1 = Z3ProductSet(dim_types)
        cube = (
            Z3IntegerSet.get_interval_set(0, 50),
            Z3IntegerSet.get_interval_set(200, 300),
            Z3IntegerSet.get_interval_set(400, 500)
        )
        hyper_cube_1.add_cube(cube)

        self.assertTrue(hyper_cube_1.contained_in(hyper_cube_0))

        hyper_cube_1 = Z3ProductSet(dim_types)
        cube = (
            Z3IntegerSet.get_interval_set(-50, 50),
            Z3IntegerSet.get_interval_set(200, 300),
            Z3IntegerSet.get_interval_set(400, 500)
        )
        hyper_cube_1.add_cube(cube)

        self.assertFalse(hyper_cube_1.contained_in(hyper_cube_0))

    def test_equal(self):
        dim_types = (int, int, int)
        hyper_cube_0 = Z3ProductSet(dim_types)
        cube = (
            Z3IntegerSet.get_interval_set(0, 100),
            Z3IntegerSet.get_interval_set(200, 300),
            Z3IntegerSet.get_interval_set(400, 500)
        )
        hyper_cube_0.add_cube(cube)

        hyper_cube_1 = Z3ProductSet(dim_types)
        cube = (
            Z3IntegerSet.get_interval_set(0, 50),
            Z3IntegerSet.get_interval_set(200, 300),
            Z3IntegerSet.get_interval_set(400, 500)
        )
        hyper_cube_1.add_cube(cube)

        self.assertNotEqual(hyper_cube_0, hyper_cube_1)

        cube = (
            Z3IntegerSet.get_interval_set(50, 100),
            Z3IntegerSet.get_interval_set(200, 300),
            Z3IntegerSet.get_interval_set(400, 500)
        )
        hyper_cube_1.add_cube(cube)
        self.assertEqual(hyper_cube_0, hyper_cube_1)


if __name__ == '__main__':
    unittest.main()
