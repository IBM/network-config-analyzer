import unittest

from smt_experiments.z3_hyper_cube import Z3HyperCube


class TestZ3HyperCube(unittest.TestCase):
    def test_contains_0(self):
        dimension_names = ['a', 'b', 'c']
        hyper_cube = Z3HyperCube(dimension_names)
        cube = {'a': (0, 100), 'b': (200, 300), 'c': (400, 500)}
        hyper_cube.add_cube(cube)

        in_element = {'a': 50, 'b': 250, 'c': 450}
        self.assertTrue(in_element in hyper_cube)

        not_in_element = {'a': 50, 'b': 250, 'c': 300}
        self.assertFalse(not_in_element in hyper_cube)

        not_in_element = {'a': -3, 'b': 500, 'c': 222}
        self.assertFalse(not_in_element in hyper_cube)

    def test_contains_1(self):
        dimension_names = ['a', 'b', 'c']
        hyper_cube = Z3HyperCube(dimension_names)
        cube = {'a': (0, 100), 'b': (200, 300), 'c': (400, 500)}
        hyper_cube.add_cube(cube)

        cube = {'a': (400, 500), 'b': (200, 300), 'c': (0, 100)}
        hyper_cube.add_cube(cube)

        in_element = {'a': 50, 'b': 250, 'c': 450}
        self.assertTrue(in_element in hyper_cube)

        in_element = {'a': 444, 'b': 250, 'c': 50}
        self.assertTrue(in_element in hyper_cube)

        not_in_element = {'a': 450, 'b': 250, 'c': 450}
        self.assertFalse(not_in_element in hyper_cube)

        not_in_element = {'a': 300, 'b': 500, 'c': 222}
        self.assertFalse(not_in_element in hyper_cube)

    def test_contains_2(self):
        dimension_names = ['a', 'b', 'c']
        hyper_cube = Z3HyperCube(dimension_names)
        cube = {'a': (0, 100), 'b': (200, 300), 'c': (400, 500)}
        hyper_cube.add_cube(cube)

        cube = {'a': (50, 60), 'b': (250, 260), 'c': (450, 460)}
        hyper_cube.subtract_cube(cube)

        in_element = {'a': 45, 'b': 245, 'c': 445}
        self.assertTrue(in_element in hyper_cube)

        not_in_element = {'a': 450, 'b': 250, 'c': 450}
        self.assertFalse(not_in_element in hyper_cube)

        not_in_element = {'a': 55, 'b': 255, 'c': 455}
        self.assertFalse(not_in_element in hyper_cube)

    def test_contained_in(self):
        dimension_names = ['a', 'b', 'c']
        hyper_cube_0 = Z3HyperCube(dimension_names)
        cube = {'a': (0, 100), 'b': (200, 300), 'c': (400, 500)}
        hyper_cube_0.add_cube(cube)

        hyper_cube_1 = Z3HyperCube(dimension_names)
        cube = {'a': (0, 50), 'b': (200, 300), 'c': (400, 500)}
        hyper_cube_1.add_cube(cube)

        self.assertTrue(hyper_cube_1.contained_in(hyper_cube_0))

        hyper_cube_1 = Z3HyperCube(dimension_names)
        cube = {'a': (-50, 50), 'b': (200, 300), 'c': (400, 500)}
        hyper_cube_1.add_cube(cube)

        self.assertFalse(hyper_cube_1.contained_in(hyper_cube_0))

    def test_equal(self):
        dimension_names = ['a', 'b', 'c']
        hyper_cube_0 = Z3HyperCube(dimension_names)
        cube = {'a': (0, 100), 'b': (200, 300), 'c': (400, 500)}
        hyper_cube_0.add_cube(cube)

        hyper_cube_1 = Z3HyperCube(dimension_names)
        cube = {'a': (0, 50), 'b': (200, 300), 'c': (400, 500)}
        hyper_cube_1.add_cube(cube)

        self.assertNotEqual(hyper_cube_0, hyper_cube_1)

        cube = {'a': (50, 100), 'b': (200, 300), 'c': (400, 500)}
        hyper_cube_1.add_cube(cube)
        self.assertEqual(hyper_cube_0, hyper_cube_1)


if __name__ == '__main__':
    unittest.main()
