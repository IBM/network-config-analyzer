import unittest

from nca.CoreDS.DimensionsManager import DimensionsManager
from set_valued_decision_diagram.set_valued_decision_diagram import SetValuedDecisionDiagram
from nca.CoreDS.CanonicalIntervalSet import CanonicalIntervalSet
from nca.CoreDS.MinDFA import MinDFA


def set_up_dims():
    """set up common dimensions, i0, i1, i2 and s0, s1, s2 that are integers and strings accordingly."""
    dim_manager = DimensionsManager()
    for i in range(3):
        int_dim_name = f'i{i}'
        dim_manager.set_domain(int_dim_name, DimensionsManager.DimensionType.IntervalSet)
        str_dim_name = f's{i}'
        dim_manager.set_domain(str_dim_name, DimensionsManager.DimensionType.DFA)


class SetValuedDecisionDiagramBasicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        set_up_dims()

    def test_from_cube_1(self):
        cube = (
            ('i0', CanonicalIntervalSet.get_interval_set(0, 10)),
        )
        s = SetValuedDecisionDiagram.from_cube(cube)
        self.assertTrue(True)

    def test_from_cube_2(self):
        cube = (
            ('i0', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i1', CanonicalIntervalSet.get_interval_set(0, 10))
        )
        s = SetValuedDecisionDiagram.from_cube(cube)
        self.assertTrue(True)

    def test_from_cube_min_dfa(self):
        cube = (
            ('s0', MinDFA.dfa_from_regex('abc')),
            ('s1', MinDFA.dfa_from_regex('xyz')),
            ('i2', CanonicalIntervalSet.get_interval_set(0, 10))
        )
        s = SetValuedDecisionDiagram.from_cube(cube),
        self.assertTrue(True)

    def test_contains_no_dont_cares(self):
        cube = (
            ('i0', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i1', CanonicalIntervalSet.get_interval_set(10, 20)),
            ('i2', CanonicalIntervalSet.get_interval_set(20, 30))
        )
        s = SetValuedDecisionDiagram.from_cube(cube)
        in_item = (
            ('i0', 5),
            ('i1', 15),
            ('i2', 25)
        )
        not_in_item = (
            ('i0', 9),
            ('i1', 11),
            ('i2', 19)
        )
        self.assertIn(in_item, s)
        self.assertNotIn(not_in_item, s)

    def test_contained_with_dont_cares(self):
        cube = (
            ('i0', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i2', CanonicalIntervalSet.get_interval_set(20, 30))
        )
        s = SetValuedDecisionDiagram.from_cube(cube)
        in_item = (
            ('i0', 9),
            ('i1', 10),
            ('i2', 24)
        )
        not_in_item = (
            ('i0', 10),
            ('i1', 20),
            ('i2', 11)
        )
        self.assertIn(in_item, s)
        self.assertNotIn(not_in_item, s)

    def test_contained_in_single_cube_no_dont_cares(self):
        cube1 = (
            ('i0', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i1', CanonicalIntervalSet.get_interval_set(10, 20)),
            ('i2', CanonicalIntervalSet.get_interval_set(20, 30))
        )
        s1 = SetValuedDecisionDiagram.from_cube(cube1)

        cube2 = (
            ('i0', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i1', CanonicalIntervalSet.get_interval_set(0, 20)),
            ('i2', CanonicalIntervalSet.get_interval_set(20, 30))
        )
        s2 = SetValuedDecisionDiagram.from_cube(cube2)

        self.assertTrue(s1.contained_in(s1))
        self.assertTrue(s2.contained_in(s2))
        self.assertTrue(s1.contained_in(s2))
        self.assertFalse(s2.contained_in(s1))

    def test_contained_in_single_cube_with_dont_cares(self):
        cube1 = (
            ('i0', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i1', CanonicalIntervalSet.get_interval_set(10, 20)),
            ('i2', CanonicalIntervalSet.get_interval_set(20, 30))
        )
        s1 = SetValuedDecisionDiagram.from_cube(cube1)

        cube2 = (
            ('i0', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i2', CanonicalIntervalSet.get_interval_set(20, 30))
        )
        s2 = SetValuedDecisionDiagram.from_cube(cube2)

        self.assertTrue(s1.contained_in(s1))
        self.assertTrue(s2.contained_in(s2))
        self.assertTrue(s1.contained_in(s2))
        self.assertFalse(s2.contained_in(s1))

    # TODO: some more extensive tests for contained_in, using MinDFA and complex don't care situations
    def test_union_basic_no_dont_cares(self):
        cube1 = (
            ('i0', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i1', CanonicalIntervalSet.get_interval_set(10, 20)),
            ('i2', CanonicalIntervalSet.get_interval_set(20, 30))
        )
        s1 = SetValuedDecisionDiagram.from_cube(cube1)
        cube2 = (
            ('i0', CanonicalIntervalSet.get_interval_set(100, 110)),
            ('i1', CanonicalIntervalSet.get_interval_set(110, 120)),
            ('i2', CanonicalIntervalSet.get_interval_set(120, 130))
        )
        s2 = SetValuedDecisionDiagram.from_cube(cube2)
        s = s1 | s2
        in_element = (
            ('i0', 105),
            ('i1', 115),
            ('i2', 125)
        )
        not_in_element = (
            ('i0', 5),
            ('i1', 15),
            ('i2', 125)
        )

        self.assertTrue(s1.contained_in(s))
        self.assertTrue(s2.contained_in(s))
        self.assertFalse(s.contained_in(s1))
        self.assertFalse(s.contained_in(s2))
        self.assertIn(in_element, s)
        self.assertNotIn(not_in_element, s)

    def test_union_basic_with_dont_cares(self):
        cube1 = (
            ('i0', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i1', CanonicalIntervalSet.get_interval_set(10, 20)),
            ('i2', CanonicalIntervalSet.get_interval_set(20, 30))
        )
        s1 = SetValuedDecisionDiagram.from_cube(cube1)
        cube2 = (
            ('i0', CanonicalIntervalSet.get_interval_set(0, 20)),
            ('i2', CanonicalIntervalSet.get_interval_set(120, 130))
        )
        s2 = SetValuedDecisionDiagram.from_cube(cube2)
        s = s1 | s2
        in_element1 = (
            ('i0', 5),
            ('i1', 15),
            ('i2', 25)
        )
        in_element2 = (
            ('i0', 5),
            ('i1', 100),
            ('i2', 125)
        )
        not_in_element1 = (
            ('i0', 15),
            ('i1', 15),
            ('i2', 25)
        )
        not_in_element2 = (
            ('i0', 5),
            ('i1', 25),
            ('i2', 25)
        )

        self.assertTrue(s1.contained_in(s))
        self.assertTrue(s2.contained_in(s))
        self.assertFalse(s.contained_in(s1))
        self.assertFalse(s.contained_in(s2))
        self.assertIn(in_element1, s)
        self.assertIn(in_element2, s)
        self.assertNotIn(not_in_element1, s)
        self.assertNotIn(not_in_element2, s)

    def test_intersection_basic_no_dont_cares(self):
        cube1 = (
            ('i0', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i1', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i2', CanonicalIntervalSet.get_interval_set(0, 10))
        )
        s1 = SetValuedDecisionDiagram.from_cube(cube1)
        cube2 = (
            ('i0', CanonicalIntervalSet.get_interval_set(5, 15)),
            ('i1', CanonicalIntervalSet.get_interval_set(5, 15)),
            ('i2', CanonicalIntervalSet.get_interval_set(5, 15))
        )
        s2 = SetValuedDecisionDiagram.from_cube(cube2)
        s = s1 & s2

        in_item = (
            ('i0', 10),
            ('i1', 10),
            ('i2', 10)
        )
        not_in_item1 = (
            ('i0', 2),
            ('i1', 2),
            ('i2', 2)
        )
        not_in_item2 = (
            ('i0', 12),
            ('i1', 12),
            ('i2', 12)
        )
        self.assertTrue(s.contained_in(s1))
        self.assertTrue(s.contained_in(s2))
        self.assertFalse(s1.contained_in(s))
        self.assertFalse(s2.contained_in(s))
        self.assertIn(in_item, s)
        self.assertNotIn(not_in_item1, s)
        self.assertNotIn(not_in_item2, s)

    def test_intersection_basic_with_dont_cares(self):
        cube1 = (
            ('i0', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i1', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i2', CanonicalIntervalSet.get_interval_set(0, 10))
        )
        s1 = SetValuedDecisionDiagram.from_cube(cube1)
        cube2 = (
            ('i0', CanonicalIntervalSet.get_interval_set(5, 15)),
            ('i2', CanonicalIntervalSet.get_interval_set(5, 15))
        )
        s2 = SetValuedDecisionDiagram.from_cube(cube2)
        s = s1 & s2

        in_item = (
            ('i0', 10),
            ('i1', 10),
            ('i2', 10)
        )
        not_in_item1 = (
            ('i0', 2),
            ('i1', 2),
            ('i2', 2)
        )
        not_in_item2 = (
            ('i0', 10),
            ('i1', 12),
            ('i2', 10)
        )
        self.assertTrue(s.contained_in(s1))
        self.assertTrue(s.contained_in(s2))
        self.assertFalse(s1.contained_in(s))
        self.assertFalse(s2.contained_in(s))
        self.assertIn(in_item, s)
        self.assertNotIn(not_in_item1, s)
        self.assertNotIn(not_in_item2, s)

    def test_complement_basic(self):
        cube1 = (
            ('i0', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i1', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i2', CanonicalIntervalSet.get_interval_set(0, 10))
        )
        s1 = SetValuedDecisionDiagram.from_cube(cube1)
        s = s1.complement()
        in_item = (
            ('i0', 5),
            ('i1', 12),
            ('i2', 5)
        )
        not_in_item = (
            ('i0', 5),
            ('i1', 5),
            ('i2', 5)
        )
        self.assertIn(in_item, s)
        self.assertNotIn(not_in_item, s)

    def test_subtraction_basic_no_dont_cares(self):
        # TODO
        pass

    def test_subtraction_basic_with_dont_cares(self):
        # TODO
        pass


if __name__ == '__main__':
    unittest.main()
