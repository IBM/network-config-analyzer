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


if __name__ == '__main__':
    unittest.main()
