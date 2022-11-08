import unittest

from set_valued_decision_diagram.set_valued_decision_diagram import SetValuedDecisionDiagram
from nca.CoreDS.CanonicalIntervalSet import CanonicalIntervalSet
from nca.CoreDS.MinDFA import MinDFA


class SetValuedDecisionDiagramBasicTests(unittest.TestCase):
    def test_from_cube_1(self):
        cube = (
            ('x', CanonicalIntervalSet.get_interval_set(0, 10)),
        )
        s = SetValuedDecisionDiagram.from_cube(cube)
        self.assertTrue(True)

    def test_from_cube_2(self):
        cube = (
            ('x', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('y', CanonicalIntervalSet.get_interval_set(0, 10))
        )
        s = SetValuedDecisionDiagram.from_cube(cube)
        self.assertTrue(True)

    def test_from_cube_min_dfa(self):
        cube = (
            ('s', MinDFA.dfa_from_regex('abc')),
            ('t', MinDFA.dfa_from_regex('xyz')),
            ('u', CanonicalIntervalSet.get_interval_set(0, 10))
        )
        s = SetValuedDecisionDiagram.from_cube(cube),
        self.assertTrue(True)

    def test_contains_no_dont_cares(self):
        cube = (
            ('a', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('b', CanonicalIntervalSet.get_interval_set(10, 20)),
            ('c', CanonicalIntervalSet.get_interval_set(20, 30))
        )
        s = SetValuedDecisionDiagram.from_cube(cube)
        in_item = (
            ('a', 5),
            ('b', 15),
            ('c', 25)
        )
        not_in_item = (
            ('a', 9),
            ('b', 11),
            ('c', 19)
        )
        self.assertIn(in_item, s)
        self.assertNotIn(not_in_item, s)

    def test_contained_with_dont_cares(self):
        cube = (
            ('a', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('c', CanonicalIntervalSet.get_interval_set(20, 30))
        )
        s = SetValuedDecisionDiagram.from_cube(cube)
        in_item = (
            ('a', 9),
            ('b', 10),
            ('c', 24)
        )
        not_in_item = (
            ('a', 10),
            ('b', 20),
            ('c', 11)
        )
        self.assertIn(in_item, s)
        self.assertNotIn(not_in_item, s)

    def test_contained_in_single_cube_no_dont_cares(self):
        cube1 = (
            ('a', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('b', CanonicalIntervalSet.get_interval_set(10, 20)),
            ('c', CanonicalIntervalSet.get_interval_set(20, 30))
        )
        s1 = SetValuedDecisionDiagram.from_cube(cube1)

        cube2 = (
            ('a', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('b', CanonicalIntervalSet.get_interval_set(0, 20)),
            ('c', CanonicalIntervalSet.get_interval_set(20, 30))
        )
        s2 = SetValuedDecisionDiagram.from_cube(cube2)

        self.assertTrue(s1.contained_in(s1))
        self.assertTrue(s2.contained_in(s2))
        self.assertTrue(s1.contained_in(s2))
        self.assertFalse(s2.contained_in(s1))

    def test_contained_in_single_cube_with_dont_cares(self):
        cube1 = (
            ('a', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('b', CanonicalIntervalSet.get_interval_set(10, 20)),
            ('c', CanonicalIntervalSet.get_interval_set(20, 30))
        )
        s1 = SetValuedDecisionDiagram.from_cube(cube1)

        cube2 = (
            ('a', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('c', CanonicalIntervalSet.get_interval_set(20, 30))
        )
        s2 = SetValuedDecisionDiagram.from_cube(cube2)

        self.assertTrue(s1.contained_in(s1))
        self.assertTrue(s2.contained_in(s2))
        self.assertTrue(s1.contained_in(s2))
        self.assertFalse(s2.contained_in(s1))

    # TODO: some more extensive tests for contained_in, using MinDFA and complex don't care situations


if __name__ == '__main__':
    unittest.main()
