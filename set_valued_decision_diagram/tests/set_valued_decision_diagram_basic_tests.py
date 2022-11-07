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

    def test_contains(self):
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



if __name__ == '__main__':
    unittest.main()
