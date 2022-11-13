import unittest

from nca.CoreDS.DimensionsManager import DimensionsManager
from decision_diagram.set_valued_decision_diagram import SetValuedDecisionDiagram
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

    def test_contains_no_dont_care(self):
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

    def test_contained_with_dont_care(self):
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

    def test_contained_in_no_dont_care(self):
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

    def test_contained_in_with_dont_care_in_self(self):
        cube1 = (
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
        i0_complement = DimensionsManager().get_dimension_domain_by_name('i0') - \
                        CanonicalIntervalSet.get_interval_set(0, 10)
        cube3 = (
            ('i0', i0_complement),
            ('i1', CanonicalIntervalSet.get_interval_set(10, 30)),
            ('i2', CanonicalIntervalSet.get_interval_set(20, 30))
        )
        s3 = SetValuedDecisionDiagram.from_cube(cube3)
        s4 = s2 | s3

        self.assertTrue(s1.contained_in(s4))
        self.assertFalse(s4.contained_in(s1))
        self.assertTrue(s2.contained_in(s4))
        self.assertFalse(s4.contained_in(s2))
        self.assertTrue(s3.contained_in(s4))
        self.assertFalse(s4.contained_in(s3))
        self.assertFalse(s1.contained_in(s3))
        self.assertFalse(s3.contained_in(s1))

    def test_contained_in_with_dont_care_in_other(self):
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

    def test_union_basic_no_dont_care(self):
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

    def test_union_basic_with_dont_care(self):
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

    def test_intersection_basic_no_dont_care(self):
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

    def test_intersection_basic_with_dont_care(self):
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

    def test_complement_basic_with_dont_care(self):
        cube1 = (
            ('i0', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i2', CanonicalIntervalSet.get_interval_set(0, 10))
        )
        s1 = SetValuedDecisionDiagram.from_cube(cube1)
        cube2 = (
            ('i1', CanonicalIntervalSet.get_interval_set(5, 15)),
            ('i2', CanonicalIntervalSet.get_interval_set(5, 15))
        )
        s2 = SetValuedDecisionDiagram.from_cube(cube2)
        s = s1 | s2
        s_complement = s.complement()
        all_s = s | s_complement
        empty_s = s & s_complement
        in_item1 = (
            ('i0', 12),
            ('i1', 10),
            ('i2', 2)
        )
        in_item2 = (
            ('i0', 2),
            ('i1', 2),
            ('i2', 12)
        )
        in_item3 = (
            ('i0', 20),
            ('i1', 20),
            ('i2', 20)
        )
        not_in_item1 = (
            ('i0', 10),
            ('i1', 10),
            ('i2', 10)
        )
        not_in_item2 = (
            ('i0', 100),
            ('i1', 12),
            ('i2', 12)
        )
        not_in_item3 = (
            ('i0', 4),
            ('i1', 100),
            ('i2', 4)
        )

        self.assertTrue(all_s.is_all())
        self.assertTrue(empty_s.is_empty())
        self.assertFalse(s_complement.contained_in(s))
        self.assertFalse(s.contained_in(s_complement))
        self.assertIn(in_item1, s_complement)
        self.assertIn(in_item2, s_complement)
        self.assertIn(in_item3, s_complement)
        self.assertNotIn(not_in_item1, s_complement)
        self.assertNotIn(not_in_item2, s_complement)
        self.assertNotIn(not_in_item3, s_complement)

    def test_subtraction_basic_no_dont_care(self):
        cube1 = (
            ('i0', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i1', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i2', CanonicalIntervalSet.get_interval_set(0, 10))
        )
        s1 = SetValuedDecisionDiagram.from_cube(cube1)
        cube2 = (
            ('i0', CanonicalIntervalSet.get_interval_set(0, 2)),
            ('i1', CanonicalIntervalSet.get_interval_set(3, 5)),
            ('i2', CanonicalIntervalSet.get_interval_set(6, 8))
        )
        s2 = SetValuedDecisionDiagram.from_cube(cube2)
        s = s1 - s2
        in_item1 = (
            ('i0', 1),
            ('i1', 4),
            ('i2', 5)
        )
        in_item2 = (
            ('i0', 1),
            ('i1', 6),
            ('i2', 7)
        )
        not_in_item1 = (
            ('i0', 9),
            ('i1', 11),
            ('i2', 9)
        )
        not_in_item2 = (
            ('i0', 1),
            ('i1', 4),
            ('i2', 7)
        )
        self.assertTrue(s.contained_in(s1))
        self.assertFalse(s1.contained_in(s))
        self.assertFalse(s.contained_in(s2))
        self.assertFalse(s2.contained_in(s))
        self.assertIn(in_item1, s)
        self.assertIn(in_item2, s)
        self.assertNotIn(not_in_item1, s)
        self.assertNotIn(not_in_item2, s)

    def test_subtraction_basic_with_dont_care_in_self(self):
        cube1 = (
            ('i0', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i2', CanonicalIntervalSet.get_interval_set(0, 10))
        )
        s1 = SetValuedDecisionDiagram.from_cube(cube1)
        cube2 = (
            ('i0', CanonicalIntervalSet.get_interval_set(0, 2)),
            ('i1', CanonicalIntervalSet.get_interval_set(3, 5)),
            ('i2', CanonicalIntervalSet.get_interval_set(6, 8))
        )
        s2 = SetValuedDecisionDiagram.from_cube(cube2)
        s = s1 - s2
        in_item1 = (
            ('i0', 1),
            ('i1', 4),
            ('i2', 5)
        )
        in_item2 = (
            ('i0', 5),
            ('i1', 6),
            ('i2', 7)
        )
        not_in_item1 = (
            ('i0', 11),
            ('i1', 11),
            ('i2', 9)
        )
        not_in_item2 = (
            ('i0', 1),
            ('i1', 4),
            ('i2', 7)
        )
        self.assertTrue(s.contained_in(s1))
        self.assertFalse(s1.contained_in(s))
        self.assertFalse(s.contained_in(s2))
        self.assertFalse(s2.contained_in(s))
        self.assertIn(in_item1, s)
        self.assertIn(in_item2, s)
        self.assertNotIn(not_in_item1, s)
        self.assertNotIn(not_in_item2, s)

    def test_subtraction_basic_with_dont_care_in_other(self):
        cube1 = (
            ('i0', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i1', CanonicalIntervalSet.get_interval_set(0, 10)),
            ('i2', CanonicalIntervalSet.get_interval_set(0, 10))
        )
        s1 = SetValuedDecisionDiagram.from_cube(cube1)
        cube2 = (
            ('i1', CanonicalIntervalSet.get_interval_set(3, 5)),
            ('i2', CanonicalIntervalSet.get_interval_set(6, 8))
        )
        s2 = SetValuedDecisionDiagram.from_cube(cube2)
        s = s1 - s2
        in_item1 = (
            ('i0', 7),
            ('i1', 7),
            ('i2', 7)
        )
        in_item2 = (
            ('i0', 4),
            ('i1', 4),
            ('i2', 4)
        )
        not_in_item1 = (
            ('i0', 9),
            ('i1', 11),
            ('i2', 9)
        )
        not_in_item2 = (
            ('i0', 5),
            ('i1', 4),
            ('i2', 7)
        )
        self.assertTrue(s.contained_in(s1))
        self.assertFalse(s1.contained_in(s))
        self.assertFalse(s.contained_in(s2))
        self.assertFalse(s2.contained_in(s))
        self.assertIn(in_item1, s)
        self.assertIn(in_item2, s)
        self.assertNotIn(not_in_item1, s)
        self.assertNotIn(not_in_item2, s)


if __name__ == '__main__':
    unittest.main()
