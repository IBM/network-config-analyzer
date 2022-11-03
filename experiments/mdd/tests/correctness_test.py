import unittest

from experiments.mdd.set_valued_decision_diagram import SetValuedDecisionDiagram


class MyTestCase(unittest.TestCase):
    def test_contains_basic(self):
        dd = SetValuedDecisionDiagram.from_cube([{1, 2, 3}, {0, 1, 2}, {2, 3, 4}])
        self.assertIn([1, 2, 3], dd)
        self.assertNotIn([0, 1, 3], dd)

    def test_or_basic_0(self):
        dd1 = SetValuedDecisionDiagram.from_cube([{0, 1, 2}])
        dd2 = SetValuedDecisionDiagram.from_cube([{0, 2, 3}])
        dd = dd1 | dd2
        self.assertIn([0], dd)
        self.assertIn([1], dd)
        self.assertIn([2], dd)
        self.assertIn([3], dd)
        self.assertNotIn([4], dd)

    def test_or_basic_1(self):
        dd1 = SetValuedDecisionDiagram.from_cube([{0, 1, 2}, {0, 1, 2}])
        dd2 = SetValuedDecisionDiagram.from_cube([{0, 2}, {1, 3}])
        dd = dd1 | dd2
        self.assertIn([0, 3], dd)
        self.assertIn([0, 0], dd)
        self.assertIn([1, 2], dd)
        self.assertNotIn([1, 3], dd)

    def test_and_basic_0(self):
        dd1 = SetValuedDecisionDiagram.from_cube([{0, 1, 2}, {0, 1, 2}])
        dd2 = SetValuedDecisionDiagram.from_cube([{0, 2, 4}, {0, 2, 4}])
        dd = dd1 & dd2
        self.assertIn([0, 2], dd)
        self.assertIn([2, 2], dd)
        self.assertNotIn([1, 2], dd)
        self.assertNotIn([0, 1], dd)

    def test_and_basic_1(self):
        dd1 = SetValuedDecisionDiagram.from_cube([{0, 1, 2}, {0, 1, 2}])
        dd2 = SetValuedDecisionDiagram.from_cube([{3, 4, 5}, {3, 4, 5}])
        dd3 = dd1 | dd2

        dd4 = SetValuedDecisionDiagram.from_cube([{0, 2, 4}, {0, 2, 4}])
        dd5 = SetValuedDecisionDiagram.from_cube([{1, 3, 5}, {1, 3, 5}])
        dd6 = dd4 | dd5

        dd = dd3 & dd6
        self.assertIn([0, 2], dd)
        self.assertIn([3, 5], dd)
        self.assertIn([4, 4], dd)
        self.assertNotIn([4, 5], dd)
        self.assertNotIn([0, 4], dd)

    def test_eq(self):
        dd1 = SetValuedDecisionDiagram.from_cube([{0, 1, 2}, {0, 1, 2}])
        dd2 = SetValuedDecisionDiagram.from_cube([{3, 4, 5}, {3, 4, 5}])
        dd3 = dd1 | dd2

        dd4 = SetValuedDecisionDiagram.from_cube([{0, 2, 4}, {0, 2, 4}])
        dd5 = SetValuedDecisionDiagram.from_cube([{1, 3, 5}, {1, 3, 5}])
        dd6 = dd4 | dd5

        dd = dd3 & dd6

        x = SetValuedDecisionDiagram.from_cube([{0, 2}, {0, 2}])
        x = x | SetValuedDecisionDiagram.from_cube([{4}, {4}])
        x = x | SetValuedDecisionDiagram.from_cube([{1}, {1}])
        x = x | SetValuedDecisionDiagram.from_cube([{3, 5}, {3, 5}])

        self.assertEqual(dd, x)
        self.assertNotEqual(dd6, x)

    def test_sub_1(self):
        # TODO: pass
        dd1 = SetValuedDecisionDiagram.from_cube([{0, 1, 2}, {0, 1, 2}])
        dd2 = SetValuedDecisionDiagram.from_cube([{0, 2}, {0, 2}])
        dd = dd1 - dd2

        target = SetValuedDecisionDiagram.from_cube([{1}, {0, 1, 2}])
        target = target | SetValuedDecisionDiagram.from_cube([{0, 2}, {1}])

        self.assertEqual(dd, target)

    def test_sub_2(self):
        # TODO: pass
        dd1 = SetValuedDecisionDiagram.from_cube([{0, 1, 2}, {0, 1, 2}])
        dd1 = dd1 | SetValuedDecisionDiagram.from_cube([{3, 4, 5}, {3, 4, 5}])
        dd2 = SetValuedDecisionDiagram.from_cube([{0, 2, 4}, {0, 2, 4}])
        dd2 = dd2 | SetValuedDecisionDiagram.from_cube([{1, 3, 5}, {1, 3, 5}])
        dd = dd1 - dd2

        target = SetValuedDecisionDiagram.from_cube([{0, 2}, {1}])
        target = target | SetValuedDecisionDiagram.from_cube([{1}, {0, 2}])
        target = target | SetValuedDecisionDiagram.from_cube([{3, 5}, {4}])
        target = target | SetValuedDecisionDiagram.from_cube([{4}, {3, 5}])

        self.assertEqual(dd, target)

    @unittest.skip
    def test_empty_basic(self):
        dd = SetValuedDecisionDiagram.get_empty()
        self.assertTrue(dd.is_empty())
        self.assertFalse(dd.is_universal())

    @unittest.skip
    def test_universal_basic(self):
        dd = SetValuedDecisionDiagram.get_universal()
        self.assertTrue(dd.is_universal())
        self.assertFalse(dd.is_empty())


if __name__ == '__main__':
    unittest.main()
