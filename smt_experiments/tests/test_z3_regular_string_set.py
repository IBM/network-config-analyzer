import unittest

from smt_experiments.z3_sets.z3_regular_string_set import Z3RegularStringSet


class MyTestCase(unittest.TestCase):
    def test_init(self):
        s = Z3RegularStringSet()

    def test_init_empty(self):
        s = Z3RegularStringSet()
        self.assertTrue(s.is_empty())



if __name__ == '__main__':
    unittest.main()
