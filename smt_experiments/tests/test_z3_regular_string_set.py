import unittest

from smt_experiments.z3_sets.z3_regular_string_set import Z3RegularStringSet


class MyTestCase(unittest.TestCase):
    def test_init(self):
        s = Z3RegularStringSet()

    def test_init_empty(self):
        s = Z3RegularStringSet()
        self.assertTrue(s.is_empty())

    def test_from_regex_0(self):
        regex = r'abc'
        s = Z3RegularStringSet.dfa_from_regex(regex)
        self.assertIn('abc', s)
        self.assertNotIn('abcd', s)

    def test_from_regex_1(self):
        regex = r'abc(.*)'
        s = Z3RegularStringSet.dfa_from_regex(regex)
        self.assertIn('abcd', s)
        self.assertNotIn('dabc', s)


if __name__ == '__main__':
    unittest.main()
