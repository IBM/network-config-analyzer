import unittest

from smt_experiments.z3_string_set import Z3StringSet


class BasicTests(unittest.TestCase):
    def test_contains_all_words(self):
        in_word = 'bla'
        str_set = Z3StringSet.get_all_words()
        self.assertIn(in_word, str_set)

    def test_contains_exact_match(self):
        str_set = Z3StringSet.from_str('bla')
        in_word = 'bla'
        not_in_word = 'blabla'

        self.assertIn(in_word, str_set)
        self.assertNotIn(not_in_word, str_set)

    def test_contains_prefix(self):
        str_set = Z3StringSet.from_str('bla*')
        in_word = 'blablak'
        not_in_word = 'mblabla'

        self.assertIn(in_word, str_set)
        self.assertNotIn(not_in_word, str_set)

    def test_contains_suffix(self):
        str_set = Z3StringSet.from_str('*bla')
        in_word = 'kablabla'
        not_in_word = 'mblablak'

        self.assertIn(in_word, str_set)
        self.assertNotIn(not_in_word, str_set)

    def test_contains_presence(self):
        str_set = Z3StringSet.from_str('*')
        in_word = 'bla'
        not_in_word = ''

        self.assertIn(in_word, str_set)
        self.assertNotIn(not_in_word, str_set)

    def test_and(self):
        str_set_1 = Z3StringSet.from_str('bla/*')
        str_set_2 = Z3StringSet.from_str('*/bla')
        str_set = str_set_1 & str_set_2
        in_word_1 = 'bla/bla'
        in_word_2 = 'bla/moo/bla'
        not_in_word_1 = 'moo/bla'
        not_in_word_2 = 'moobla/bla'

        self.assertIn(in_word_1, str_set)
        self.assertIn(in_word_2, str_set)
        self.assertNotIn(not_in_word_1, str_set)
        self.assertNotIn(not_in_word_2, str_set)

    def test_or(self):
        pass

    def test_sub(self):
        pass

    def test_is_empty(self):
        pass

    def test_is_all_words(self):
        pass

    def test_contained_in(self):
        pass

    def test_is_finite(self):
        pass

    def test_eq(self):
        pass




if __name__ == '__main__':
    unittest.main()
