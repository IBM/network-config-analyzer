import unittest

from z3_sets.z3_simple_string_set import Z3SimpleStringSet


class BasicTests(unittest.TestCase):
    def test_contains_all_words(self):
        in_word = 'bla'
        str_set = Z3SimpleStringSet.get_universal_set()
        self.assertIn(in_word, str_set)

    def test_contains_exact_match(self):
        str_set = Z3SimpleStringSet.from_wildcard('bla')
        in_word = 'bla'
        not_in_word = 'blabla'

        self.assertIn(in_word, str_set)
        self.assertNotIn(not_in_word, str_set)

    def test_contains_prefix(self):
        str_set = Z3SimpleStringSet.from_wildcard('bla*')
        in_word = 'blablak'
        not_in_word = 'mblabla'

        self.assertIn(in_word, str_set)
        self.assertNotIn(not_in_word, str_set)

    def test_contains_suffix(self):
        str_set = Z3SimpleStringSet.from_wildcard('*bla')
        in_word = 'kablabla'
        not_in_word = 'mblablak'

        self.assertIn(in_word, str_set)
        self.assertNotIn(not_in_word, str_set)

    def test_and(self):
        str_set_1 = Z3SimpleStringSet.from_wildcard('bla/*')
        str_set_2 = Z3SimpleStringSet.from_wildcard('*/bla')
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
        str_set_1 = Z3SimpleStringSet.from_wildcard('bla/*')
        str_set_2 = Z3SimpleStringSet.from_wildcard('*/bla')
        str_set = str_set_1 | str_set_2
        in_word_1 = 'food/bla'
        in_word_2 = 'bla/moo/moo'
        not_in_word_1 = 'moo/bla/moo'
        not_in_word_2 = 'moobla/black'

        self.assertIn(in_word_1, str_set)
        self.assertIn(in_word_2, str_set)
        self.assertNotIn(not_in_word_1, str_set)
        self.assertNotIn(not_in_word_2, str_set)

    def test_sub(self):
        str_set_1 = Z3SimpleStringSet.from_wildcard('bla/*')
        str_set_2 = Z3SimpleStringSet.from_wildcard('*/bla')
        str_set = str_set_1 - str_set_2
        in_word_1 = 'bla/moo'
        in_word_2 = 'bla/moo/moo'
        not_in_word_1 = 'moo/moo'
        not_in_word_2 = 'bla/moo/bla'

        self.assertIn(in_word_1, str_set)
        self.assertIn(in_word_2, str_set)
        self.assertNotIn(not_in_word_1, str_set)
        self.assertNotIn(not_in_word_2, str_set)

    def test_is_empty_1(self):
        str_set = Z3SimpleStringSet.get_empty_set()
        self.assertTrue(str_set.is_empty())

    def test_is_empty_2(self):
        str_set_1 = Z3SimpleStringSet.from_wildcard('ba')
        str_set_2 = Z3SimpleStringSet.from_wildcard('ka')
        str_set = str_set_1 & str_set_2
        self.assertFalse(str_set_1.is_empty())
        self.assertFalse(str_set_2.is_empty())
        self.assertTrue(str_set.is_empty())

    def test_is_empty_3(self):
        str_set_1 = Z3SimpleStringSet.from_wildcard('*/bla')
        str_set_2 = Z3SimpleStringSet.from_wildcard('*/bla')
        str_set = str_set_1 - str_set_2
        self.assertFalse(str_set_1.is_empty())
        self.assertTrue(str_set.is_empty())

    def test_is_all_words_1(self):
        str_set = Z3SimpleStringSet.get_universal_set()
        self.assertTrue(str_set.is_universal())

    def test_is_all_words_2(self):
        str_set = Z3SimpleStringSet.get_universal_set()
        str_set_1 = Z3SimpleStringSet.from_wildcard('bla')
        str_set_2 = str_set | str_set_1
        self.assertFalse(str_set_1.is_universal())
        self.assertTrue(str_set_2.is_universal())

    def test_contained_in(self):
        str_set_1 = Z3SimpleStringSet.from_wildcard('bla/*')
        str_set_2 = Z3SimpleStringSet.from_wildcard('bla/moo/*')
        self.assertTrue(str_set_2.contained_in(str_set_1))
        self.assertFalse(str_set_1.contained_in(str_set_2))

    def test_eq(self):
        str_set_1 = Z3SimpleStringSet.from_wildcard('bla/*')
        str_set_2 = Z3SimpleStringSet.from_wildcard('bla/*')
        str_set_3 = Z3SimpleStringSet.from_wildcard('*/moo')
        self.assertEqual(str_set_1, str_set_2)
        self.assertNotEqual(str_set_1, str_set_3)


if __name__ == '__main__':
    unittest.main()
