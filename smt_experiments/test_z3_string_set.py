import unittest

from smt_experiments.z3_string_set import Z3StringSet


class BasicTests(unittest.TestCase):
    def test_contains_all_words(self):
        in_word = 'bla'
        str_set = Z3StringSet.get_all_words_set()
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
        str_set_1 = Z3StringSet.from_str('bla/*')
        str_set_2 = Z3StringSet.from_str('*/bla')
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
        str_set_1 = Z3StringSet.from_str('bla/*')
        str_set_2 = Z3StringSet.from_str('*/bla')
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
        str_set = Z3StringSet.get_empty_set()
        self.assertTrue(str_set.is_empty())

    def test_is_empty_2(self):
        str_set_1 = Z3StringSet.from_str('ba')
        str_set_2 = Z3StringSet.from_str('ka')
        str_set = str_set_1 & str_set_2
        self.assertFalse(str_set_1.is_empty())
        self.assertFalse(str_set_2.is_empty())
        self.assertTrue(str_set.is_empty())

    def test_is_empty_3(self):
        str_set_1 = Z3StringSet.from_str('*/bla')
        str_set_2 = Z3StringSet.from_str('*/bla')
        str_set = str_set_1 - str_set_2
        self.assertFalse(str_set_1.is_empty())
        self.assertTrue(str_set.is_empty())

    def test_is_all_words_1(self):
        str_set = Z3StringSet.get_all_words_set()
        self.assertTrue(str_set.is_all_words())

    def test_is_all_words_2(self, str_set):
        str_set_1 = Z3StringSet.from_str('bla')
        str_set_2 = str_set | str_set_1
        self.assertFalse(str_set_1.is_all_words())
        self.assertTrue(str_set_2.is_all_words())

    def test_sample(self):
        str_set = Z3StringSet.from_str('bla')
        sample = str_set.get_example_from_set()
        self.assertEqual(sample, 'bla')

        str_set_1 = Z3StringSet.from_str('*/bla')
        str_set_2 = Z3StringSet.from_str('bla/*')
        str_set = str_set_1 & str_set_2
        sample = str_set.get_example_from_set()
        self.assertTrue(sample.startswith('bla/'))
        self.assertTrue(sample.endswith('/bla'))

    def test_contained_in(self):
        str_set_1 = Z3StringSet.from_str('bla/*')
        str_set_2 = Z3StringSet.from_str('bla/moo/*')
        self.assertTrue(str_set_2.contained_in(str_set_1))
        self.assertFalse(str_set_1.contained_in(str_set_2))

    def test_eq(self):
        str_set_1 = Z3StringSet.from_str('bla/*')
        str_set_2 = Z3StringSet.from_str('bla/*')
        str_set_3 = Z3StringSet.from_str('*/moo')
        self.assertEqual(str_set_1, str_set_2)
        self.assertNotEqual(str_set_1, str_set_3)

    def test_is_finite(self):
        str_set_1 = Z3StringSet.from_str('bla/*')
        self.assertFalse(str_set_1.is_finite())

        str_set_2 = Z3StringSet.from_str('bla/bla/bla')
        self.assertTrue(str_set_2.is_finite())

        str_set_3 = Z3StringSet.from_str('*/bla')
        self.assertFalse(str_set_3.is_finite())

        str_set_4 = str_set_1 & str_set_3
        self.assertFalse(str_set_4.is_finite())

        str_set_5 = str_set_2 & str_set_4
        self.assertTrue(str_set_5.is_finite())


if __name__ == '__main__':
    unittest.main()
