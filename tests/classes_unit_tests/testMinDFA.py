import unittest
from greenery import fsm
from nca.CoreDS.DimensionsManager import DimensionsManager
from nca.CoreDS.MinDFA import MinDFA

alphabet_regex = MinDFA.default_alphabet_regex


def get_str_dfa(s):
    # dfa_alphabet = dim_manager.get_dimension_domain_by_name("methods").alphabet
    return MinDFA.dfa_from_regex(s)


class TestMinDFA(unittest.TestCase):
    def test_basic(self):
        dfa1 = get_str_dfa("put|get")
        dfa2 = get_str_dfa("get|put")
        self.assertEqual(dfa1, dfa2)
        dfa3 = get_str_dfa("put")
        dfa4 = get_str_dfa("get")
        self.assertEqual(dfa1, dfa3 | dfa4)
        self.assertEqual(dfa1, dfa4 | dfa3)
        dfa5 = dfa4 & dfa1
        self.assertEqual(dfa5, dfa4)
        print(dfa4.get_fsm_str())
        print(repr(dfa4))
        # equiv dfa created directly, with a different set of state numbers
        equiv_dfa = fsm.Fsm(
            alphabet={"e", "g", "t", fsm.ANYTHING_ELSE},
            states={0, 1, 2, 5},
            initial=0,
            finals={5},
            map={
                0: {'g': 1},
                1: {'e': 2},
                2: {'t': 5},
                5: {}
            }
        )
        dfa6 = MinDFA.dfa_from_fsm(equiv_dfa)
        res1 = dfa6 == dfa4
        print(res1)
        self.assertFalse(res1)

        dfa6 = dfa6.fsm
        dfa4 = dfa4.fsm
        res2 = dfa6.equivalent(dfa4)
        print(res2)
        self.assertTrue(res2)
        dfa6.reduce()
        print(repr(dfa6))
        # self.assertEqual(dfa6, dfa4)

    def test_basic_2(self):
        dfa1 = get_str_dfa("ab|aeb")
        print(repr(dfa1))
        dfa2 = get_str_dfa("ab|aec")
        print(repr(dfa2))
        dfa3 = get_str_dfa("aa|afb|aec")
        print(repr(dfa3))

    def test_basic_3(self):
        dfa1 = get_str_dfa("(b*ab)*")
        print(repr(dfa1))
        dfa2 = get_str_dfa("(c*ab)*")
        print(repr(dfa2))

    def test_min_dfa_members(self):
        dfa1 = get_str_dfa("put|get")  # put|get
        self.assertEqual(dfa1.is_all_words, MinDFA.Ternary.FALSE)
        self.assertEqual(dfa1.complement_dfa, None)
        self.assertTrue(dfa1.has_finite_len())

        input_regex = "abc*".replace('*', alphabet_regex)  # abc[.\w/\-]*
        dfa2 = get_str_dfa(input_regex)  # abc*
        self.assertEqual(dfa2.is_all_words, MinDFA.Ternary.UNKNOWN)
        self.assertEqual(dfa2.complement_dfa, None)
        self.assertFalse(dfa2.has_finite_len())

        dfa3 = MinDFA.dfa_all_words(alphabet_regex)  # all
        self.assertEqual(dfa3.is_all_words, MinDFA.Ternary.TRUE)
        self.assertEqual(dfa3.complement_dfa, None)  # TODO: add complement DFA for this case
        self.assertFalse(dfa3.has_finite_len())

        dfa4 = dfa3 - dfa1  # all but "put|get"
        self.assertEqual(dfa4.is_all_words, MinDFA.Ternary.FALSE)
        self.assertEqual(dfa4.complement_dfa, dfa1)
        self.assertFalse(dfa4.has_finite_len())

        dfa5 = dfa3 - dfa2  # all but "abc*"
        self.assertEqual(dfa5.is_all_words, MinDFA.Ternary.FALSE)
        self.assertEqual(dfa5.complement_dfa, dfa2)
        self.assertEqual(dfa2.complement_dfa, dfa5)
        self.assertFalse(dfa5.has_finite_len())

        dfa6 = dfa5 | dfa2  # all (not directly from  dfa_all_words() )
        self.assertEqual(dfa6.is_all_words, MinDFA.Ternary.UNKNOWN)
        self.assertEqual(dfa6.complement_dfa, None)
        self.assertFalse(dfa6.has_finite_len())
        self.assertEqual(dfa6, dfa3)

        empty_dfa = dfa1 - dfa1
        dfa7 = dfa3 - empty_dfa
        self.assertEqual(dfa7.is_all_words, MinDFA.Ternary.TRUE)
        self.assertEqual(dfa7.complement_dfa, empty_dfa)
        self.assertFalse(dfa7.has_finite_len())

        empty2 = dfa1 - dfa3
        self.assertEqual(empty2.is_all_words, MinDFA.Ternary.FALSE)
        self.assertEqual(empty2.complement_dfa, None)
        self.assertTrue(empty2.has_finite_len())

    def test_rep(self):
        input_regex = "abc*".replace('*', alphabet_regex)  # abc[.\w/\-]*
        dfa2 = get_str_dfa(input_regex)  # abc*
        print(dfa2.rep())
        self.assertEqual(dfa2.rep(), "abc")
        empty_dfa = dfa2 - dfa2
        res = empty_dfa.rep()
        self.assertEqual(res, NotImplemented)

    def test_operators(self):
        dfa1 = get_str_dfa("put|get")  # put|get
        self.assertEqual(dfa1.is_all_words, MinDFA.Ternary.FALSE)
        # self.assertEqual(dfa1.complement_dfa, None)
        # due to caching, dfa1 can have a complement dfa from operations on previous tests
        if dfa1.complement_dfa is not None:
            self.assertEqual(dfa1 | dfa1.complement_dfa, MinDFA.dfa_all_words(alphabet_regex))

        self.assertTrue(dfa1.has_finite_len())

        all = MinDFA.dfa_all_words(alphabet_regex)

        self.assertEqual(dfa1, all & dfa1)
        self.assertEqual(dfa1, dfa1 & all)
        self.assertEqual(all, dfa1 | all)
        self.assertEqual(all, all | dfa1)

    def test_contained_in(self):
        dfa1 = get_str_dfa("put|get")
        dfa2 = get_str_dfa("put")
        self.assertFalse(dfa1.contained_in(dfa2))
        self.assertTrue(dfa2.contained_in(dfa1))
        all = MinDFA.dfa_all_words(alphabet_regex)
        self.assertTrue(dfa2.contained_in(all))
        self.assertFalse(all.contained_in(dfa2))

    def test_bool(self):
        dfa2 = get_str_dfa("put")
        self.assertTrue(bool(dfa2))
        empty = dfa2 - dfa2
        self.assertFalse(bool(empty))

    # test to demonstrate the alphabet issue
    def test_hash(self):
        dfa1 = get_str_dfa("put")
        x = get_str_dfa("abc*")
        all = MinDFA.dfa_all_words(alphabet_regex)
        y = all - x
        all2 = x | y
        dfa2 = dfa1 & all
        d = dict()
        d[dfa1] = "put"
        self.assertEqual(d[dfa1], d[dfa2])
        self.assertEqual(dfa1.fsm.alphabet, dfa2.fsm.alphabet)
        dfa3 = all2 & dfa1   # changing order of args due to caching, thus not using (dfa1 & all2)
        self.assertNotEqual(dfa1.fsm.alphabet, dfa3.fsm.alphabet)
        self.assertEqual(d[dfa1], d[dfa3])

    '''
    def test_copy(self):
        dfa1 = get_str_dfa("put")
        all = MinDFA.dfa_all_words(alphabet_regex)
        dfa2 = all - dfa1
        dfa3 = dfa2.copy()
        self.assertNotEqual(dfa3.complement_dfa, None)
    '''

    def test_cache(self):
        dfa1 = get_str_dfa("put")
        x = get_str_dfa("abc*")
        y = dfa1 | x
        l = []
        for i in range(100):
            l.append(dfa1 | x)
        # print(z)
        # print(y)
        print(dfa1.__or__.cache_info())
        self.assertEqual(dfa1.__or__.cache_info().hits > 0, True)

    def test_regex_for_paths(self):
        allowed_chars = "[" + MinDFA.default_dfa_alphabet_chars + "]"
        accepted_string1 = '/foo'
        accepted_string2 = '/foo/'
        accepted_string3 = '/foo/abc'
        not_accepted_string = '/fooabc'
        path_string = '/foo'  # as appearing in policy, with Prefix attribute
        regex1 = path_string + '|' + path_string + '/' + allowed_chars + '*'
        dfa1 = MinDFA.dfa_from_regex(regex1)
        self.assertTrue(accepted_string1 in dfa1)
        self.assertTrue(accepted_string2 in dfa1)
        self.assertTrue(accepted_string3 in dfa1)
        self.assertFalse(not_accepted_string in dfa1)

        regex2 = f'{path_string}(/{allowed_chars}*)?'
        print(regex2)
        dfa2 = MinDFA.dfa_from_regex(regex2)
        self.assertTrue(accepted_string1 in dfa2)
        self.assertTrue(accepted_string2 in dfa2)
        self.assertTrue(accepted_string3 in dfa2)
        self.assertFalse(not_accepted_string in dfa2)

        # dfa1 and dfa2 are equivalent
        self.assertEqual(dfa1, dfa2)

