import sys
import os



print(os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), '..', 'network-config-analyzer'))
sys.path.append(
    os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), '..', 'network-config-analyzer'))

from DimensionsManager import DimensionsManager
from MinDFA import MinDFA
import unittest
from greenery.fsm import fsm, anything_else


alphabet_regex = DimensionsManager().default_dfa_alphabet_str

def get_str_dfa(s):
    #dfa_alphabet = dim_manager.get_dimension_domain_by_name("methods").alphabet
    return MinDFA.dfa_from_regex(s)

class TestMinDFA(unittest.TestCase):
    def test_basic(self):
        dfa1 = get_str_dfa("put|get")
        dfa2 = get_str_dfa("get|put")
        self.assertEqual(dfa1, dfa2)
        dfa3 = get_str_dfa("put")
        dfa4 = get_str_dfa("get")
        self.assertEqual(dfa1, dfa3|dfa4)
        self.assertEqual(dfa1, dfa4|dfa3)
        dfa5 = dfa4 & dfa1
        self.assertEqual(dfa5, dfa4)
        print(dfa4.get_fsm_str())
        print(repr(dfa4))
        cex = fsm(
            alphabet = {"e", "g", "t", anything_else},
            states   = {0, 1, 2, 5},
            initial  = 0,
            finals   = {5},
            map      = {
                0: {'g': 1},
                1: {'e': 2},
                2: {'t': 5},
                5: {}
            }
        )
        dfa6 = MinDFA.dfa_from_fsm(cex)
        res1 = dfa6 == dfa4
        print(res1)
        self.assertFalse(res1)

        dfa6 = dfa6.get_fsm()
        dfa4 = dfa4.get_fsm()
        res2 = dfa6.equivalent(dfa4)
        print(res2)
        self.assertTrue(res2)
        dfa6.reduce()
        print(repr(dfa6))
        #self.assertEqual(dfa6, dfa4)

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
        dfa1 = get_str_dfa("put|get")
        self.assertEqual(dfa1.is_all_words, MinDFA.Ternary.FALSE)
        self.assertEqual(dfa1.complement_dfa, None)
        self.assertTrue(dfa1.has_finite_len())

        input_regex = "abc*".replace('*', alphabet_regex)  # abc[.\w/\-]*
        dfa2 = get_str_dfa(input_regex)
        self.assertEqual(dfa2.is_all_words, MinDFA.Ternary.UNKNOWN)
        self.assertEqual(dfa2.complement_dfa, None)
        self.assertFalse(dfa2.has_finite_len())

        dfa3 = MinDFA.dfa_all_words(alphabet_regex)
        self.assertEqual(dfa3.is_all_words, MinDFA.Ternary.TRUE)
        self.assertEqual(dfa3.complement_dfa, None)  # TODO: add complement DFA for this case
        self.assertFalse(dfa3.has_finite_len())

        dfa4 = dfa3 - dfa1
        self.assertEqual(dfa4.is_all_words, MinDFA.Ternary.FALSE)
        self.assertEqual(dfa4.complement_dfa, dfa1)
        self.assertFalse(dfa4.has_finite_len())

        dfa5 = dfa3 - dfa2
        self.assertEqual(dfa5.is_all_words, MinDFA.Ternary.FALSE)
        self.assertEqual(dfa5.complement_dfa, dfa2)
        self.assertFalse(dfa5.has_finite_len())

        dfa6 = dfa5 | dfa2
        self.assertEqual(dfa6.is_all_words, MinDFA.Ternary.UNKNOWN)
        self.assertEqual(dfa6.complement_dfa, None)
        self.assertFalse(dfa6.has_finite_len())
        self.assertEqual(dfa6, dfa3)


