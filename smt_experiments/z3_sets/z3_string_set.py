# TODO: how should we take into account the set of allowed alphabet?
#   especially the "is_all_words" function
# TODO: take the tests for the MinDFA module and compare it to the Z3
#  implementation
import sre_parse
from typing import Optional

import z3
from z3 import sat, PrefixOf, SuffixOf, Length, ModelRef, String

from smt_experiments.role_analyzer import regex_to_z3_expr
from smt_experiments.z3_sets.z3_set import Z3Set
from smt_experiments.z3_sets.z3_utils import solve_with_model


class Z3StringSet(Z3Set):
    _var = String(Z3Set._var_name)

    @classmethod
    def from_str(cls, s: str):
        str_set = cls()

        if '*' not in s:
            str_set.constraints = str_set._var == s
        elif '*' == s:
            # TODO: is it true that this means that the string is not empty?
            str_set.constraints = Length(str_set._var) > 0
        elif '*' == s[-1]:
            str_set.constraints = PrefixOf(s[:-1], str_set._var)
        elif '*' == s[0]:
            str_set.constraints = SuffixOf(s[1:], str_set._var)

        else:
            raise RuntimeError(f'* should only appear at the start or end of the string. got {s}.')

        return str_set

    def get_example_from_set(self) -> Optional[str]:
        result, model = solve_with_model(self.constraints)
        if result == sat:
            model: ModelRef
            example = model.eval(self._var).as_string()
            return example
        return None

    @classmethod
    def dfa_from_regex(cls, s: str):
        # TODO: make sure this works
        z3_regex = regex_to_z3_expr(sre_parse.parse(s))
        z3_set = cls()
        z3_set.constraints = z3.InRe(z3_set._var, z3_regex)
        return z3_set
