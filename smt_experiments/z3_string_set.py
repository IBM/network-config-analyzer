# Exact - "bla": only "bla"
# Prefix - "bla*": starts with "bla"
# Suffix - "*bla": ends with "bla"
# Presence - "*": any non-empty
# TODO: how should we take into account the set of allowed alphabet?
#   especially the "is_all_words" function
# TODO: take the tests for the MinDFA module and compare it to the Z3
#  implementation
from typing import Optional

import z3
from z3 import And, BoolRef, Solver, sat, PrefixOf, \
    SuffixOf, Length, unsat, Not, substitute, Or, BoolVal, ModelRef, SeqRef, Int, Exists

from smt_experiments.z3_utils import solve_without_model, solve_with_model


class Z3StringSet:
    _fresh_var_counter = 0

    @classmethod
    def _get_fresh_var_name(cls):
        var_prefix = 's'
        num = cls._fresh_var_counter
        cls._fresh_var_counter += 1
        return f'{var_prefix}!{num}'

    def __init__(self):
        var_name = self._get_fresh_var_name()
        self._var = z3.String(var_name)
        self._constraints = None

    def __contains__(self, item: str):
        constraints = And(
            self._var == item,
            self._constraints
        )
        return solve_without_model(constraints) == sat

    def __eq__(self, other):
        return self.contained_in(other) and other.contained_in(self)

    @classmethod
    def from_str(cls, s: str):
        str_set = cls()

        if '*' not in s:
            str_set._constraints = str_set._var == s
        elif '*' == s:
            # TODO: is it true that this means that the string is not empty?
            str_set._constraints = Length(str_set._var) > 0
        elif '*' == s[-1]:
            str_set._constraints = PrefixOf(s[:-1], str_set._var)
        elif '*' == s[0]:
            str_set._constraints = SuffixOf(s[1:], str_set._var)

        else:
            raise RuntimeError(f'* should only appear at the start or end of the string. got {s}.')

        return str_set

    @classmethod
    def get_all_words_set(cls):
        str_set = cls()
        str_set._constraints = BoolVal(True)
        return str_set

    @classmethod
    def get_empty_set(cls):
        str_set = cls()
        str_set._constraints = BoolVal(False)
        return str_set

    def is_all_words(self) -> bool:
        constraints = Not(self._constraints)
        return solve_without_model(constraints) == unsat

    def copy(self):
        pass

    def __hash__(self):
        pass

    def enumerate_all_words(self) -> list[str]:
        # TODO: this might be tricky to implement,
        #   but maybe it could be done as we construct the term?
        #   there might be an elegant way of doing this
        assert self.is_finite()
        return []

    def is_finite(self) -> bool:
        # TODO: this is not directly available in z3, but there might be an elegant way
        #   of doing this
        #   I think that this might be done while the expression is constructed. maybe
        # TODO: this assumes that if there is a word of length greater than 1000, then the
        #   language is infinite
        max_str_len = 100
        constraints = And(
            self._constraints,
            Length(self._var) > max_str_len
        )
        return solve_without_model(constraints) == unsat

    def __str__(self):
        pass

    def is_empty(self):
        return solve_without_model(self._constraints) == unsat

    def contained_in(self, other) -> bool:
        return (self - other).is_empty()

    def _get_constraints_with_different_var(self, other):
        other: Z3StringSet
        return substitute(self._constraints, (self._var, other._var))

    def __or__(self, other):
        other: Z3StringSet
        str_set = Z3StringSet()
        str_set._constraints = Or(
            self._get_constraints_with_different_var(str_set),
            other._get_constraints_with_different_var(str_set),
        )
        return str_set

    def __and__(self, other):
        other: Z3StringSet
        str_set = Z3StringSet()
        str_set._constraints = And(
            self._get_constraints_with_different_var(str_set),
            other._get_constraints_with_different_var(str_set),
        )
        return str_set

    def __sub__(self, other):
        other: Z3StringSet
        str_set = Z3StringSet()
        str_set._constraints = And(
            self._get_constraints_with_different_var(str_set),
            Not(other._get_constraints_with_different_var(str_set)),
        )
        return str_set

    def get_example_from_set(self) -> Optional[str]:
        result, model = solve_with_model(self._constraints)
        if result == sat:
            model: ModelRef
            example = model.eval(self._var).as_string()
            return example
        return None
