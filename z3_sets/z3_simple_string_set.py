# TODO: There is no support for a specific alphabet, currently it is set to z3's default.
import sre_parse

from z3 import sat, PrefixOf, SuffixOf, String, Or, BoolVal, unsat, And, Not, InRe, unknown

from z3_sets.role_analyzer import regex_to_z3_expr
from z3_sets.z3_set import Z3Set
from z3_sets.z3_utils import solve_without_model


class Z3SimpleStringSet(Z3Set):
    """String set with simple constraints (prefix, suffix, exact match) implementation with z3.
    Note that there is support for creation from regex, but it is not recommended as z3
    tends to get stuck when there are multiple regex constraints.
    """
    @property
    def python_type(self):
        return str

    def __init__(self):
        self._var = String('s')
        self._constraints = BoolVal(False)

    @classmethod
    def get_universal_set(cls):
        new = cls()
        new._constraints = BoolVal(True)
        return new

    def is_empty(self):
        res = solve_without_model(self._constraints, timeout=True)
        if res == unsat:
            return True
        if res == sat:
            return False
        if res == unknown:
            raise TimeoutError

    @classmethod
    def get_empty_set(cls):
        return cls()

    def __contains__(self, item: str) -> bool:
        if not isinstance(item, str):
            raise TypeError
        constraint = And(self._var == item, self._constraints)
        return solve_without_model(constraint) == sat

    def copy(self):
        new = Z3SimpleStringSet()
        new._constraints = self._constraints
        return new

    def __iand__(self, other):
        if not isinstance(other, Z3SimpleStringSet):
            raise TypeError
        self._constraints = And(self._constraints, other._constraints)
        return self

    def __ior__(self, other):
        if not isinstance(other, Z3SimpleStringSet):
            raise TypeError
        self._constraints = Or(self._constraints, other._constraints)
        return self

    def __invert__(self):
        new = self.copy()
        new._constraints = Not(self._constraints)
        return new

    def __str__(self):
        return str(self._constraints)

    @classmethod
    def from_wildcard(cls, s: str):
        str_set = cls()
        if '*' not in s:
            str_set._constraints = str_set._var == s
        elif '*' == s:
            str_set._constraints = BoolVal(True)
        elif '*' == s[-1]:
            str_set._constraints = PrefixOf(s[:-1], str_set._var)
        elif '*' == s[0]:
            str_set._constraints = SuffixOf(s[1:], str_set._var)

        else:
            raise ValueError(f'* should only appear at the start or end of the string. got {s}.')

        return str_set

    @classmethod
    def dfa_from_regex(cls, regex: str):
        str_set = cls()
        parsed_regex = sre_parse.parse(regex)
        z3_regex = regex_to_z3_expr(parsed_regex)
        str_set._constraints = InRe(str_set._var, z3_regex)
        return str_set
