
from greenery.fsm import fsm
from greenery.lego import parse, from_fsm


class MinDFA(fsm):
    """
    MinDFA is a wrapper class for greenery.fsm , to support the api required for dimensions in hypercube-set
    (similar to CanonicalIntervalSet)
    It extends greenery.fsm, and has the following additional members:
    - is_all_words: flag (ternary-logic) to indicate if it is known for this DFA if its language is all words or not.
    - complement_dfa: either None (if complement dfa is unknown) or another MinDFA object which complements this
                      dfa to all words.
    """

    class Ternary:
        FALSE = 0
        TRUE = 1
        UNKNOWN = 2

    def __init__(self, alphabet, states, initial, finals, map):
        super().__init__(alphabet, states, initial, finals, map)
        self.is_all_words = MinDFA.Ternary.UNKNOWN
        self.complement_dfa = None

    def __setattr__(self, name, value):
        """
        The fsm object is immutable, and for minDFA only the new members can be set.
        """
        if name in {"is_all_words", "complement_dfa"}:
            self.__dict__[name] = value
        else:
            super().__setattr__(name, value)
        return self

    @staticmethod
    def dfa_from_fsm(f):
        """
        create MinDFA object from a greenery.fsm object
        :param f: greenery.fsm object , assuming f was reduced (min fsm)
        :return: MinDFA object
        """
        return MinDFA(f.alphabet, f.states, f.initial, f.finals, f.map)

    @staticmethod
    # TODO: when not being used from DFA_all_words, should provide alphabet set
    #  (for MinDFA equivalence in canonical rep, need to have the same alphabet for equal DFAs)
    def dfa_from_regex(s, alphabet=None):
        """
        Using greenery to convert regex to a minimal DFA
        :param s: str object with the input regular expression
        :param alphabet:
        :return:
        """
        # TODO: consider runtime impact for using alphabet...
        # alphabet = None
        f = parse(s).to_fsm(alphabet)
        # for canonical rep -- transform to minimal MinDFA
        f.reduce()
        res = MinDFA.dfa_from_fsm(f)
        # TODO: currently assuming input str as regex only has '*' operator for infinity
        if '*' not in s:
            res.is_all_words = MinDFA.Ternary.FALSE
        return res

    @staticmethod
    def dfa_all_words(legal_characters):
        """
        get MinDFA for all words in a domain
        :param legal_characters: str object with regular expression for all words in a domain
        :return: MinDFA object such that its language is equivalent to all words in the domain
        """
        res = MinDFA.dfa_from_regex(legal_characters)
        res.is_all_words = MinDFA.Ternary.TRUE
        return res

    def is_dfa_wll_words(self, all_words_dfa):
        """
        return True iff self is equivalent to DFA of all words.
        avoid dfa-comparison if possible (rely on is_all_words and len() when possible )
        :param all_words_dfa: the DFA of all words for the relevant domain.
        :rtype: bool
        """
        if self.is_all_words == MinDFA.Ternary.TRUE:
            return True
        elif self.is_all_words == MinDFA.Ternary.UNKNOWN and not self.has_finite_len() and self == all_words_dfa:
            return True
        return False

    def copy(self):
        res = MinDFA.dfa_from_fsm(self)
        res.is_all_words = self.is_all_words
        if self.complement_dfa is not None:
            res.complement_dfa = self.complement_dfa.copy()
        return res

    def __hash__(self):
        return hash(super().__str__())

    def _get_strings_set_str(self):
        """
        This method assumes that self has a finite len.
        Returns a set of strings with all str values in the language of self.
        :rtype: set of strings
        """
        str_values = set()
        # TODO: avoid using from_fsm, use strings() directly on fsm object
        str_generator = self.strings()
        for i in range(0, len(self)):
            str_val = next(str_generator)
            str_val_new = ''.join(ch for ch in str_val)
            str_values |= {str_val_new}
        return str(str_values)

    def has_finite_len(self):
        """
        :return: True iff self has finite number of words accepted by it.
        :rtype: bool
        """
        if self.is_all_words == MinDFA.Ternary.TRUE:
            return False
        try:
            finite_len = len(self)
            return True
        except OverflowError:
            return False

    def __str__(self):
        """
        str representation of the language accepted by this DFA:
        - option 1: if language has finite number of words -> return string with all accepted words.
        - option 2 (costly): convert fsm to regex with greenery
        :rtype: str
        """
        if self.has_finite_len():
            return self._get_strings_set_str()
        # TODO: consider performance implications of this conversion from MinDFA to regex
        return str(from_fsm(self))

    def get_fsm_str(self):
        """
        get a string representation for this DFA from greenery.fsm str method: states and transition table.
        :rtype: str
        """
        return super().__str__()

    def __bool__(self):
        return not self.empty()

    def contained_in(self, other):
        """
        return True iff self is contained in other.
        :param other: a minDFA object
        :rtype: bool
        """
        if other.is_all_words == MinDFA.Ternary.TRUE:
            return True
        if self.is_all_words == MinDFA.Ternary.TRUE and other.is_all_words == MinDFA.Ternary.FALSE:
            return False
        # TODO: if both are finite-len, can use set containment on accepted words
        return self.issubset(other)

    # operators at fsm already apply reduce() (minimization)
    def __or__(self, other):
        if self.is_all_words == MinDFA.Ternary.TRUE:
            return self.copy()
        if other.is_all_words == MinDFA.Ternary.TRUE:
            return other.copy()
        fsm_res = super().__or__(other)
        res = MinDFA.dfa_from_fsm(fsm_res)
        if res.has_finite_len():
            res.is_all_words = MinDFA.Ternary.FALSE
        res.complement_dfa = None
        return res

    def __and__(self, other):
        if self.is_all_words == MinDFA.Ternary.TRUE:
            return other.copy()
        if other.is_all_words == MinDFA.Ternary.TRUE:
            return self.copy()
        fsm_res = super().__and__(other)
        res = MinDFA.dfa_from_fsm(fsm_res)
        if self.is_all_words == MinDFA.Ternary.FALSE or other.is_all_words == MinDFA.Ternary.FALSE:
            res.is_all_words = MinDFA.Ternary.FALSE
        res.complement_dfa = None
        return res

    def __sub__(self, other):
        fsm_res = super().__sub__(other)
        res = MinDFA.dfa_from_fsm(fsm_res)
        if other.is_all_words == MinDFA.Ternary.TRUE:
            res.is_all_words = MinDFA.Ternary.FALSE
        if res.has_finite_len():
            res.is_all_words = MinDFA.Ternary.FALSE
        if not other.empty():
            res.is_all_words = MinDFA.Ternary.FALSE
        if self.is_all_words == MinDFA.Ternary.TRUE and other.empty():
            res.is_all_words = MinDFA.Ternary.TRUE
        if self.is_all_words == MinDFA.Ternary.TRUE:
            res.complement_dfa = other.copy()
        return res

    def rep(self):
        """
        :return: a string accepted by this DFA
        :rtype: string
        """
        if self.empty():
            return NotImplemented
        # TODO: avoid using from_fsm
        str_generator = from_fsm(self).strings()
        return next(str_generator)
