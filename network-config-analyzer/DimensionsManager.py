from enum import Enum

from CanonicalIntervalSet import CanonicalIntervalSet
from MinDFA import MinDFA

"""
A singleton class to manage dimensions names and their association to type and domain.
"""


class DimensionsManager:
    class DimensionType(Enum):
        IntervalSet = 0
        DFA = 1

    class __DimensionsManager:
        def __init__(self):
            self.default_dfa_alphabet_str = "[.\w/\-]*"
            self.default_interval_domain_tuple = (0, 100000)
            self.domain_str_to_dfa_map = dict()
            dfa_all_words_default = self._get_dfa_from_alphabet_str(self.default_dfa_alphabet_str)
            ports_interval = CanonicalIntervalSet.get_interval_set(1, 65536)
            self.dim_dict = dict()
            self.dim_dict["src_ports"] = (DimensionsManager.DimensionType.IntervalSet, ports_interval)
            self.dim_dict["dst_ports"] = (DimensionsManager.DimensionType.IntervalSet, ports_interval)
            self.dim_dict["methods"] = (DimensionsManager.DimensionType.DFA, dfa_all_words_default)
            self.dim_dict["paths"] = (DimensionsManager.DimensionType.DFA, dfa_all_words_default)
            self.dim_dict["hosts"] = (DimensionsManager.DimensionType.DFA, dfa_all_words_default)

            icmp_type_interval = CanonicalIntervalSet.get_interval_set(0, 254)
            icmp_code_interval = CanonicalIntervalSet.get_interval_set(0, 255)
            self.dim_dict["icmp_type"] = (DimensionsManager.DimensionType.IntervalSet, icmp_type_interval)
            self.dim_dict["icmp_code"] = (DimensionsManager.DimensionType.IntervalSet, icmp_code_interval)

        def _get_dfa_from_alphabet_str(self, alphabet_str):
            if alphabet_str in self.domain_str_to_dfa_map:
                return self.domain_str_to_dfa_map[alphabet_str]
            new_dfa = MinDFA.dfa_all_words(alphabet_str)
            self.domain_str_to_dfa_map[alphabet_str] = new_dfa
            return new_dfa

    instance = None

    def __init__(self):
        if not DimensionsManager.instance:
            DimensionsManager.instance = DimensionsManager.__DimensionsManager()

    def __getattr__(self, name):
        return getattr(self.instance, name)

    def get_dimension_type_by_name(self, dim_name):
        return self.dim_dict[dim_name][0]

    def get_dimension_domain_by_name(self, dim_name):
        return self.dim_dict[dim_name][1]

    def set_domain(self, dim_name, dim_type, interval_tuple=None, alphabet_str=None):
        if dim_type == DimensionsManager.DimensionType.IntervalSet:
            interval = interval_tuple if interval_tuple is not None else self.default_interval_domain_tuple
            domain = CanonicalIntervalSet.get_interval_set(interval[0], interval[1])
        else:
            alphabet = alphabet_str if alphabet_str is not None else self.default_dfa_alphabet_str
            domain = self._get_dfa_from_alphabet_str(alphabet)
        self.dim_dict[dim_name] = (dim_type, domain)

