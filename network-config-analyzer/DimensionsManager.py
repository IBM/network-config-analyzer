#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
from enum import Enum
from CanonicalIntervalSet import CanonicalIntervalSet
from MethodSet import MethodSet
from MinDFA import MinDFA


class DimensionsManager:
    """
    A singleton class to manage dimensions names and their association to type and domain.
    The dimensions are related to certain protocol's properties in ConnectionSet.
    They are used for allowed connection representation, as protocols properties, within CanonicalHyperCubeSet objects.
    """

    class DimensionType(Enum):
        IntervalSet = 0
        DFA = 1

    # the inner class is needed to make the outer class a singleton
    class __DimensionsManager:
        def __init__(self):
            # TODO: verify alphabet for regex type dimensions, currently using one default alphabet
            #  currently valid chars are: ['.', '/', '-', 0-9, a-z, A-Z ]
            self.default_dfa_alphabet_chars = ".\\w/\\-"
            self.default_dfa_alphabet_str = "[" + self.default_dfa_alphabet_chars + "]*"
            self.default_interval_domain_tuple = (0, 100000)
            self.domain_str_to_dfa_map = dict()
            dfa_all_words_default = self._get_dfa_from_alphabet_str(self.default_dfa_alphabet_str)
            ports_interval = CanonicalIntervalSet.get_interval_set(1, 65535)
            all_methods_interval = MethodSet(True)
            self.dim_dict = dict()
            self.dim_dict["src_ports"] = (DimensionsManager.DimensionType.IntervalSet, ports_interval)
            self.dim_dict["dst_ports"] = (DimensionsManager.DimensionType.IntervalSet, ports_interval)
            self.dim_dict["methods"] = (DimensionsManager.DimensionType.IntervalSet, all_methods_interval)
            self.dim_dict["paths"] = (DimensionsManager.DimensionType.DFA, dfa_all_words_default)
            self.dim_dict["hosts"] = (DimensionsManager.DimensionType.DFA, dfa_all_words_default)

            icmp_type_interval = CanonicalIntervalSet.get_interval_set(0, 254)
            icmp_code_interval = CanonicalIntervalSet.get_interval_set(0, 255)
            self.dim_dict["icmp_type"] = (DimensionsManager.DimensionType.IntervalSet, icmp_type_interval)
            self.dim_dict["icmp_code"] = (DimensionsManager.DimensionType.IntervalSet, icmp_code_interval)

        def _get_dfa_from_alphabet_str(self, alphabet_str):
            """
            get a MinDFA object for an input alphabet_str
            :param alphabet_str: regex in greenery format to express the str dimension domain
            :return: MinDFA object
            """
            # for performance considerations - use caching at domain_str_to_dfa_map
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
        """
        get dimension's type from its name
        :param str dim_name: dimension name
        :return:  DimensionsManager.DimensionType: the type value
        """
        return self.dim_dict[dim_name][0]

    def get_dimension_domain_by_name(self, dim_name):
        """
        get dimensions domain from its name
        :param str dim_name: dimension name
        :return: CanonicalIntervalSet object or MinDFA object  (depends on dimension type)
        """
        return self.dim_dict[dim_name][1]

    def set_domain(self, dim_name, dim_type, interval_tuple=None, alphabet_str=None):
        """
        set a new dimension, or change an existing dimension
        :param str dim_name: dimension name
        :param DimensionsManager.DimensionType dim_type: dimension type
        :param tuple(int,int) interval_tuple:  for interval domain value
        :param str alphabet_str: regex in greenery format to express the str dimension domain
        """
        if dim_type == DimensionsManager.DimensionType.IntervalSet:
            interval = interval_tuple if interval_tuple is not None else self.default_interval_domain_tuple
            domain = CanonicalIntervalSet.get_interval_set(interval[0], interval[1])
        else:
            alphabet = alphabet_str if alphabet_str is not None else self.default_dfa_alphabet_str
            domain = self._get_dfa_from_alphabet_str(alphabet)
        self.dim_dict[dim_name] = (dim_type, domain)

    def validate_value_by_domain(self, value, dim_name, value_name):
        """
        validate that value is valid, within the defined set of values by the dimension domain
        return validation result and error str if invalid
        :param Union[int,str] value: a value to validate (int or str, depends on the dimension type)
        :param str dim_name: dimension name
        :param str value_name: name of the value (to be used in error message)
        :return: tuple(valid_res, err_str), where:
            valid_res: a bool flag to indicate if value is valid by dimension domain
            err_str: str: a description of the error if value is invalid
        """
        dim_type = self.get_dimension_type_by_name(dim_name)
        dim_domain = self.get_dimension_domain_by_name(dim_name)
        if dim_type == DimensionsManager.DimensionType.IntervalSet:
            assert isinstance(value, int)
            is_valid = value in dim_domain
            if not is_valid:
                return False, f'{value_name} must be in the range {dim_domain}'
        # TODO: handle also validation for str value in regex domain
        return True, ''

    def get_dim_values_str(self, dim_values, dim_name):
        """
        :param Union[CanonicalIntervalSet, MinDFA] dim_values: dimension values object
        :param str dim_name: string of a dimension name
        :return: str: a string representing the values in dim_values, under dimension dim_name
        """
        dim_type = self.get_dimension_type_by_name(dim_name)
        dim_domain = self.get_dimension_domain_by_name(dim_name)

        if dim_type == DimensionsManager.DimensionType.IntervalSet:
            if len(dim_values) > 1:
                return '{' + str(dim_values) + '}'
            return str(dim_values)  # dim_values should be of type CanonicalIntervalSet
        else:  # dim_values should be of type MinDFA
            if dim_values.has_finite_len():
                return str(dim_values)  # return set of words accepted by this MinDFA
            all_words_dfa = dim_domain
            # TODO: for istio regex the "*" corresponds to any string but empty
            if dim_values.is_dfa_wll_words(all_words_dfa):
                return "*"
            # complement dfa
            complement_dfa = dim_values.complement_dfa if dim_values.complement_dfa is not None else \
                all_words_dfa - dim_values
            if complement_dfa.has_finite_len():
                return f'all but {complement_dfa}'  # return set of words not accepted by this MinDFA
            return str(dim_values)  # return regex representing this MinDFA
