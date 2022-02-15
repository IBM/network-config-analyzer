#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from sys import stderr
from ruamel.yaml import comments
from enum import Enum

from DimensionsManager import DimensionsManager


class GenericYamlParser:
    """
    A base class for yaml parsers, providing basic services
    """
    class FilterActionType(Enum):
        """
        Allowed actions for Calico's network policy rules
        """
        In = 0
        NotIn = 1
        Contain = 2
        StartWith = 3
        EndWith = 4

    def __init__(self, yaml_file_name=''):
        """
        :param str yaml_file_name: The name of the parsed file
        """
        self.yaml_file_name = yaml_file_name
        self.warning_msgs = []  # Collect all warning messages during parsing here

    def syntax_error(self, msg, obj=None):
        """
        Just raise a SyntaxError Exception, possibly with file-line-column context
        :param str msg: The message to print
        :param obj: optionally, a CommentedBase object with context
        :return: None
        """
        if isinstance(obj, comments.CommentedBase):
            raise SyntaxError(msg, (self.yaml_file_name, obj.lc.line, obj.lc.col, '')) from None
        raise SyntaxError(msg) from None

    def warning(self, msg, obj=None):
        """
        Print a warning message and store it for later use
        :param str msg: The message to print
        :param object obj: The object this message refers to
        :return: None
        """
        print_msg = 'Warning: ' + msg
        if isinstance(obj, comments.CommentedBase):
            print_msg = f'{self.yaml_file_name}:{obj.lc.line}:{obj.lc.col}: {print_msg}'

        print(print_msg, file=stderr)
        self.warning_msgs.append(msg)

    def check_fields_validity(self, dict_to_check, dict_name, allowed_keys, allowed_values=None):
        """
        Check that all keys in dict_to_check are legal (appear in allowed_keys)
        if value type is specified for a key, it checks valid type of values too
        and that all non-optional keys exist.
        For keys that get specific known values only, it checks that the existing value of the key in the given dict
        is in the allowed_values.
        Allowed values contains all the possible values of a key in the correct type (value and type check).
        :param dict dict_to_check: The dictionary for which the keys should be checked
        :param str dict_name: A name for the dictionary (providing context in error messages)
        :param dict allowed_keys: Map from allowed keys to usage code (0-optional, 1-must have, 2-not yet supported)
         and type (type is optional) - if type is specified, allowed_keys maps string to array.
        :param dict allowed_values: Map from a key name to its allowed values (optional)
        :return: None
        :raises SyntaxError: if some of the keys are not allowed/missing
        """

        for key, key_info in allowed_keys.items():
            if isinstance(key_info, list):
                code = key_info[0]
                value_type = key_info[1]
            else:
                code = key_info
                value_type = None
            if code == 1 and key not in dict_to_check:
                self.syntax_error(f'{dict_name} must have {key} entry', dict_to_check)
            if key in dict_to_check:
                if code == 2:
                    self.syntax_error(f'{key} is not yet supported inside {dict_name}', dict_to_check)
                value = dict_to_check.get(key)
                if code == 1 and value is None:
                    self.syntax_error(f'mandatory {key} value can not be null in {dict_name}', dict_to_check)
                if value_type is not None:
                    if value is not None and not isinstance(value, value_type):
                        self.syntax_error(f'type of {key} is not {value_type} in {dict_name}',
                                          dict_to_check)
                if allowed_values and key in allowed_values:
                    if value and value not in allowed_values[key]:
                        self.syntax_error(f'{key} has invalid value in {dict_name}')

        map_keys = set(dict_to_check.keys())
        allowed_entries = set(allowed_keys.keys())
        bad_policy_keys = map_keys.difference(allowed_entries)
        if bad_policy_keys:
            self.syntax_error(f'{bad_policy_keys.pop()} is not a valid entry in the specification of {dict_name}',
                              dict_to_check)

    def validate_existing_key_is_not_null(self, dict_elem, key):
        """
        check that if key exists in dict_elem, its value is not null
        :param dict_elem: dict  the element to check
        :param key: string  the key to validate
        :return:
        """
        if key in dict_elem and dict_elem.get(key) is None:
            self.syntax_error(f'Key: \'{key}\' cannot be null ')

    def validate_array_not_empty(self, array_elem, elem_name):
        """
        chack that array_elem is a non-empty array
        :param array_elem: list  the element to check
        :param elem_name:  string  the name of the element to check
        :return:
        """
        if not isinstance(array_elem, list):
            self.syntax_error(f'Key: \'{elem_name}\' should be an array ')
        if not array_elem:
            self.syntax_error(f'Key: \'{elem_name}\' cannot be empty ')

    def get_key_array_and_validate_not_empty(self, dict_elem, key):
        """
        check that for a given key in dict_elem, if it exists - its value is a non-empty array
        :param dict_elem:  dict element to check
        :param key: string   the key to check
        :return:
        """
        key_array = dict_elem.get(key)
        if key_array is not None:
            self.validate_array_not_empty(key_array, key)
            return key_array
        return None

    def validate_dict_elem_has_non_empty_array_value(self, dict_elem, dict_key_str):
        """
        assuming that dict values are of type arrays, checking that at least one of the arrays is not empty,
        and that dict_elem is not empty
        :param dict_elem: dict element to check
        :param dict_key_str: string  the name of the key to which the dict is mapped
        """
        arr_length_set = set(len(v) for v in dict_elem.values())
        if arr_length_set == {0} or not arr_length_set:
            self.syntax_error(f"{dict_key_str} cannot be empty ")

    def validate_value_in_domain(self, value, dim_name, array, value_name):
        """
        check that a given parsed value is valid by the defined domain of its associated dimension
        :param value: the value to validate
        :param dim_name:  the dimension name (which defines the domain)
        :param array: the element where this value is parsed from
        :param value_name: the name of the value (to be shown in error message)
        :return: None
        :raises SyntaxError: if the value is not within the defined domain for the relevant dimension
        """
        is_valid, err_message = DimensionsManager().validate_value_by_domain(value, dim_name, value_name)
        if not is_valid:
            self.syntax_error(err_message, array)
