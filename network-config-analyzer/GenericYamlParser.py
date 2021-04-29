#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from sys import stderr
from ruamel.yaml import comments


class GenericYamlParser:
    """
    A base class for yaml parsers, providing basic services
    """
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
            raise SyntaxError(msg, (self.yaml_file_name, obj.lc.line, obj.lc.col, ''))
        raise SyntaxError(msg)

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

    def check_keys_are_legal(self, dict_to_check, dict_name, allowed_keys_names, allowed_values=()):
        """
        Check that all keys in dict_to_check are legal (appear in allowed_keys_names)
        and that all non-optional keys exist.
        For keys that get specific known values only, it checks that the existing value of the key in the given dict
        is in the allowed_values.
        Allowed values contains all the possible values of a key in the correct type (value and type check).
        :param dict dict_to_check: The dictionary for which the keys should be checked
        :param str dict_name: A name for the dictionary (providing context in error messages)
        :param dict allowed_keys_names: Map from allowed keys to usage code
        (0-optional, 1-must have, 2-not yet supported)
        :param dict allowed_values: Map from a key name to its allowed values (optional)
        :return: None
        :raises SyntaxError: if some of the keys are not allowed/missing
        """
        if dict_to_check:
            if not isinstance(dict_to_check, dict):
                self.syntax_error('type of ' + dict_name + 'is not a map', dict_to_check)
        for key, code in allowed_keys_names.items():
            if code == 1 and key not in dict_to_check:
                self.syntax_error(f'{dict_name} must have a {key} entry', dict_to_check)
            if code == 2 and key in dict_to_check:
                self.syntax_error(f'{key} is not yet supported inside {dict_name}', dict_to_check)
            if key in dict_to_check and key in allowed_values:
                value = dict_to_check.get(key)
                if value not in allowed_values[key]:
                    self.syntax_error(f'{key} has invalid value/type in {dict_name}')

        map_keys = set(dict_to_check.keys())
        allowed_keys = set(allowed_keys_names.keys())
        bad_policy_keys = map_keys.difference(allowed_keys)
        if bad_policy_keys:
            self.syntax_error(f'{bad_policy_keys.pop()} is not a valid entry in the specification of {dict_name}',
                              dict_to_check)
