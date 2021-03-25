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

    def check_keys_are_legal(self, dict_to_check, dict_name, allowed_entries):
        """
        Check that all keys in dict_to_check are legal (appear in allowed_entries) and that all non-optional keys exist.
        :param dict dict_to_check: The dictionary for which the keys should be checked
        :param str dict_name: A name for the dictionary (providing context in error messages)
        :param dict allowed_entries: Map from allowed keys to usage code (0-optional, 1-must have, 2-not yet supported)
        :return: None
        :raises SyntaxError: if some of the keys are not allowed/missing
        """
        for key, code in allowed_entries.items():
            if code == 1 and key not in dict_to_check:
                self.syntax_error(f'{dict_name} must have a {key} entry', dict_to_check)
            if code == 2 and key in dict_to_check:
                self.syntax_error(f'{key} is not yet supported inside {dict_name}', dict_to_check)

        map_keys = set(dict_to_check.keys())
        allowed_keys = set(allowed_entries.keys())
        bad_policy_keys = map_keys.difference(allowed_keys)
        if bad_policy_keys:
            self.syntax_error(f'{bad_policy_keys.pop()} is not a valid entry in the specification of {dict_name}',
                              dict_to_check)
