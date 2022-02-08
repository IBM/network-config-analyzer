#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import os
import abc
from dataclasses import dataclass
from ruamel.yaml import YAML, error
from sys import stderr


@dataclass
class YamlFile:
    """
    A class for holding the retrieved data of a yaml file from git repo
    """
    data: object
    path: str


class GenericTreeScanner(abc.ABC):
    """
    A base class for reading yaml files
    """
    def __init__(self):
        pass

    @abc.abstractmethod
    def get_yamls(self):
        pass

    @staticmethod
    def is_yaml_file(file_name):
        """
        returns if the given file is a yaml file
        :param str file_name: the name of the file
        :rtype: bool
        """
        extension = os.path.splitext(file_name)[1]
        return extension in {'.yaml', '.yml', '.json'}

    @staticmethod
    def _yield_yaml_file(path, stream, from_repo=False):
        """
        yields the yaml file for its data
        :param str path: the path of the file
        :param stream: an IO-Text stream or Union of the file contents, depends on the scanner's type
        :param bool from_repo: indicates if the given path is from a repository
        """
        decoded_stream = stream
        if from_repo:
            decoded_stream = stream.decoded_content
        yaml = YAML(typ="safe")
        try:
            yield YamlFile(yaml.load_all(decoded_stream), path)
        except error.MarkedYAMLError as parse_error:
            print(parse_error.problem_mark.name + ':' + str(parse_error.problem_mark.line) + ':' +
                  str(parse_error.problem_mark.column) + ':', 'Parse Error:', parse_error.problem, file=stderr)
            return
        except error.YAMLError:
            print('Bad yaml file:', path, file=stderr)
            return


from GitScanner import GitScanner
from DirScanner import DirScanner


class TreeScannerFactory:

    @staticmethod
    def get_scanner(entry):
        """
        factory method to determine what scanner to build
        :param str entry: the entry (path/url) to be scanned
        """
        if entry.startswith(('https://github', GitScanner.raw_github_content_prefix)):
            return GitScanner(entry)
        elif os.path.isfile(entry) or os.path.isdir(entry) or (entry.endswith('**') and os.path.isdir(entry[:-2])):
            return DirScanner(entry)
        else:
            return None
