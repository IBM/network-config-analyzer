#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import os
import abc
from sys import stderr
from dataclasses import dataclass
import yaml


@dataclass
class YamlFile:
    """
    A class for holding the retrieved data of a yaml file from git repo
    """
    data: object
    path: str


class ObjectWithLocation:
    line_number = 0
    path = ''
    column_number = 0


class YamlDict(dict, ObjectWithLocation):
    pass


class YamlList(list, ObjectWithLocation):
    pass


def to_yaml_objects(yaml_node):
    if isinstance(yaml_node, yaml.SequenceNode):
        res = YamlList()
        res.line_number = yaml_node.start_mark.line
        res.path = yaml_node.start_mark.name
        res.column_number = yaml_node.start_mark.column
        for obj in yaml_node.value:
            res.append(to_yaml_objects(obj))
        return res
    if isinstance(yaml_node, yaml.MappingNode):
        res = YamlDict()
        res.line_number = yaml_node.start_mark.line + 1
        res.path = yaml_node.start_mark.name
        res.column_number = yaml_node.start_mark.column + 1
        for obj in yaml_node.value:
            res[obj[0].value] = to_yaml_objects(obj[1])
        return res

    # Node is a ScalarNode. First check if it can be interpreted as an int (e.g., port number)
    try:
        int_val = int(yaml_node.value)
        return int_val
    except ValueError:
        pass

    if not yaml_node.style:
        # Now check if it is Boolean
        if yaml_node.value == 'true':
            return True
        if yaml_node.value == 'false':
            return False
        # check if it's the null value
        if yaml_node.value in ['', 'null']:
            return None

    return yaml_node.value


def convert_documents(documents):
    return [to_yaml_objects(document) for document in documents]


class GenericTreeScanner(abc.ABC):
    """
    A base class for reading yaml files
    """
    def __init__(self, fast_load=False):
        """
        :param bool fast_load: if True, load yaml faster, without saving objects location in file
        """
        self.fast_load = fast_load

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

    def _yield_yaml_file(self, path, stream):
        """
        yields the yaml file for its data
        :param str path: the path of the file
        :param stream: an IO-Text stream or Union of the file contents, depends on the scanner's type
        """
        try:
            if self.fast_load:
                documents = yaml.load_all(stream, Loader=yaml.CSafeLoader)
            else:
                documents = convert_documents(yaml.compose_all(stream, Loader=yaml.CSafeLoader))
            yield YamlFile(documents, path)
        except yaml.MarkedYAMLError as parse_error:
            print(f'{parse_error.problem_mark.name}:{parse_error.problem_mark.line+1}:{parse_error.problem_mark.column+1}:',
                  'Parse Error:', parse_error.problem, file=stderr)
            return
        except yaml.YAMLError:
            print('Bad yaml file:', path, file=stderr)
            return


from .GitScanner import GitScanner  # noqa: E402
from .DirScanner import DirScanner  # noqa: E402


class TreeScannerFactory:

    @staticmethod
    def get_scanner(entry, fast_load=False):
        """
        factory method to determine what scanner to build
        :param str entry: the entry (path/url) to be scanned
        :param bool fast_load: if True, load yaml faster, without saving objects location in file
        """
        if entry.startswith(('https://github', GitScanner.raw_github_content_prefix)):
            return GitScanner(entry, fast_load)
        elif os.path.isfile(entry) or os.path.isdir(entry) or (entry.endswith('**') and os.path.isdir(entry[:-2])):
            return DirScanner(entry, fast_load)
        else:
            return None
