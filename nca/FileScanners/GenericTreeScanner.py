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
    column_number = 0


class YamlDict(dict, ObjectWithLocation):
    pass


class YamlList(list, ObjectWithLocation):
    pass


def to_yaml_objects(yaml_node):
    if isinstance(yaml_node, yaml.SequenceNode):
        res = YamlList()
        res.line_number = yaml_node.start_mark.line
        res.column_number = yaml_node.start_mark.column
        for obj in yaml_node.value:
            res.append(to_yaml_objects(obj))
        return res
    if isinstance(yaml_node, yaml.MappingNode):
        res = YamlDict()
        res.line_number = yaml_node.start_mark.line
        res.column_number = yaml_node.start_mark.column
        for obj in yaml_node.value:
            res[obj[0].value] = to_yaml_objects(obj[1])
        return res

    try:
        int_val = int(yaml_node.value)
        return int_val
    except ValueError:
        pass

    if yaml_node.style is None and yaml_node.value in ['', 'null']:
        return None

    return yaml_node.value


def convert_documents(documents):
    res = []
    for document in documents:
        yaml_object_doc = to_yaml_objects(document)
        res.append(yaml_object_doc)
    return res


class GenericTreeScanner(abc.ABC):
    """
    A base class for reading yaml files
    """
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
        documents = yaml.compose_all(stream, Loader=yaml.SafeLoader)
        try:
            yield YamlFile(convert_documents(documents), path)
        except yaml.MarkedYAMLError as parse_error:
            print(f'{parse_error.problem_mark.name}:{parse_error.problem_mark.line}:{parse_error.problem_mark.column}:',
                  'Parse Error:', parse_error.problem, file=stderr)
            return
        except yaml.YAMLError:
            print('Bad yaml file:', path, file=stderr)
            return


from .GitScanner import GitScanner  # noqa: E402
from .DirScanner import DirScanner  # noqa: E402


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
