#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import os
from enum import Enum
from dataclasses import dataclass
from sys import stderr
import yaml


@dataclass
class YamlFile:
    """
    A class for holding the retrieved data of a yaml file from git repo
    """
    data: object
    path: str


class GenericScanner:
    """
    A base class for reading yaml files
    """

    class ScannerType(Enum):
        """
        A class that represents what to be scanned
        """
        GitUrl = 0
        FileSystemPath = 1

    def __init__(self, scanner_type):
        self.scanner_type = scanner_type

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
        decoded_stream = stream
        if self.scanner_type == GenericScanner.ScannerType.GitUrl:
            decoded_stream = stream.decoded_content
        try:
            yield YamlFile(yaml.load_all(decoded_stream, Loader=yaml.SafeLoader), path)
        except yaml.YAMLError:
            print('Bad yaml file:', path, file=stderr)
            return
