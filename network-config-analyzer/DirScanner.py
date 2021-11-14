#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import os
from GenericScanner import GenericScanner


class DirScanner(GenericScanner):
    """
       A class for reading yaml files from a file system path
    """

    def __init__(self, fs_path):
        GenericScanner.__init__(self, GenericScanner.ScannerType.FileSystemPath)
        self.fs_path = fs_path

    def get_yamls_in_dir(self):
        """
        Call this function to get a generator for all yamls in the directory
        """
        for root, _, files in os.walk(self.fs_path):
            for file in files:
                if not GenericScanner.is_yaml_file(file):
                    continue
                file_with_path = os.path.join(root, file)
                yield from self._yield_yaml_file(file_with_path, open(file_with_path))
