#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import os
from TreeGenericScanner import TreeGenericScanner


class DirScanner(TreeGenericScanner):
    """
       A class for reading yaml files from a file system path
    """

    def __init__(self, fs_path, np_scanner):
        TreeGenericScanner.__init__(self, TreeGenericScanner.ScannerType.FileSystemPath, np_scanner)
        self.fs_path = fs_path

    def check_and_yield_file(self, file_path):
        if TreeGenericScanner.is_yaml_file(file_path):
            yield from self._yield_yaml_file(file_path, open(file_path))

    def get_yamls(self):
        """
        Call this function to get a generator for all yaml files
        """
        if os.path.isfile(self.fs_path):
            yield from self.check_and_yield_file(self.fs_path)

        for root, _, files in os.walk(self.fs_path):
            for file in files:
                yield from self.check_and_yield_file(os.path.join(root, file))
