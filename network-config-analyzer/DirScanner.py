#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import os
from GenericTreeScanner import GenericTreeScanner


class DirScanner(GenericTreeScanner):
    """
       A class for reading yaml files from a file system path
    """

    def __init__(self, fs_path, rt_load=False):
        GenericTreeScanner.__init__(self, rt_load)
        self.fs_path = fs_path

    def check_and_yield_file(self, file_path):
        """
        checks if the given file is yaml file and yield its components
        :param str file_path: path of file to check and yield
        """
        if GenericTreeScanner.is_yaml_file(file_path):
            yield from self._yield_yaml_file(file_path, open(file_path))

    def get_yamls(self):
        """
        Call this function to get a generator for all yaml files
        """
        if os.path.isfile(self.fs_path):
            yield from self.check_and_yield_file(self.fs_path)
            return

        if self.fs_path.endswith('**'):
            yield from self._scan_dir_for_yamls(self.fs_path[:-2], True)
            return
        yield from self._scan_dir_for_yamls(self.fs_path, False)

    def _scan_dir_for_yamls(self, dir_path, recursive):
        for root, sub_dirs, files in os.walk(dir_path):
            if recursive:
                for sub_dir in sub_dirs:
                    self._scan_dir_for_yamls(os.path.join(root, sub_dir), recursive)
            for file in files:
                yield from self.check_and_yield_file(os.path.join(root, file))
