#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import os
import io
from sys import stderr
from .GenericTreeScanner import GenericTreeScanner
from .HelmScanner import HelmScanner
from nca.Utils.NcaLogger import NcaLogger


class DirScanner(GenericTreeScanner, HelmScanner):
    """
       A class for reading yaml files from a file system path
    """

    def __init__(self, fs_path, rt_load=False):
        GenericTreeScanner.__init__(self, rt_load)
        HelmScanner.__init__(self)
        self.fs_path = fs_path

    def _check_and_yield_file(self, file_path):
        """
        checks if the given file is yaml file and yield its components
        :param str file_path: path of file to check and yield
        """
        if GenericTreeScanner.is_yaml_file(file_path):
            file_stream = open(file_path, encoding='utf8')
            yield from self._yield_yaml_file(file_path, file_stream)
            file_stream.close()

    def get_yamls(self):
        """
        Call this function to get a generator for all yaml files
        """
        if os.path.isfile(self.fs_path):
            yield from self._check_and_yield_file(self.fs_path)
            return

        if self.fs_path.endswith('**'):
            yield from self._scan_dir_for_yamls(self.fs_path[:-2], True)
            return
        yield from self._scan_dir_for_yamls(self.fs_path, False)

    def _scan_dir_for_yamls(self, dir_path, recursive):
        for root, sub_dirs, files in os.walk(dir_path):
            for file in files:
                try:
                    if self.is_helm_chart(file):
                        if not self.helm_path:
                            NcaLogger().log_message(msg=f'HELM is not installed - Skipping {root+file}', level='W')
                            continue
                        file_name, file_content = self.parse_chart(root)
                        file_stream = io.StringIO(file_content)
                        yield from self._yield_yaml_file(file_name, file_stream)
                        file_stream.close()
                    else:
                        full_path = os.path.abspath(os.path.join(root, file))
                        # skip if file was resolved by HELM or Helm template
                        if self.is_yaml_file(full_path) and not self.is_resolved_template(full_path):
                            if self.is_template(full_path):
                                print('Warning: Skipping templated yaml file:', full_path, file=stderr)
                            else:
                                yield from self._check_and_yield_file(os.path.join(root, file))
                except UnicodeDecodeError as decode_err:
                    print(f'Parse Error: While scanning {dir_path}, failed to decode {file}. error:\n{decode_err.reason}')
            if not recursive:
                break
