#
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

"""
Utility class to control HELM
"""

import os
from CmdlineRunner import CmdlineRunner
import re


class HelmScanner:
    """
       A class for handling HELM and resolving HELM Charts
    """

    def __init__(self):
        self.template_files = []

    def parse_chart(self, chart_dir):
        """
        Resolve HELM Chart file and parse it for yamls.
        :param chart_dir: The path of the Chart package
        :return: dict: dict of yaml filenames and their resolved content
        """
        resolved_yamls_dict = {}
        resolved_yamls = CmdlineRunner.resolve_helm_chart(chart_dir)[:-1]
        resolved_yamls = str(resolved_yamls).encode('ascii', 'ignore').decode('unicode_escape')
        resolved_yamls = resolved_yamls[:-1]
        resolved_yamls_list = str(resolved_yamls).split('---')[1:]

        # insert Chart and Values into the templates list, so they will be not parsed again.
        self.template_files.append(os.path.join(chart_dir, 'Chart.yaml'))
        self.template_files.append(os.path.join(chart_dir, 'values.yaml'))

        for index, file in enumerate(resolved_yamls_list):
            file_name = re.findall('# Source: (.*\\.yaml)', file)[0]

            # create the full path from the chart dir
            file_name_idx = str(file_name).find('/')
            file_name = file_name[file_name_idx + 1:]
            file_name = os.path.join(chart_dir, file_name)
            file_name = file_name.replace('/', '\\')
            self.template_files.append(file_name)
            resolved_yamls_dict[file_name] = file

        return resolved_yamls_dict

    def is_resolved_template(self, file):
        """
        Check if a given file was already resolved
        :param file: file path to check
        :return: bool
        """
        return file in self.template_files

    @staticmethod
    def is_template(file):
        """
        Check if the given file is templated or not
        :param file: file path to check
        :return: bool
        """
        if not file:
            return False
        f = open(file, "r")
        is_template = '{{' in f.read()
        f.close()
        return is_template

    @staticmethod
    def is_helm_chart(file):
        """
        Check if the given file is a Helm chart
        :param file: file path to check
        :return: bool
        """
        return file in {'Chart.yaml', 'chart.yaml'}
