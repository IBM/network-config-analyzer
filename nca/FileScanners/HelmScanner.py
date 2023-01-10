#
# Copyright 2022- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

"""
Utility class to control HELM
"""

import os
import re
from nca.Utils.CmdlineRunner import CmdlineRunner


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
        :return: str filename: the char file that was resolved
                 str resolved_yamls: the parsed yamel string
        """
        # Get Helm buffer and convert from a BYTE buffer to string
        resolved_yamls = CmdlineRunner.resolve_helm_chart(chart_dir).decode('UTF-8')

        # insert Chart and Values into the templates list, so they will be not parsed again.
        self.template_files.append(os.path.join(chart_dir, 'Chart.yaml'))
        self.template_files.append(os.path.join(chart_dir, 'values.yaml'))

        file_names = re.findall('# Source: \\w*(.*\\.yaml)', resolved_yamls)
        for file_name in file_names:
            file_name = os.path.abspath(chart_dir + file_name)
            self.template_files.append(file_name)
        self.template_files = list(set(self.template_files))

        return os.path.join(chart_dir, 'Chart.yaml'), resolved_yamls

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
        :param str file: file path to check
        :return: bool
        """
        if not file:
            return False
        with open(file, "r", encoding='utf8') as f:
            return '{{' in f.read()

    @staticmethod
    def is_helm_chart(file):
        """
        Check if the given file is a Helm chart
        :param file: file path to check
        :return: bool
        """
        return file in {'Chart.yaml', 'chart.yaml'}
