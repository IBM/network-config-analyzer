#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import json
import os
import sys
from urllib import request
from nca.Utils.CmdlineRunner import CmdlineRunner


class OutputConfiguration(dict):
    """
    a class to handle output configuration per query
    """

    def __init__(self, output_config_dict=None, query_name=''):
        default_output_config = {'fwRulesRunInTestMode': False, 'fwRulesDebug': False,
                                 'fwRulesGroupByLabelSinglePod': False, 'fwRulesFilterSystemNs': False,
                                 'fwRulesMaxIter': 10, 'outputFormat': 'txt', 'outputPath': None,
                                 'simplifyGraph': False, 'fwRulesOverrideAllowedLabels': None, 'prURL': None,
                                 'connectivityFilterIstioEdges': True, 'outputEndpoints': 'deployments',
                                 'subset': {}, 'explain': None, 'fullExplanation': False, 'excludeIPv6Range': True}

        super().__init__(default_output_config)
        if output_config_dict is not None:
            self.update(output_config_dict)

        self.queryName = query_name
        self.configName = ''

    def __getattr__(self, name):
        return super().__getitem__(name)

    def print_query_output(self, output, supported_output_formats=None):
        """
        print accumulated query's output according to query's output config (in required format, to file or stdout)
        :param output: string
        :param supported_output_formats: set of strings with supported output formats for the query
        :return: None
        """
        if supported_output_formats is None:
            supported_output_formats = {'txt'}
        if self.outputFormat not in supported_output_formats:
            print(f'{self.outputFormat} output format is not supported for this query')
            return
        path = self.outputPath
        if path is not None:
            # print output to a file
            if self.outputFormat == 'jpg':
                tmp_dot_file = f'{path}.nca_tmp.dot'
                dot_cmd = ['dot', tmp_dot_file, '-Tjpg', f'-o{path}']
                try:
                    with open(tmp_dot_file, "w") as f:
                        f.write(output)
                    CmdlineRunner.run_and_get_output(dot_cmd)
                except Exception as e:
                    print(f'Failed to create a jpg file: {path}\n{e}', file=sys.stderr)
                if not os.path.isfile(path):
                    dot_cmd_string = ' '.join(dot_cmd)
                    print(f'Command {dot_cmd_string}\n did not create {path}\n', file=sys.stderr)
                if os.path.isfile(tmp_dot_file):
                    os.remove(tmp_dot_file)
            elif self.outputFormat == 'html':
                tmp_dot_file = f'{path}.nca_tmp.dot'
                dot_cmd = ['dot', tmp_dot_file, '-Tjpg', f'-o{path}']
                try:
                    with open(tmp_dot_file, "w") as f:
                        f.write(output)
                    CmdlineRunner.run_and_get_output(dot_cmd)
                except Exception as e:
                    print(f'Failed to create a jpg file: {path}\n{e}', file=sys.stderr)
                if not os.path.isfile(path):
                    dot_cmd_string = ' '.join(dot_cmd)
                    print(f'Command {dot_cmd_string}\n did not create {path}\n', file=sys.stderr)
                if os.path.isfile(tmp_dot_file):
                    os.remove(tmp_dot_file)

            else:
                try:
                    with open(path, "a") as f:
                        f.write(output)
                    print(f'wrote query output to: {path}')
                except FileNotFoundError:
                    print(f'FileNotFoundError: configured outputPath is: {path}', file=sys.stderr)
        elif self.prURL is not None:
            self.write_git_comment(output)
        else:
            # print output to stdout
            print(output)

    def write_git_comment(self, comment_body):
        """
        Add a comment to a PR
        :param str comment_body:
        :return: The code returned by the GitHub server (201 means OK)
        :rtype: int
        """
        if 'GHE_TOKEN' not in os.environ:
            print("ERROR: missing GHE_TOKEN")
            return 0
        if not self.prURL:
            print('Error: missing URL')
            return 0

        headers = {'Authorization': 'token {0:s}'.format(os.environ['GHE_TOKEN'])}
        data = {'body': comment_body}
        req = request.Request(self.prURL, headers=headers, data=json.dumps(data).encode('ascii'))
        with request.urlopen(req) as resp:
            if resp.status not in [200, 201]:
                print("request failed, status = ", resp.status, "URL:", self.prURL, "message = ", resp.read())
            else:
                print("request succeeded, status = ", resp.status, "message = ", resp.read())

            return resp.status
