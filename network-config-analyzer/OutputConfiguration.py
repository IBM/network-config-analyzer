#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#


class OutputConfiguration(dict):
    """
    a class to handle output configuration per query
    """

    def __init__(self, output_config_dict=None, query_name=''):
        default_output_config = {'fwRulesRunInTestMode': False, 'fwRulesDebug': False,
                                 'fwRulesGroupByLabelSinglePod': False, 'fwRulesFilterSystemNs': False,
                                 'fwRulesMaxIter': 10, 'fwRulesGeneralizeLabelExpr': False, 'outputFormat': 'txt',
                                 'outputPath': None, 'fwRulesOverrideAllowedLabels': None}
        super().__init__(default_output_config)
        if output_config_dict is not None:
            self.update(output_config_dict)

        self.queryName = query_name
        self.configName = ''

    def __getattr__(self, name):
        return super().__getitem__(name)

    def print_query_output(self, output, yaml_supported=False):
        """
        print accumulated query's output according to query's output config (in required format, to file or stdout)
        :param yaml_supported: bool flag indicating if query supports yaml output format
        :param output: string
        :return: None
        """
        if not yaml_supported and self['outputFormat'] == 'yaml':
            print('yaml output format is not supported for this query')
            return
        path = self['outputPath']
        if path is not None:
            # print output to a file
            try:
                with open(path, "a") as f:
                    f.write(output)
                print(f'wrote query output to: {path}')
            except FileNotFoundError:
                print(f"FileNotFoundError: configured outputPath is: {path}")
        else:
            # print output to stdout
            print(output)
