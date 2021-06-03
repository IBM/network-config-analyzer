import os

import yaml


class OutputConfiguration:
    """
    a class to handle output configuration per query
    """
    def __init__(self, output_config_dict=None):

        self.attributes = ['fwRulesRunInTestMode', 'fwRulesDebug', 'fwRulesGroupByLabelSinglePod',
                           'fwRulesFilterSystemNs', 'fwRulesMaxIter', 'fwRulesOutputFormat', 'outputPath']
        self.output_config_dict = output_config_dict
        # assign default values for each config attribute
        self.fwRulesRunInTestMode = False
        self.fwRulesDebug = False
        self.fwRulesGroupByLabelSinglePod = False
        self.fwRulesFilterSystemNs = False
        self.fwRulesMaxIter = 10
        self.fwRulesOutputFormat = 'txt'
        self.outputPath = None
        self.queryName = ''

        # get values from output_config_dict if exists
        if self.output_config_dict is not None:
            for (key, val) in output_config_dict.items():
                if key in self.attributes:
                    # print('setting pair in config: ' + str(key) + ' , ' + str(val))
                    setattr(self, key, val)

    def print_query_output(self, output):
        """
        print query's output according to query's output config.
        currently only supported/used for connectivity query and for semantic-diff query.
        using only the fw-rules output to be redirected to file if outputPath is configured .
        :param output: string
        :return: None
        """
        if self.outputPath is not None:
            # print output to a file
            try:
                f = open(self.outputPath, "a")
                f.write(output)
                f.close()
            except FileNotFoundError:
                print(f"FileNotFoundError: configured outputPath is: {self.outputPath}")
        else:
            # print output to stdout
            print(output)

