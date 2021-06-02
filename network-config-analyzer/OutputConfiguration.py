import os
import yaml


class OutputConfiguration:
    def __init__(self, output_config_file):
        self.output_config_file = output_config_file
        self.attributes = ['fwRulesRunInTestMode', 'fwRulesDebug', 'fwRulesGroupByLabelSinglePod',
                           'fwRulesFilterSystemNs', 'fw_rules_max_iter', 'fwRulesYamlOutputPath']

        # assign default values for each config attribute
        self.fwRulesRunInTestMode = False
        self.fwRulesDebug = False
        self.fwRulesGroupByLabelSinglePod = False
        self.fwRulesFilterSystemNs = False
        self.fwRulesMaxIter = 10
        self.fwRulesYamlOutputPath = ''

        # get values from output config file if exists
        if self.output_config_file is not None:
            if os.path.exists(self.output_config_file):
                self._parse_output_config_file()
            else:
                print(
                    f'warning: could not find outputConfiguration path at: {self.output_config_file}, using the default '
                    f'output configuration instead ')
        #else:
        #    print('using default output config values, as output_config_file is None ')

    def _parse_output_config_file(self):
        #print(f'using file: {self.output_config_file} for output config values ')
        with open(self.output_config_file) as f:
            config_data_map = yaml.safe_load(f)
            for attr in self.attributes:
                if attr in config_data_map:
                    setattr(self, attr, config_data_map[attr])
