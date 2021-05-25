import os

import yaml


class ConfigFwRules:

    def __init__(self, config_file, config_name):
        self.config_file = config_file
        self.config_name = config_name
        self.attributes = ['run_in_test_mode', 'max_iter', 'filter_system_ns', 'expected_fw_rules_dir',
                           'override_result_file', 'create_output_files', 'expected_fw_rules_txt',
                           'expected_fw_rules_yaml', 'debug', 'use_pod_owner_name', 'use_pod_representative', 'group_by_label_single_pod']
        # assign default config params
        self.max_iter = 10
        self.run_in_test_mode = False # runs some extra checks and assertions
        self.debug = False  # adds debug printing
        self.use_pod_owner_name = True  #currently inactive as a flag
        self.use_pod_representative = False  #TODO: should remove this option?
        self.group_by_label_single_pod = False # TODO: should be an option?
        self.filter_system_ns = False
        self.override_result_file = True
        self.create_output_files = True
        self.expected_fw_rules_txt = None
        self.expected_fw_rules_yaml = None
        self.expected_fw_rules_dir = None
        self.expected_results_files = {'txt': '', 'yaml': ''}
        self.default_results_dir = 'fw_rules_output'
        self.default_res_file_name = config_name

        # update params from config file
        self._parse_config_file()

    def _parse_config_file(self):
        if self.config_file is None:
            return
        #print(os.getcwd())
        if os.path.exists(self.config_file):
            with open(self.config_file) as f:
                config_data_map = yaml.safe_load(f)
                for attr in self.attributes:
                    if attr in config_data_map:
                        setattr(self, attr, config_data_map[attr])

        else:
            print('fw-rules config file not found, using default config values')
        self._set_expected_results_files()
        return

    def _set_expected_results_files(self):
        if self.expected_fw_rules_dir is not None:
            if self.expected_fw_rules_txt is not None:
                txt_file_path = os.path.join(self.expected_fw_rules_dir, self.expected_fw_rules_txt)
            else:
                txt_file_path = os.path.join(self.expected_fw_rules_dir, self.config_name + '.txt')
            self.expected_results_files['txt'] = txt_file_path
            if self.expected_fw_rules_yaml is not None:
                yaml_file_path = os.path.join(self.expected_fw_rules_dir, self.expected_fw_rules_yaml)
            else:
                yaml_file_path = os.path.join(self.expected_fw_rules_dir, self.config_name + '.yaml')
            self.expected_results_files['yaml'] = yaml_file_path
        return
