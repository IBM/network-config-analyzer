import NetworkConfigQuery
from NetworkConfig import NetworkConfig
from OutputFilesFlags import OutputFilesFlags


class NetworkConfigQueryRunner:
    """
    A Class for Running Queries
    """

    def __init__(self, key_name, configs_array, expected_output, output_configuration, network_configs=None):
        self.query_name = f'{key_name[0].upper()+key_name[1:]}Query'
        self.configs_array = configs_array
        self.output_configuration = output_configuration
        self.network_configs = network_configs
        self.expected_output_file = expected_output

    def _get_config(self, config_name):
        """
        :param str config_name: The name of a previously defined config or a policy within a previously defined config
        :return: A NetworkConfig object for the requested config
        :rtype: NetworkConfig
        """
        if isinstance(config_name, NetworkConfig):
            return config_name
        if '/' not in config_name:  # plain config name
            if config_name not in self.network_configs:
                raise Exception(f'NetworkPolicyList {config_name} is undefined')
            return self.network_configs[config_name]

        # User wants a specific policy from the given config. config_name has the form <config>/<namespace>/<policy>
        split_config = config_name.split('/', 1)
        config_name = split_config[0]
        policy_name = split_config[1]
        if config_name not in self.network_configs:
            raise Exception(f'NetworkPolicyList {config_name} is undefined')
        return self.network_configs[config_name].clone_with_just_one_policy(policy_name)

    def run_query(self, cmd_line_flag=False):
        """
        runs the query based on the self.query_name
        :param bool cmd_line_flag: indicates if the query arg is given in the cmd-line
        rtype: (int, int)
        """
        query_to_exec = getattr(NetworkConfigQuery, self.query_name)  # for calling static methods
        formats = query_to_exec.get_supported_output_formats()
        query_type = query_to_exec.get_query_type()
        if query_type == NetworkConfigQuery.QueryType.SingleConfigQuery:
            res, query_output = self._run_query_for_each_config()

        else:
            if len(self.configs_array) <= 1:
                return 0
            if query_type == NetworkConfigQuery.QueryType.ComparisonToBaseConfigQuery:
                res, query_output = self._run_query_on_configs_vs_base_config(cmd_line_flag)

            elif query_type == NetworkConfigQuery.QueryType.PairComparisonQuery:
                res, query_output = self._run_query_on_config_vs_followed_configs(cmd_line_flag)

            else:  # pairWiseInterferes
                res, query_output = self._run_query_on_all_pairs()
        comparing_err = 0
        self.output_configuration.print_query_output(query_output, formats)
        if self.expected_output_file is not None:
            if self.query_name in {'ConnectivityMapQuery', 'SemanticDiffQuery'}:
                comparing_err = self._compare_actual_vs_expected_output(query_output)
            else:
                print(f'Warning: expectedOutput is not relevant for {self.query_name}. '
                      'Output compare will not occur')
        return res, comparing_err

    def _execute_one_config_query(self, query_type, config):
        query_to_exec = getattr(NetworkConfigQuery, query_type)(config, self.output_configuration)
        return query_to_exec.compute_query_output(query_to_exec.exec())

    def _execute_pair_configs_query(self, query_type, config1, config2, cmd_line_flag=False):
        query_to_exec = getattr(NetworkConfigQuery, query_type)(config1, config2, self.output_configuration)
        return query_to_exec.compute_query_output(query_to_exec.exec(), cmd_line_flag)

    def _run_query_for_each_config(self):
        res = 0
        output = ''
        for config in self.configs_array:
            query_res, query_output = self._execute_one_config_query(self.query_name, self._get_config(config))
            res += query_res
            output += query_output + '\n'
        return res, output

    def _run_query_on_configs_vs_base_config(self, cmd_line_flag):
        res = 0
        output = ''
        base_config = self._get_config(self.configs_array[0])
        for config in self.configs_array[1:]:
            query_res, query_output = self._execute_pair_configs_query(
                self.query_name, self._get_config(config), base_config, cmd_line_flag)
            res += query_res
            output += query_output + '\n'
        return res, output

    def _run_query_on_config_vs_followed_configs(self, cmd_line_flag):
        res = 0
        output = ''
        for ind1 in range(len(self.configs_array) - 1):
            config1 = self.configs_array[ind1]
            for ind2 in range(ind1 + 1, len(self.configs_array)):
                query_res, query_output = self._execute_pair_configs_query(
                    self.query_name, self._get_config(config1), self._get_config(self.configs_array[ind2]),
                    cmd_line_flag)
                res += query_res
                output += query_output + '\n'
        return res, output

    def _run_query_on_all_pairs(self):
        res = 0
        output = ''
        for config1 in self.configs_array:
            for config2 in self.configs_array:
                if config1 != config2:
                    query_res, query_output = self._execute_pair_configs_query(
                        self.query_name, self._get_config(config1), self._get_config(config2))
                    res += query_res
                    output += query_output + '\n'
        return res, output

    def _compare_actual_vs_expected_output(self, query_output):
        print('Comparing actual query output to expected-results file {0}'.format(self.expected_output_file))
        actual_output_lines = query_output.split('\n')
        try:
            with open(self.expected_output_file, 'r') as golden_file:
                if OutputFilesFlags().update_expected_files:
                    self._create_or_update_query_output_file(query_output)
                    return 0
                for golden_file_line_num, golden_file_line in enumerate(golden_file):
                    if golden_file_line_num >= len(actual_output_lines):
                        print('Error: Expected results have more lines than actual results')
                        print('Comparing Result Failed \n')
                        return 1
                    if golden_file_line.rstrip() != actual_output_lines[golden_file_line_num]:
                        print(f'Error: Result mismatch at line {golden_file_line_num + 1} ')
                        print(golden_file_line)
                        print(actual_output_lines[golden_file_line_num])
                        print('Comparing Result Failed \n')
                        return 1
        except FileNotFoundError:
            if OutputFilesFlags().create_expected_files:
                self._create_or_update_query_output_file(query_output)
                return 0
            print('Error: Expected output file not found')
            return 1

        print('Comparing Results Passed \n')
        return 0

    def _create_or_update_query_output_file(self, query_output):
        output_file = open(self.expected_output_file, 'w')
        output_file.write(query_output)
