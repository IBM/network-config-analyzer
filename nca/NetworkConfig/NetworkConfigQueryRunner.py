#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
from nca.Utils.OutputFilesFlags import OutputFilesFlags
from nca.Resources.NetworkPolicy import NetworkPolicy
from .NetworkConfig import NetworkConfig
from . import NetworkConfigQuery


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

    def _parse_network_config_of_specified_policy(self, config_name):
        """
        User wants a specific policy from the given config.
        config_name has one of the following forms:
        (1) <config>/<namespace>/<policy>
        (2) <config>/<kind>/<namespace>/<policy>/ , where kind is the relevant kind from:
        ['K8sNetworkPolicy', 'CalicoNetworkPolicy', 'CalicoGlobalNetworkPolicy','IstioAuthorizationPolicy', 'K8sIngress']
        :param str config_name: the full config name (from which a specific policy is requested)
        :return: the parsed config name, policy name, policy type
        :rtype: (str, str, NetworkPolicy.PolicyType)
        """
        sep_count = config_name.count('/')
        split_config = config_name.split('/', 1)
        config_name = split_config[0]
        policy_type = None
        if sep_count <= 2:
            policy_name = split_config[1]
        elif sep_count == 3:
            split_layer = split_config[1].split('/', 1)
            kind = split_layer[0]
            policy_name = split_layer[1]
            policy_type = NetworkPolicy.PolicyType.input_kind_name_str_to_policy_type(kind)
            if policy_type is None:
                raise Exception(f'Policy kind {kind} is not supported')
        else:
            raise Exception(f'Invalid config name {config_name}')
        if config_name not in self.network_configs:
            raise Exception(f'NetworkPolicyList {config_name} is undefined')
        return config_name, policy_name, policy_type

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

        # User wants a specific policy from the given config
        config_name, policy_name, policy_type = self._parse_network_config_of_specified_policy(config_name)
        # TODO: should preserve all active layers from original config?  or just the layer of the requested policy?
        #  example: if orig config has heps with calico and istio, but chosen policy is from istio, we would need
        #  calico layer to have default deny for hep.
        return self.network_configs[config_name].clone_with_just_one_policy(policy_name, policy_type)

    def run_query(self, cmd_line_flag=False):
        """
        runs the query based on the self.query_name
        :param bool cmd_line_flag: indicates if the query arg is given in the cmd-line
        :return: a 3-tuple with:
          - res: The result of running the query
          - comparing_err: flag to indicate if query output matches the expected output
          - not_executed: when > 0, indicates that the query was not executed for all configs
        rtype: (int, int, int)
        """
        query_to_exec = getattr(NetworkConfigQuery, self.query_name)  # for calling static methods
        formats = query_to_exec.get_supported_output_formats()
        query_type = query_to_exec.get_query_type()
        if query_type == NetworkConfigQuery.QueryType.SingleConfigQuery:
            res, query_output, not_executed = self._run_query_for_each_config()
        else:
            if len(self.configs_array) <= 1:
                return 0
            if query_type == NetworkConfigQuery.QueryType.ComparisonToBaseConfigQuery:
                res, query_output, not_executed = self._run_query_on_configs_vs_base_config(cmd_line_flag)

            elif query_type == NetworkConfigQuery.QueryType.PairComparisonQuery:
                res, query_output, not_executed = self._run_query_on_config_vs_followed_configs(cmd_line_flag)

            else:  # pairWiseInterferes
                res, query_output, not_executed = self._run_query_on_all_pairs()
        if not_executed:
            print(f'Warning: {self.query_name} was not executed on all input configs.')
        comparing_err = 0
        self.output_configuration.print_query_output(query_output, formats)
        if self.expected_output_file is not None:
            if self.output_configuration.fullExplanation:
                comparing_err = self._compare_actual_vs_expected_output(query_output)
            else:
                print(f'Warning: expectedOutput is not relevant for {self.query_name}. '
                      'Output compare will not occur')
        return res, comparing_err, not_executed

    def _execute_one_config_query(self, query_type, config):
        query_to_exec = getattr(NetworkConfigQuery, query_type)(config, self.output_configuration)
        return query_to_exec.execute_and_compute_output_in_required_format()

    def _execute_pair_configs_query(self, query_type, config1, config2, cmd_line_flag=False):
        query_to_exec = getattr(NetworkConfigQuery, query_type)(config1, config2, self.output_configuration)
        return query_to_exec.execute_and_compute_output_in_required_format(cmd_line_flag)

    def _run_query_for_each_config(self):
        res = 0
        output = ''
        queries_not_executed = 0
        for config in self.configs_array:
            query_res, query_output, query_not_executed =\
                self._execute_one_config_query(self.query_name, self._get_config(config))
            res += query_res
            output += query_output + '\n'
            queries_not_executed += query_not_executed
        return res, output, queries_not_executed

    def _run_query_on_configs_vs_base_config(self, cmd_line_flag):
        res = 0
        output = ''
        queries_not_executed = 0
        base_config = self._get_config(self.configs_array[0])
        for config in self.configs_array[1:]:
            query_res, query_output, query_not_executed = self._execute_pair_configs_query(
                self.query_name, self._get_config(config), base_config, cmd_line_flag)
            res += query_res
            output += query_output + '\n'
            queries_not_executed += query_not_executed
        return res, output, queries_not_executed

    def _run_query_on_config_vs_followed_configs(self, cmd_line_flag):
        res = 0
        output = ''
        queries_not_executed = 0
        for ind1 in range(len(self.configs_array) - 1):
            config1 = self.configs_array[ind1]
            for ind2 in range(ind1 + 1, len(self.configs_array)):
                query_res, query_output, query_not_executed = self._execute_pair_configs_query(
                    self.query_name, self._get_config(config1), self._get_config(self.configs_array[ind2]),
                    cmd_line_flag)
                res += query_res
                output += query_output + '\n'
                queries_not_executed += query_not_executed
        return res, output, queries_not_executed

    def _run_query_on_all_pairs(self):
        res = 0
        output = ''
        queries_not_executed = 0
        for config1 in self.configs_array:
            for config2 in self.configs_array:
                if config1 != config2:
                    query_res, query_output, query_not_executed = self._execute_pair_configs_query(
                        self.query_name, self._get_config(config1), self._get_config(config2))
                    res += query_res
                    output += query_output + '\n'
                    queries_not_executed += query_not_executed
        return res, output, queries_not_executed

    def _compare_actual_vs_expected_output(self, query_output):
        print('Comparing actual query output to expected-results file {0}'.format(self.expected_output_file))
        actual_output_lines = query_output.split('\n')
        try:
            with open(self.expected_output_file, 'r') as golden_file:
                if OutputFilesFlags().update_expected_files:
                    self._create_or_update_query_output_file(query_output)
                    return 0
                golden_file_line_num = 0
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
                if golden_file_line_num != len(actual_output_lines) - 1:
                    # allow a few empty lines in actual results
                    for i in range(golden_file_line_num + 1, len(actual_output_lines)):
                        if actual_output_lines[i]:
                            print('Error: Expected results have less lines than actual results')
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
