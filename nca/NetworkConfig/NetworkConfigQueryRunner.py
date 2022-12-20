#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import json
import yaml

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
        res, output, queries_not_executed = self._init_query_results_values()
        for config in self.configs_array:
            query_res, query_output, query_not_executed =\
                self._execute_one_config_query(self.query_name, self._get_config(config))
            res, output, queries_not_executed = \
                self._update_query_results_after_one_iteration(res, query_res, output, query_output,
                                                               queries_not_executed, query_not_executed)
        return self._return_final_query_results(res, output, queries_not_executed)

    def _run_query_on_configs_vs_base_config(self, cmd_line_flag):
        res, output, queries_not_executed = self._init_query_results_values()
        base_config = self._get_config(self.configs_array[0])
        for config in self.configs_array[1:]:
            query_res, query_output, query_not_executed = self._execute_pair_configs_query(
                self.query_name, self._get_config(config), base_config, cmd_line_flag)
            res, output, queries_not_executed = \
                self._update_query_results_after_one_iteration(res, query_res, output, query_output,
                                                               queries_not_executed, query_not_executed)
        return self._return_final_query_results(res, output, queries_not_executed)

    def _run_query_on_config_vs_followed_configs(self, cmd_line_flag):
        res, output, queries_not_executed = self._init_query_results_values()
        for ind1 in range(len(self.configs_array) - 1):
            config1 = self.configs_array[ind1]
            for ind2 in range(ind1 + 1, len(self.configs_array)):
                query_res, query_output, query_not_executed = self._execute_pair_configs_query(
                    self.query_name, self._get_config(config1), self._get_config(self.configs_array[ind2]),
                    cmd_line_flag)
                res, output, queries_not_executed = \
                    self._update_query_results_after_one_iteration(res, query_res, output, query_output,
                                                                   queries_not_executed, query_not_executed)
        return self._return_final_query_results(res, output, queries_not_executed)

    def _run_query_on_all_pairs(self):
        res, output, queries_not_executed = self._init_query_results_values()
        for config1 in self.configs_array:
            for config2 in self.configs_array:
                if config1 != config2:
                    query_res, query_output, query_not_executed = self._execute_pair_configs_query(
                        self.query_name, self._get_config(config1), self._get_config(config2))
                    res, output, queries_not_executed = \
                        self._update_query_results_after_one_iteration(res, query_res, output, query_output,
                                                                       queries_not_executed, query_not_executed)

        return self._return_final_query_results(res, output, queries_not_executed)

    # following 3 def-s are for avoiding code repetition in previous 4 def-s
    @staticmethod
    def _init_query_results_values():
        """
        initializes the query variable results as following
        res : 0 (the numerical result)
        output : will be initialized to an empty list to be dumped into str later
        queries not executed : 0 (the number of not executed queries)
        rtype: int , list, int
        """
        return 0, [], 0

    @staticmethod
    def _update_query_results_after_one_iteration(result, iter_res, output, iter_output, num_not_exec, iter_not_exec):
        """
        gets the query result from one iteration on the configs_array, and updates and returns the general
        results variables as following:
        1- adds the iteration numerical result to the existing numerical result
        2. append the iteration output to the existing one
        3. adds the iter_not_exec to the existing number of not executed queries
        :param int result: the numerical result from running previous iterations
        :param int iter_res: the numerical result from running this iteration
        :param list output: the output from previous iterations
        :param Union[str, dict] iter_output: the query output from last iteration
        a dict in case of yaml, json output format , otherwise str
        :param int num_not_exec: the number of not executed queries from previous iterations
        :param int iter_not_exec: the query_not_executed result from last iteration (0/1)
        rtype: int , list, int
        """
        result += iter_res
        output.append(iter_output)
        num_not_exec += iter_not_exec
        return result, output, num_not_exec

    def _return_final_query_results(self, res, output, queries_not_executed):
        """
        gets the final query results after running it on all iterations of configs_array
        computes the final str output of the query - (other results returned as is)
        if output format is json, dumps the output list into one-top-leveled string
        if output format is yaml, dumps the output list into str of list of yaml objects
        otherwise, writes the output list items split by \n
        :param int res: the numerical result sum of running the query
        :param list output: the output of running all query iterations
        :param int queries_not_executed: number of times query was not executed
        :return the results: numerical result, output - str , num of not executed
        :rtype: int, str, int
        """
        if self.output_configuration.outputFormat == 'json':
            output = json.dumps(output, sort_keys=False, indent=2)
        elif self.output_configuration.outputFormat == 'yaml':
            output = yaml.dump(output, None, default_flow_style=False, sort_keys=False)
        else:
            output = '\n'.join(output)
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
