#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from os import path
import copy
from ruamel.yaml import YAML

from OutputConfiguration import OutputConfiguration
from PeerContainer import PeerContainer
from GenericYamlParser import GenericYamlParser
from NetworkConfig import NetworkConfig
from NetworkConfigQuery import QueryAnswer, SemanticEquivalenceQuery, StrongEquivalenceQuery, SemanticDiffQuery, \
    SanityQuery, ContainmentQuery, RedundancyQuery, InterferesQuery, EmptinessQuery, VacuityQuery, DisjointnessQuery, \
    IntersectsQuery, TwoWayContainmentQuery, PermitsQuery, AllCapturedQuery, ConnectivityMapQuery


class SchemeRunner(GenericYamlParser):
    """
    This class takes a scheme file, build all its network configurations and runs all its queries
    """

    def __init__(self, scheme_file_name, output_format=None, output_path=None):
        GenericYamlParser.__init__(self, scheme_file_name)
        self.network_configs = {}
        self.global_res = 0
        self.output_config_from_cli_args = dict()
        if output_format is not None:
            self.output_config_from_cli_args['outputFormat'] = output_format
        if output_path is not None:
            self.output_config_from_cli_args['outputPath'] = output_path

        with open(scheme_file_name) as scheme_file:
            yaml = YAML()
            self.scheme = yaml.load(scheme_file)
            if not isinstance(self.scheme, dict):
                self.syntax_error("The scheme's top-level object must be a map")

    def _get_input_file(self, given_path):
        """
        Attempts to locate a file specified in the scheme file (possibly relatively to the scheme file)
        :param str given_path: A relative/absolute path to the file
        :return: A path where the file can be located
        :rtype: str
        """
        if not given_path:
            return given_path
        if path.isabs(given_path):
            return given_path
        if path.exists(given_path):
            return given_path
        base_dir = path.dirname(path.realpath(self.yaml_file_name))
        input_file = base_dir + path.sep + given_path
        if path.exists(input_file):
            return input_file
        return given_path

    def _add_config(self, config_entry, peer_container_global):
        """
        Produces a NetworkConfig object for a given entry in the scheme file.
        Increases self.global_res if the number of warnings/error in the config does not match the expected number.
        :param dict config_entry: The scheme file entry
        :param PeerContainer peer_container_global: The global network topology
        :return: A matching NetworkConfig object
        :rtype: NetworkConfig
        """
        self.check_fields_validity(config_entry, 'networkConfig', {'name': 1, 'namespaceList': 0, 'podList': 0,
                                                                   'networkPolicyList': 1, 'expectedWarnings': 0,
                                                                   'expectedError': 0}, {'expectedError': [0, 1]})
        config_name = config_entry['name']
        if config_name in self.network_configs:
            self.syntax_error(f'networkPolicyList {config_name} already exists', config_entry)

        ns_list = self._get_input_file(config_entry.get('namespaceList'))
        pod_list = self._get_input_file(config_entry.get('podList'))
        if ns_list or pod_list:  # a local resource file exist
            if not ns_list:  # use global resource file
                ns_list = self._get_input_file(self.scheme.get('namespaceList', 'k8s'))
            if not pod_list:  # use global resource file
                pod_list = self._get_input_file(self.scheme.get('podList', 'k8s'))
            peer_container = PeerContainer(ns_list, pod_list, config_name)
        else:
            # deepcopy is required since NetworkConfig's constructor may change peer_container
            peer_container = copy.deepcopy(peer_container_global)

        entry_list = config_entry['networkPolicyList']
        for idx, entry in enumerate(entry_list):
            entry_list[idx] = self._get_input_file(entry)

        found_error = 0
        expected_error = config_entry.get('expectedError')
        try:
            network_config = NetworkConfig(config_name, peer_container, entry_list)
            if not network_config.policies:
                self.warning(f'networkPolicyList {network_config.name} contains no networkPolicies',
                             config_entry['networkPolicyList'])

            expected_warnings = config_entry.get('expectedWarnings')
            if expected_warnings is not None:
                warnings_found = network_config.get_num_findings()
                if warnings_found != expected_warnings:
                    self.warning(f'Unexpected number of warnings for NetworkConfig {network_config.name}: '
                                 f'Expected {expected_warnings}, got {warnings_found}\n', config_entry)
                    self.global_res += 1
            self.network_configs[network_config.name] = network_config

        except SyntaxError as err:
            if expected_error is None:
                raise err
            found_error = 1

        if expected_error is not None:
            if found_error != expected_error:
                self.warning(f'error mismatch for NetworkConfig {config_name}: '
                             f'Expected {expected_error} error, got {found_error}\n', config_entry)
                self.global_res += 1

    def _get_config(self, config_name):
        """
        :param str config_name: The name of a previously defined config or a policy within a previously defined config
        :return: A NetworkConfig object for the requested config
        :rtype: NetworkConfig
        """
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

    def run_scheme(self):
        """
        This is the main method to run a scheme file. Builds all network configs and runs all queries
        :return: The number of queries with unexpected result + number of configs with unexpected number of warnings
        :rtype: int
        """
        allowed_keys = {'networkConfigList': 1, 'namespaceList': 0, 'podList': 0, 'queries': 0}
        self.check_fields_validity(self.scheme, 'scheme', allowed_keys)

        # global resource files
        pod_list = self._get_input_file(self.scheme.get('podList', 'k8s'))
        ns_list = self._get_input_file(self.scheme.get('namespaceList', 'k8s'))
        peer_container = PeerContainer(ns_list, pod_list)

        for config_entry in self.scheme.get('networkConfigList', []):
            self._add_config(config_entry, peer_container)

        self.run_queries(self.scheme.get('queries', []))
        return self.global_res

    @staticmethod
    def _lower_camel_to_snake_case(keyword):
        """
        Converts a lowerCamelCase keyword (from json file) to a snake_case (to be used as a python var)
        :param str keyword: the keyword to convert
        :return: The keyword in snake_case
        :rtype: str
        """
        ret = ''
        for letter in keyword:
            if letter.isupper():
                ret += '_' + letter.lower()
            else:
                ret += letter
        return ret

    def get_query_output_config_obj(self, query):
        """
        return an output config object based on scheme query and cli arguments
        :param query: a query dict object from scheme file
        :return: an OutputConfiguration object
        """
        output_configuration_dict = dict(query.get('outputConfiguration', {}))
        # output config from cli args overrides config from scheme file (if both exist)
        output_configuration_dict.update(self.output_config_from_cli_args)
        output_config_obj = OutputConfiguration(output_configuration_dict, query['name'])
        return output_config_obj

    def run_queries(self, query_array):
        """
        Run all queries specified in the scheme file.
        Adds to self.global_res the number of queries with unexpected results
        :param list[dict] query_array: A list of query objects to run
        :return: None
        """
        if not query_array:
            self.warning('No queries to run\n')
        allowed_elements = {'name': 1, 'equivalence': 0, 'strongEquivalence': 0, 'semanticDiff': 0, 'containment': 0,
                            'redundancy': 0, 'interferes': 0, 'pairwiseInterferes': 0, 'emptiness': 0, 'vacuity': 0,
                            'sanity': 0, 'disjointness': 0, 'twoWayContainment': 0, 'forbids': 0, 'permits': 0,
                            'expected': 0, 'allCaptured': 0, 'connectivityMap': 0, 'outputConfiguration': 0}

        for query in query_array:
            res = 0
            self.check_fields_validity(query, 'query', allowed_elements)
            query_name = query['name']
            print('Running query', query_name)
            output_config_obj = self.get_query_output_config_obj(query)

            for query_key in query.keys():
                if query_key not in ['name', 'expected', 'outputConfiguration']:
                    res += getattr(self, f'_run_{self._lower_camel_to_snake_case(query_key)}')(query[query_key],
                                                                                               output_config_obj)
            if 'expected' in query:
                expected = query['expected']
                if res != expected:
                    self.warning(f'Unexpected result for query {query_name}: Expected {expected}, got {res}\n', query)
                    self.global_res += 1

    def _run_equivalence(self, configs_array, output_configuration):
        total_res = 0
        query_output = ''
        full_result = QueryAnswer()
        for ind1 in range(len(configs_array) - 1):
            config1 = configs_array[ind1]
            for ind2 in range(ind1 + 1, len(configs_array)):
                config2 = configs_array[ind2]
                full_result = SemanticEquivalenceQuery(self._get_config(config1), self._get_config(config2),
                                                       output_configuration).exec()
                query_output += full_result.output_result
                total_res += not full_result.bool_result
                if not full_result.bool_result:
                    query_output += full_result.output_explanation + '\n'
#                query_output += '\n'
        if full_result.bool_result:
            query_output += '\n'
        output_configuration.print_query_output(query_output)
        return total_res

    def _run_strong_equivalence(self, configs_array, output_configuration):
        total_res = 0
        query_output = ''
        full_result = QueryAnswer()
        for ind1 in range(len(configs_array) - 1):
            config1 = configs_array[ind1]
            for ind2 in range(ind1 + 1, len(configs_array)):
                config2 = configs_array[ind2]
                full_result = StrongEquivalenceQuery(self._get_config(config1), self._get_config(config2),
                                                     output_configuration).exec()
                total_res += not full_result.bool_result
                query_output += full_result.output_result
                if not full_result.bool_result and full_result.output_explanation:
                    query_output += full_result.output_explanation + '\n'
#                query_output += '\n'
        if full_result.bool_result or not full_result.output_explanation:
            query_output += '\n'
        output_configuration.print_query_output(query_output)
        return total_res

    def _run_semantic_diff(self, configs_array, output_configuration):
        res = 0
        query_output = ''
        for ind1 in range(len(configs_array) - 1):
            config1 = configs_array[ind1]
            for ind2 in range(ind1 + 1, len(configs_array)):
                config2 = configs_array[ind2]
                full_result = SemanticDiffQuery(self._get_config(config1), self._get_config(config2),
                                                output_configuration).exec()
                if output_configuration.outputFormat == 'txt':
                    query_output += full_result.output_result
                res += full_result.numerical_result
                if not full_result.bool_result:
                    query_output += full_result.output_explanation + '\n'
#                query_output += '\n'
        output_configuration.print_query_output(query_output, SemanticDiffQuery.supported_output_formats)
        return res

    def _run_containment(self, configs_array, output_configuration):
        if len(configs_array) <= 1:
            return 0
        res = 0
        query_output = ''
        base_config = self._get_config(configs_array[0])
        for config in configs_array[1:]:
            full_result = ContainmentQuery(self._get_config(config), base_config, output_configuration).exec()
            res += full_result.bool_result
            if full_result.output_result:
                query_output += full_result.output_result
            if full_result.output_explanation:
                query_output += full_result.output_explanation
            query_output += '\n'
        query_output += '\n'
        output_configuration.print_query_output(query_output)
        return res

    def _run_redundancy(self, configs_array, output_configuration):
        res = 0
        query_output = ''
        for config in configs_array:
            full_result = RedundancyQuery(self._get_config(config), output_configuration).exec()
            if not full_result.bool_result:
                query_output += full_result.output_result
            else:
                query_output += full_result.output_explanation
            query_output += '\n'
            res += full_result.numerical_result
        query_output += '\n'
        output_configuration.print_query_output(query_output)
        return res

    def _run_interferes(self, configs_array, output_configuration):
        if len(configs_array) <= 1:
            return 0
        res = 0
        query_output = ''
        full_result = QueryAnswer()
        base_config = self._get_config(configs_array[0])
        for config in configs_array[1:]:
            full_result = InterferesQuery(base_config, self._get_config(config), output_configuration).exec()
            res += full_result.bool_result
            query_output += full_result.output_result
            if full_result.bool_result:
                query_output += full_result.output_explanation
            query_output += '\n'

        if not full_result.bool_result:
            query_output += '\n'
        output_configuration.print_query_output(query_output)
        return res

    def _run_pairwise_interferes(self, configs_array, output_configuration):
        if len(configs_array) <= 1:
            return 0
        total_res = 0
        query_output = ''
        full_result = QueryAnswer()
        for config1 in configs_array:
            for config2 in configs_array:
                if config1 != config2:
                    full_result = InterferesQuery(self._get_config(config1), self._get_config(config2),
                                                  output_configuration).exec()
                    total_res += full_result.bool_result
                    query_output += full_result.output_result
                    if full_result.bool_result:
                        query_output += full_result.output_explanation
                    query_output += '\n'
        if not full_result.bool_result:
            query_output += '\n'
        output_configuration.print_query_output(query_output)
        return total_res

    def _run_emptiness(self, configs_array, output_configuration):
        res = 0
        query_output = ''
        for config in configs_array:
            full_result = EmptinessQuery(self._get_config(config), output_configuration).exec()
            if full_result.bool_result:
                query_output += full_result.output_explanation
            else:
                query_output += full_result.output_result
            query_output += '\n'
            res += full_result.numerical_result
        query_output += '\n'
        output_configuration.print_query_output(query_output)
        return res

    def _run_vacuity(self, configs_array, output_configuration):
        res = 0
        query_output = ''
        for config in configs_array:
            full_result = VacuityQuery(self._get_config(config), output_configuration).exec()
            query_output += full_result.output_result
            query_output += '\n'
            res += full_result.bool_result
        query_output += '\n'
        output_configuration.print_query_output(query_output)
        return res

    def _run_sanity(self, configs_array, output_configuration):
        res = 0
        query_output = ''
        for config in configs_array:
            full_result = SanityQuery(self._get_config(config), output_configuration).exec()
            res += full_result.numerical_result
            query_output += full_result.output_result
            if not full_result.bool_result:
                query_output += full_result.output_explanation
            query_output += '\n'
        query_output += '\n'
        output_configuration.print_query_output(query_output)
        return res

    def _run_disjointness(self, configs_array, output_configuration):
        res = 0
        query_output = ''
        for config in configs_array:
            full_result = DisjointnessQuery(self._get_config(config), output_configuration).exec()
            res += full_result.numerical_result
            query_output += full_result.output_result
            if not full_result.bool_result:
                query_output += full_result.output_explanation
            query_output += '\n'
        query_output += '\n'
        output_configuration.print_query_output(query_output)
        return res

    def _run_two_way_containment(self, configs_array, output_configuration):
        total_res = 0
        query_output = ''
        for ind1 in range(len(configs_array) - 1):
            config1 = configs_array[ind1]
            for ind2 in range(ind1 + 1, len(configs_array)):
                config2 = configs_array[ind2]
                full_result = TwoWayContainmentQuery(self._get_config(config1), self._get_config(config2),
                                                     output_configuration).exec()
                query_output += full_result.output_result
                total_res += full_result.numerical_result
                if full_result.numerical_result != 3:
                    query_output += full_result.output_explanation
                query_output += '\n'
        query_output += '\n'
        output_configuration.print_query_output(query_output)
        return total_res

    def _run_forbids(self, configs_array, output_configuration):
        if len(configs_array) <= 1:
            return 0
        res = 0
        query_output = ''
        full_result = QueryAnswer()
        base_config = self._get_config(configs_array[0])
        for config in configs_array[1:]:
            full_result = IntersectsQuery(self._get_config(config), base_config, output_configuration).exec(True)
            res += full_result.bool_result
            if full_result.bool_result:
                query_output += configs_array[0] + ' does not forbid connections specified in ' + config + ':'
                query_output += full_result.output_explanation
            else:
                query_output += configs_array[0] + ' forbids connections specified in ' + config
            query_output += '\n'

        if not full_result.bool_result:
            query_output += '\n'
        output_configuration.print_query_output(query_output)
        return res

    def _run_permits(self, configs_array, output_configuration):
        if len(configs_array) <= 1:
            return 0
        res = 0
        query_output = ''
        full_result = QueryAnswer()
        base_config = self._get_config(configs_array[0])
        for config in configs_array[1:]:
            full_result = PermitsQuery(self._get_config(config), base_config).exec()
            if not full_result.bool_result:
                if not full_result.output_explanation:
                    query_output += full_result.output_result
                else:
                    res += 1
                    query_output += (configs_array[0] + ' does not permit connections specified in ' + config + ':')
                    query_output += full_result.output_explanation + '\n'
            else:
                query_output += configs_array[0] + ' permits all connections specified in ' + config
            query_output += '\n'

        query_output += '\n'
        output_configuration.print_query_output(query_output)
        return res

    def _run_all_captured(self, configs_array, output_configuration):
        res = 0
        query_output = ''
        for config in configs_array:
            full_result = AllCapturedQuery(self._get_config(config), output_configuration).exec()
            res += full_result.numerical_result
            query_output += full_result.output_result
            if not full_result.bool_result:
                query_output += full_result.output_explanation
        query_output += '\n'
        output_configuration.print_query_output(query_output)
        return res

    def _run_connectivity_map(self, configs_array, output_configuration):
        query_output = ''
        for config in configs_array:
            output_configuration.configName = config
            full_result = ConnectivityMapQuery(self._get_config(config), output_configuration).exec()
            query_output += full_result.output_explanation
            query_output += '\n'
        query_output += '\n'
        output_configuration.print_query_output(query_output, ConnectivityMapQuery.supported_output_formats)
        return 0
