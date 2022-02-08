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
from NetworkConfigQueryRunner import NetworkConfigQueryRunner


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

    def _get_input_file(self, given_path, out_flag=False):
        """
        Attempts to locate a file specified in the scheme file (possibly relatively to the scheme file)
        :param str given_path: A relative/absolute path to the file
        :param bool out_flag: Indicates if the function is called with expected_output file,
        its absolute path needed even if it doesn't exist
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
        if path.exists(input_file) or out_flag:
            return input_file
        return given_path

    def _handle_resources_list(self, resources_list):
        if not resources_list:  # shouldn't get here
            return None
        if isinstance(resources_list, str):
            resources_list = [resources_list]
        input_file_list = []
        for resource in resources_list:
            input_file_list.append(self._get_input_file(resource))
        return input_file_list

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

        ns_list = config_entry.get('namespaceList')
        pod_list = config_entry.get('podList')
        if ns_list or pod_list:  # a local resource file exist
            if not ns_list:  # use global resource file
                ns_list = self.scheme.get('namespaceList', 'k8s')
            if not pod_list:  # use global resource file
                pod_list = self.scheme.get('podList', 'k8s')
            pod_list = self._handle_resources_list(pod_list)
            ns_list = self._handle_resources_list(ns_list)
            peer_container = PeerContainer(ns_list, pod_list, config_name)
        else:
            # deepcopy is required since NetworkConfig's constructor may change peer_container
            peer_container = copy.deepcopy(peer_container_global)

        entry_list = config_entry['networkPolicyList']
        for idx, entry in enumerate(entry_list):
            if entry.endswith('**'):
                # ignoring the ** in order to get abspath, then re-adding them to the full path be used later
                entry_list[idx] = self._get_input_file(entry[:-2])
                entry_list[idx] += '/**'
            else:
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

    def run_scheme(self):
        """
        This is the main method to run a scheme file. Builds all network configs and runs all queries
        :return: The number of queries with unexpected result + number of configs with unexpected number of warnings
        :rtype: int
        """
        allowed_keys = {'networkConfigList': 1, 'namespaceList': 0, 'podList': 0, 'queries': 0}
        self.check_fields_validity(self.scheme, 'scheme', allowed_keys)

        # global resource files
        pod_list = self._handle_resources_list(self.scheme.get('podList', 'k8s'))
        ns_list = self._handle_resources_list(self.scheme.get('namespaceList', 'k8s'))
        peer_container = PeerContainer(ns_list, pod_list)

        for config_entry in self.scheme.get('networkConfigList', []):
            self._add_config(config_entry, peer_container)

        self.run_queries(self.scheme.get('queries', []))
        return self.global_res

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
                            'expected': 0, 'expectedOutput': 0, 'allCaptured': 0, 'connectivityMap': 0,
                            'outputConfiguration': 0}

        for query in query_array:
            res = 0
            comparing_err = 0
            self.check_fields_validity(query, 'query', allowed_elements)
            query_name = query['name']
            print('Running query', query_name)
            output_config_obj = self.get_query_output_config_obj(query)
            expected_output = self._get_input_file(query.get('expectedOutput', None), True)
            for query_key in query.keys():
                if query_key not in ['name', 'expected', 'outputConfiguration', 'expectedOutput']:
                    res, comparing_err = NetworkConfigQueryRunner(query_key, query[query_key], expected_output,
                                                                  output_config_obj, self.network_configs).run_query()

            if 'expected' in query:
                expected = query['expected']
                if res != expected:
                    self.warning(f'Unexpected result for query {query_name}: Expected {expected}, got {res}\n', query)
                    self.global_res += 1
            if comparing_err != 0:
                self.warning(f'Unexpected output comparing result for query {query_name} ')
                self.global_res += 1
