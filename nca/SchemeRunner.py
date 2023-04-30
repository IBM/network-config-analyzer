#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import time
from os import path
from nca.FileScanners.GenericTreeScanner import TreeScannerFactory
from nca.Utils.OutputConfiguration import OutputConfiguration
from nca.Parsers.GenericYamlParser import GenericYamlParser
from nca.NetworkConfig.NetworkConfigQueryRunner import NetworkConfigQueryRunner
from nca.NetworkConfig.ResourcesHandler import ResourcesHandler


class SchemeRunner(GenericYamlParser):
    """
    This class takes a scheme file, build all its network configurations and runs all its queries
    """

    def __init__(self, scheme_file_name, output_format=None, output_path=None, optimized_run='false'):
        GenericYamlParser.__init__(self, scheme_file_name)
        self.network_configs = {}
        self.global_res = 0
        self.output_config_from_cli_args = dict()
        if output_format is not None:
            self.output_config_from_cli_args['outputFormat'] = output_format
        if output_path is not None:
            self.output_config_from_cli_args['outputPath'] = output_path
        self.optimized_run = optimized_run

        scanner = TreeScannerFactory.get_scanner(scheme_file_name)
        for yaml_file in scanner.get_yamls():
            for yaml_doc in yaml_file.data:
                self.scheme = yaml_doc
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
        if given_path.startswith(('https://github', 'https://raw.githubusercontent')):
            return given_path
        base_dir = path.dirname(path.realpath(self.yaml_file_name))
        input_file = base_dir + path.sep + given_path
        if path.exists(input_file) or out_flag:
            return input_file
        if not path.exists(input_file):
            raise Exception(f'{given_path} entry is not a valid path')
        return given_path

    def _handle_resources_list(self, resources_list):
        if resources_list is None:
            return None
        if isinstance(resources_list, str):
            resources_list = [resources_list]
        input_file_list = []
        for resource in resources_list:
            if resource.endswith('**'):
                # ignoring the ** in order to get abspath, then re-adding them to the full path be used later
                resource_path = self._get_input_file(resource[:-2])
                resource_path += '/**'
            else:
                resource_path = self._get_input_file(resource)
            input_file_list.append(resource_path)
        return input_file_list

    def _add_config(self, config_entry, resources_handler, optimized_run):
        """
        Produces a NetworkConfig object for a given entry in the scheme file.
        Increases self.global_res if the number of warnings/error in the config does not match the expected number.
        :param dict config_entry: The scheme file entry
        :param ResourcesHandler resources_handler: the resources handler which already include the global peer container
        :return: A matching NetworkConfig object
        :rtype: NetworkConfig
        """
        self.check_fields_validity(config_entry, 'networkConfig', {'name': 1, 'namespaceList': 0, 'podList': 0,
                                                                   'networkPolicyList': 0, 'resourceList': 0,
                                                                   'expectedWarnings': 0,
                                                                   'expectedError': 0}, {'expectedError': [0, 1]})
        config_name = config_entry['name']
        if config_name in self.network_configs:
            self.syntax_error(f'networkPolicyList {config_name} already exists', config_entry)

        ns_list = self._handle_resources_list(config_entry.get('namespaceList'))
        pod_list = self._handle_resources_list(config_entry.get('podList'))
        resource_list = self._handle_resources_list(config_entry.get('resourceList'))
        np_list = self._handle_resources_list(config_entry.get('networkPolicyList'))
        if np_list is None and resource_list is None:
            self.syntax_error(f'{config_name} must have an entry for network policies, '
                              f'either with networkPolicyList or resourceList key', config_entry)
        found_error = 0
        expected_error = config_entry.get('expectedError')
        try:
            network_config = resources_handler.get_network_config(np_list, ns_list, pod_list, resource_list,
                                                                  config_name, optimized_run=optimized_run)
            if not network_config:
                self.warning(f'networkPolicyList {network_config.name} contains no networkPolicies',
                             np_list)

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
        allowed_keys = {'networkConfigList': 1, 'namespaceList': 0, 'podList': 0, 'queries': 0, 'resourceList': 0}
        self.check_fields_validity(self.scheme, 'scheme', allowed_keys)

        # global resource files
        global_pod_list = self._handle_resources_list(self.scheme.get('podList', None))
        global_ns_list = self._handle_resources_list(self.scheme.get('namespaceList', None))
        global_resource_list = self._handle_resources_list(self.scheme.get('resourceList', None))
        resources_handler = ResourcesHandler()
        resources_handler.set_global_peer_container(global_ns_list, global_pod_list, global_resource_list,
                                                    self.optimized_run)

        # specified configs (non-global)
        start = time.time()
        for config_entry in self.scheme.get('networkConfigList', []):
            self._add_config(config_entry, resources_handler, self.optimized_run)
        end_parse = time.time()
        print(f'Finished parsing in {(end_parse - start):6.2f} seconds')
        self.run_queries(self.scheme.get('queries', []))
        end_queries = time.time()
        print(f'Parsing time: {(end_parse - start):6.2f} seconds')
        print(f'Queries time: {(end_queries - end_parse):6.2f} seconds')
        print(f'Total time: {(end_queries - start):6.2f} seconds')
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
                            'outputConfiguration': 0, 'expectedNotExecuted': 0}

        for query in query_array:
            res = 0
            comparing_err = 0
            not_executed = 0
            self.check_fields_validity(query, 'query', allowed_elements)
            query_name = query['name']
            if self.optimized_run == 'debug':
                # optimization - currently only connectivityMap query has optimized implementation and can be compared
                if not query.get('connectivityMap'):
                    print(f'Skipping query {query_name} since it does not have optimized implementation yet')
                    continue
            print('Running query', query_name)
            output_config_obj = self.get_query_output_config_obj(query)
            expected_output = self._get_input_file(query.get('expectedOutput', None), True)
            start = time.time()
            for query_key in query.keys():
                if query_key not in ['name', 'expected', 'outputConfiguration', 'expectedOutput', 'expectedNotExecuted']:
                    res, comparing_err, not_executed =\
                        NetworkConfigQueryRunner(query_key, query[query_key], expected_output, output_config_obj,
                                                 self.network_configs).run_query()

            end = time.time()
            print(f'Query {query_name} finished in {(end-start):6.2f} seconds')
            if 'expected' in query:
                expected = query['expected']
                if res != expected:
                    self.warning(f'Unexpected result for query {query_name}: Expected {expected}, got {res}\n', query)
                    self.global_res += 1
            expected_not_executed = query.get('expectedNotExecuted', 0)
            if not_executed != expected_not_executed:
                msg = f'{query_name} was not executed {not_executed} times.'
                if 'expectedNotExecuted' in query:
                    msg = msg + f' Although, expected to not be executed {expected_not_executed} times'
                self.warning(msg)
                self.global_res += 1
            if comparing_err != 0:
                self.warning(f'Unexpected output comparing result for query {query_name} ')
                self.global_res += 1
