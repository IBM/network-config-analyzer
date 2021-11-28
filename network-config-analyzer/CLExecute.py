#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import sys
from os import path

from OutputConfiguration import OutputConfiguration
from PeerContainer import PeerContainer
from NetworkConfig import NetworkConfig
from NetworkConfigQueryRunner import NetworkConfigQueryRunner


class CLExecute:
    """
    A class for running queries from commandline
    """
    def __init__(self, base_ns_list=None, base_pod_list=None, ns_list=None, pod_list=None, output_format='txt', output_path=None, pr_url=None):
        self.base_peer_container = PeerContainer(base_ns_list, base_pod_list)
        self.peer_container = PeerContainer(ns_list, pod_list)
        self.output_config = OutputConfiguration({'outputFormat': output_format, 'outputPath': output_path,
                                                  'prURL': pr_url})

    def execute_single_config_query(self, query_name, np1_list):
        network_config1 = NetworkConfig(np1_list, self.peer_container, [np1_list])
        return NetworkConfigQueryRunner(query_name, [network_config1], self.output_config).run_query()

    def execute_pair_configs_query(self, query_name, np1_list_location, np2_list_location):
        """
        Runs an equivalence-checking query between two sets of policies
        :param str query_name: the name of the arg.query
        :param str np1_list_location: First set of policies
        :param str np2_list_location: Second set of policies (or the base_policies_list)
        :return: result of executing the query
        :rtype: int
        """
        network_config1 = NetworkConfig(np1_list_location, self.peer_container, [np1_list_location])
        network_config2 = NetworkConfig(np2_list_location, self.peer_container, [np2_list_location])
        if query_name in {'permits', 'forbids'} and not network_config2:
            print(f'\nThere are no NetworkPolicies in {np1_list_location}. No traffic is specified for {query_name}.\n')
            sys.exit(1)
        res = NetworkConfigQueryRunner(query_name, [network_config1, network_config2], self.output_config).run_query()
        if query_name == 'forbids':
            return res
        if query_name == 'semanticDiff':
            return res > 0
        return not res

    def interferes(self, exclusive_network_policy_location_or_name, base_np_location):
        """
        Runs an "interferes" query
        :param str exclusive_network_policy_location_or_name: A set of policies to check if they interfere with base
        :param str base_np_location: The base set of policies
        :return: 0 if no policy interferes with base. 1 otherwise
        :rtype: int
        """
        base_np_config = NetworkConfig(base_np_location, self.peer_container, [base_np_location])
        exclusive_network_policy = NetworkConfig(exclusive_network_policy_location_or_name, self.peer_container)
        if path.isfile(exclusive_network_policy_location_or_name):
            exclusive_network_policy.scan_entry_for_policies(exclusive_network_policy_location_or_name)
        else:
            matching_policies = base_np_config.find_policy(exclusive_network_policy_location_or_name)
            if len(matching_policies) == 1:
                exclusive_network_policy.add_exclusive_policy_given_profiles(matching_policies[0],
                                                                             base_np_config.profiles)
            elif len(matching_policies) == 0:
                print('Error: ', exclusive_network_policy_location_or_name,
                      'is neither a NetworkPolicy file nor a name.', file=sys.stderr)
            elif len(matching_policies) > 1:
                print('Error: A policy named', exclusive_network_policy_location_or_name,
                      'exists in more than one namespace. Provide a fully qualified name (<ns>/<policy>)',
                      file=sys.stderr)
                sys.exit(1)

        return NetworkConfigQueryRunner('interferes', [exclusive_network_policy, base_np_config],
                                        self.output_config).run_query()
