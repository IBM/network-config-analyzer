#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import sys
from os import path

from OutputConfiguration import OutputConfiguration
from PeerContainer import PeerContainer
from NetworkConfig import NetworkConfig
import NetworkConfigQuery


class CLExecute:
    """
    A class for running queries from commandline
    """
    def __init__(self, base_ns_list=None, base_pod_list=None, ns_list=None, pod_list=None, output_format='txt', output_path=None, pr_url=None):
        self.base_peer_container = PeerContainer(base_ns_list, base_pod_list)
        self.peer_container = PeerContainer(ns_list, pod_list)
        self.output_config = OutputConfiguration({'outputFormat': output_format, 'outputPath': output_path,
                                                  'prURL': pr_url})

    def sanity(self, np_list):
        """
        Runs a set of sanity check on a given list of network policies
        :param str np_list: A set of policies
        :return: 0 if all sanity checks passed. 1 otherwise
        :rtype: int
        """
        network_config = NetworkConfig(np_list, self.peer_container, [np_list])
        query_output = '\n'
        sanity_res = NetworkConfigQuery.SanityQuery(network_config).exec()
        query_output += sanity_res.output_result
        if not sanity_res.bool_result:
            query_output += sanity_res.output_explanation
        query_output += '\n'
        self.output_config.print_query_output(query_output)
        return int(not sanity_res.bool_result)

    def equivalence(self, np1_list_location, np2_list_location):
        """
        Runs an equivalence-checking query between two sets of policies
        :param str np1_list_location: First set of policies
        :param str np2_list_location: Second set of policies
        :return: 0 if the sets of policies are semantically equivalent. 1 otherwise
        :rtype: int
        """
        network_config1 = NetworkConfig(np1_list_location, self.peer_container, [np1_list_location])
        network_config2 = NetworkConfig(np2_list_location, self.peer_container, [np2_list_location])
        query_output = '\n'
        full_result = NetworkConfigQuery.TwoWayContainmentQuery(network_config1, network_config2).exec()
        query_output += full_result.output_result
        if full_result.numerical_result != 3:
            query_output += full_result.output_explanation + '\n'
        self.output_config.print_query_output(query_output)
        return int(not full_result.bool_result)

    def connectivity_map(self, np_list_location):
        """
        Prints the list of allowed connections (as firewall rules)
        :param str np_list_location: First set of policies
        :return: 0
        :rtype: int
        """
        network_config = NetworkConfig(np_list_location, self.peer_container, [np_list_location])
        query_output = '\n'
        res = NetworkConfigQuery.ConnectivityMapQuery(network_config, self.output_config).exec()
        query_output += res.output_explanation
        query_output += '\n'
        self.output_config.print_query_output(query_output, NetworkConfigQuery.ConnectivityMapQuery.supported_output_formats)
        return 0

    def semantic_diff(self, np2_list_location, np1_list_location):
        """
        Runs a semantic-diff query between two sets of policies
        :param str np1_list_location: First set of policies
        :param str np2_list_location: Second set of policies
        :return: 0 if the sets of policies are semantically equivalent. 1 otherwise
        :rtype: int
        """
        network_config1 = NetworkConfig(np1_list_location, self.base_peer_container, [np1_list_location])
        network_config2 = NetworkConfig(np2_list_location, self.peer_container, [np2_list_location])
        query_output = '\n'
        full_result = NetworkConfigQuery.SemanticDiffQuery(network_config1, network_config2, self.output_config).exec()
        if self.output_config.outputFormat == 'txt':
            query_output += full_result.output_result
        query_output += full_result.output_explanation + '\n'
        self.output_config.print_query_output(query_output, NetworkConfigQuery.SemanticDiffQuery.supported_output_formats)
        return int(not full_result.bool_result)

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

        full_result = NetworkConfigQuery.InterferesQuery(exclusive_network_policy, base_np_config).exec()
        query_output = '\n'
        query_output += full_result.output_result
        if full_result.bool_result:
            query_output += full_result.output_explanation
        query_output += '\n'
        self.output_config.print_query_output(query_output)
        return int(full_result.bool_result)

    def forbids(self, policies_to_forbid, base_np_location):
        """
        Runs a "forbids" query
        :param str policies_to_forbid: A set of policies explicitly defining connections that should be denied in base
        :param str base_np_location: The set of policies to check
        :return: 0 if all connections are denied in base. 1 otherwise
        :rtype: int
        """
        base_config = NetworkConfig(base_np_location, self.peer_container, [base_np_location])
        forbid_config = NetworkConfig(policies_to_forbid, self.peer_container, [policies_to_forbid])
        if not forbid_config:
            print(f'\nThere are no NetworkPolicies in {policies_to_forbid}. No traffic is specified as forbidden.\n')
            sys.exit(1)

        query_output = '\n'
        full_result = NetworkConfigQuery.IntersectsQuery(forbid_config, base_config).exec(True)
        if full_result.bool_result:
            query_output += f'{base_config.name} does not forbid connections specified in {forbid_config.name}:'
            query_output += full_result.output_explanation
        else:
            query_output += f'{base_config.name} forbids connections specified in {forbid_config.name}'
        query_output += '\n'
        self.output_config.print_query_output(query_output)
        return int(full_result.bool_result)

    def permits(self, policies_to_permit, base_np_location):
        """
        Runs a "permits" query
        :param str policies_to_permit: A set of policies explicitly defining connections that should be allowed in base
        :param str base_np_location: The set of policies to check
        :return: 0 if all connections are permitted in base. 1 otherwise
        :rtype: int
        """
        base_config = NetworkConfig(base_np_location, self.peer_container, [base_np_location])
        permit_config = NetworkConfig(policies_to_permit, self.peer_container, [policies_to_permit])
        if not permit_config:
            print(f'\nNo NetworkPolicies in {policies_to_permit}. No traffic is specified as permitted.\n')
            sys.exit(1)

        query_output = '\n'
        full_result = NetworkConfigQuery.PermitsQuery(permit_config, base_config).exec()
        if not full_result.bool_result:
            query_output += full_result.output_explanation
        else:
            query_output += f'{base_config.name} permits all connections specified in {permit_config.name}'
        query_output += '\n'
        self.output_config.print_query_output(query_output)
        return int(not full_result.bool_result)
