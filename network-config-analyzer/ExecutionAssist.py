#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import sys
from os import path

from OutputConfiguration import OutputConfiguration
from PeerContainer import PeerContainer
from NetworkConfig import NetworkConfig
from NetworkConfigQuery import SanityQuery, ContainmentQuery, InterferesQuery, IntersectsQuery, TwoWayContainmentQuery, \
    ConnectivityMapQuery, SemanticDiffQuery


class BaseExecuter:
    """
    Base class for query executers
    """

    def __init__(self, ns_list='', pod_list='', output_format=None, output_path=None):
        self.peer_container = PeerContainer(ns_list, pod_list)
        output_config_dict = {'outputFormat': output_format if output_format is not None else 'txt',
                              'outputPath': output_path}
        # create output config based on command line arguments
        self.output_config = OutputConfiguration(output_config_dict)


class SanityExecute(BaseExecuter):
    """
    Class for executing sanity check
    """

    def __init__(self, np_list_location, ns_list='', pod_list='', output_format='txt', output_path=''):
        super().__init__(ns_list, pod_list, output_format, output_path)
        self.network_config = NetworkConfig(np_list_location, self.peer_container, [np_list_location])

    def execute(self):
        #print()
        query_output = '\n'
        sanity_res = SanityQuery(self.network_config).exec()
        query_output += sanity_res.output_result
        if not sanity_res.bool_result:
            query_output += sanity_res.output_explanation
        query_output += '\n'
        self.output_config.print_query_output(query_output)
        return not sanity_res.bool_result


class EquivalenceExecute(BaseExecuter):
    """
    Class for executing equivalence check
    """

    def __init__(self, np1_list_location, np2_list_location, ns_list='', pod_list='',  output_format='txt', output_path=''):
        super().__init__(ns_list, pod_list, output_format, output_path)
        self.network_config1 = NetworkConfig(np1_list_location, self.peer_container, [np1_list_location])
        self.network_config2 = NetworkConfig(np2_list_location, self.peer_container, [np2_list_location])

    def execute(self):
        #print()
        query_output = '\n'
        full_result = TwoWayContainmentQuery(self.network_config1, self.network_config2).exec()
        query_output += full_result.output_result
        if full_result.numerical_result != 3:
            query_output += full_result.output_explanation + '\n'
        self.output_config.print_query_output(query_output)
        return full_result.numerical_result


class ConnectivityMapExecute(BaseExecuter):
    def __init__(self, np_list_location, ns_list='', pod_list='', output_format='txt', output_path=''):
        super().__init__(ns_list, pod_list, output_format, output_path)
        self.network_config = NetworkConfig(np_list_location, self.peer_container, [np_list_location])

    def execute(self):
        #print()
        query_output = '\n'
        res = ConnectivityMapQuery(self.network_config, self.output_config).exec()
        #print(res.output_result)
        query_output += res.output_explanation
        query_output += '\n'
        self.output_config.print_query_output(query_output, True)
        #print()
        return not res.bool_result


class SemanticDiffExecute(BaseExecuter):
    """
    Class for executing semantic diff
    """

    def __init__(self, np1_list_location, np2_list_location, ns_list='', pod_list='', output_format='txt',
                 output_path=''):
        super().__init__(ns_list, pod_list, output_format, output_path)
        self.network_config1 = NetworkConfig(np1_list_location, self.peer_container, [np1_list_location])
        self.network_config2 = NetworkConfig(np2_list_location, self.peer_container, [np2_list_location])

    def execute(self):
        #print()
        query_output = '\n'
        full_result = SemanticDiffQuery(self.network_config1, self.network_config2, self.output_config).exec()
        if self.output_config.outputFormat == 'txt':
            query_output += full_result.output_result
        query_output += full_result.output_explanation + '\n'
        self.output_config.print_query_output(query_output, True)
        #print(full_result.output_result)
        #print(full_result.output_explanation, '\n')
        return full_result.numerical_result


class InterferesExecute(BaseExecuter):
    """
    Class for executing interference check
    """

    def __init__(self, exclusive_network_policy_location_or_name, base_np_location, ns_list='', pod_list='', output_format='txt',
                 output_path=''):
        super().__init__(ns_list, pod_list, output_format, output_path)
        self.base_np_config = NetworkConfig(base_np_location, self.peer_container, [base_np_location])
        self.exclusive_network_policy = NetworkConfig(exclusive_network_policy_location_or_name, self.peer_container)
        if path.isfile(exclusive_network_policy_location_or_name):
            self.exclusive_network_policy.add_policies_from_file(exclusive_network_policy_location_or_name)
        else:
            matching_policies = self.base_np_config.find_policy(exclusive_network_policy_location_or_name)
            if len(matching_policies) == 1:
                self.exclusive_network_policy.add_exclusive_policy_given_profiles(matching_policies[0],
                                                                                  self.base_np_config.profiles)
                return
            if len(matching_policies) == 0:
                print('Error: ', exclusive_network_policy_location_or_name,
                      'is neither a NetworkPolicy file nor a name.', file=sys.stderr)
            elif len(matching_policies) > 1:
                print('Error: A policy named', exclusive_network_policy_location_or_name,
                      'exists in more than one namespace. Provide a fully qualified name (<ns>/<policy>)',
                      file=sys.stderr)
            sys.exit(1)

        return

    def execute(self):
        full_result = InterferesQuery(self.exclusive_network_policy, self.base_np_config).exec()
        #print()
        query_output = '\n'
        query_output += full_result.output_result
        if full_result.bool_result:
            query_output += full_result.output_explanation
        #print()
        query_output += '\n'
        self.output_config.print_query_output(query_output)
        return int(full_result.bool_result)


class ForbidsExecuter(BaseExecuter):
    """
    Class for executing Forbids query
    """

    def __init__(self, policies_to_forbid, base_np_location, ns_list='', pod_list='', output_format='txt',
                 output_path=''):
        super().__init__(ns_list, pod_list, output_format, output_path)
        self.base_config = NetworkConfig(base_np_location, self.peer_container, [base_np_location])
        self.forbid_config = NetworkConfig(policies_to_forbid, self.peer_container, [policies_to_forbid])
        if not self.forbid_config:
            print(f'\nThere are no NetworkPolicies in {policies_to_forbid}. No traffic is specified as forbidden.\n')
            sys.exit(1)

    def execute(self):
        #print()
        query_output = '\n'
        full_result = IntersectsQuery(self.forbid_config, self.base_config).exec(True)
        if full_result.bool_result:
            query_output += f'{self.base_config.name} does not forbid connections specified in {self.forbid_config.name}:'
            query_output += full_result.output_explanation
        else:
            query_output += f'{self.base_config.name} forbids connections specified in {self.forbid_config.name}'
        #print()
        query_output += '\n'
        self.output_config.print_query_output(query_output)
        return int(full_result.bool_result)


class PermitsExecuter(BaseExecuter):
    """
    Class for executing Permits query
    """

    def __init__(self, policies_to_permit, base_np_location, ns_list='', pod_list='', output_format='txt',
                 output_path=''):
        super().__init__(ns_list, pod_list, output_format, output_path)
        self.base_config = NetworkConfig(base_np_location, self.peer_container, [base_np_location])
        self.permit_config = NetworkConfig(policies_to_permit, self.peer_container, [policies_to_permit])
        if not self.permit_config:
            print(f'\nNo NetworkPolicies in {policies_to_permit}. No traffic is specified as permitted.\n')
            sys.exit(1)

    def execute(self):
        #print()
        query_output = '\n'
        full_result = ContainmentQuery(self.permit_config, self.base_config).exec(True)
        if not full_result.bool_result:
            query_output += full_result.output_explanation
        else:
            query_output += f'{self.base_config.name} permits all connections specified in {self.permit_config.name}'
        #print()
        query_output += '\n'
        self.output_config.print_query_output(query_output)
        return int(not full_result.bool_result)
