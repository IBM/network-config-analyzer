#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import sys
from os import path
from PeerContainer import PeerContainer
from NetworkConfig import NetworkConfig
from NetworkConfigQuery import SanityQuery, ContainmentQuery, InterferesQuery, IntersectsQuery, TwoWayContainmentQuery, \
    ConnectivityMapQuery


class BaseExecuter:
    """
    Base class for query executers
    """

    def __init__(self, ns_list='', pod_list=''):
        self.peer_container = PeerContainer(ns_list, pod_list)


class SanityExecute(BaseExecuter):
    """
    Class for executing sanity check
    """

    def __init__(self, np_list_location, ns_list='', pod_list=''):
        super().__init__(ns_list, pod_list)
        self.network_config = NetworkConfig(np_list_location, self.peer_container, [np_list_location])

    def execute(self):
        print()
        sanity_res = SanityQuery(self.network_config).exec()
        print(sanity_res.output_result)
        if not sanity_res.bool_result:
            print(sanity_res.output_explanation)
        print()
        return not sanity_res.bool_result


class EquivalenceExecute(BaseExecuter):
    """
    Class for executing equivalence check
    """

    def __init__(self, np1_list_location, np2_list_location, ns_list='', pod_list=''):
        super().__init__(ns_list, pod_list)
        self.network_config1 = NetworkConfig(np1_list_location, self.peer_container, [np1_list_location])
        self.network_config2 = NetworkConfig(np2_list_location, self.peer_container, [np2_list_location])

    def execute(self):
        print()
        full_result = TwoWayContainmentQuery(self.network_config1, self.network_config2).exec()
        print(full_result.output_result)
        if full_result.numerical_result != 3:
            print(full_result.output_explanation, '\n')
        return full_result.numerical_result


class ConnectivityMapExecute(BaseExecuter):
    def __init__(self, np_list_location, ns_list='', pod_list=''):
        super().__init__(ns_list, pod_list)
        self.network_config = NetworkConfig(np_list_location, self.peer_container, [np_list_location])

    def execute(self):
        print()
        sanity_res = ConnectivityMapQuery(self.network_config).exec(None)
        print(sanity_res.output_result)
        if not sanity_res.bool_result:
            print(sanity_res.output_explanation)
        print()
        return not sanity_res.bool_result


class InterferesExecute(BaseExecuter):
    """
    Class for executing interference check
    """

    def __init__(self, exclusive_network_policy_location_or_name, base_np_location, ns_list='', pod_list=''):
        super().__init__(ns_list, pod_list)
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
        print()
        print(full_result.output_result)
        if full_result.bool_result:
            print(full_result.output_explanation)
        print()
        return int(full_result.bool_result)


class ForbidsExecuter(BaseExecuter):
    """
    Class for executing Forbids query
    """

    def __init__(self, policies_to_forbid, base_np_location, ns_list='', pod_list=''):
        super().__init__(ns_list, pod_list)
        self.base_config = NetworkConfig(base_np_location, self.peer_container, [base_np_location])
        self.forbid_config = NetworkConfig(policies_to_forbid, self.peer_container, [policies_to_forbid])
        if not self.forbid_config:
            print(f'\nThere are no NetworkPolicies in {policies_to_forbid}. No traffic is specified as forbidden.\n')
            sys.exit(1)

    def execute(self):
        print()
        full_result = IntersectsQuery(self.forbid_config, self.base_config).exec(True)
        if full_result.bool_result:
            print(f'{self.base_config.name} does not forbid connections specified in {self.forbid_config.name}:')
            print(full_result.output_explanation)
        else:
            print(f'{self.base_config.name} forbids connections specified in {self.forbid_config.name}')
        print()
        return int(full_result.bool_result)


class PermitsExecuter(BaseExecuter):
    """
    Class for executing Permits query
    """

    def __init__(self, policies_to_permit, base_np_location, ns_list='', pod_list=''):
        super().__init__(ns_list, pod_list)
        self.base_config = NetworkConfig(base_np_location, self.peer_container, [base_np_location])
        self.permit_config = NetworkConfig(policies_to_permit, self.peer_container, [policies_to_permit])
        if not self.permit_config:
            print(f'\nNo NetworkPolicies in {policies_to_permit}. No traffic is specified as permitted.\n')
            sys.exit(1)

    def execute(self):
        print()
        full_result = ContainmentQuery(self.permit_config, self.base_config).exec(True)
        if not full_result.bool_result:
            print(f'{self.base_config.name} does not permit connections specified in {self.permit_config.name}:')
            print(full_result.output_explanation)
        else:
            print(f'{self.base_config.name} permits all connections specified in {self.permit_config.name}')
        print()
        return int(not full_result.bool_result)
