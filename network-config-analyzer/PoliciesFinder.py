#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from ruamel.yaml import YAML
from collections import deque
from bisect import insort
from CmdlineRunner import CmdlineRunner
from NetworkConfig import NetworkConfig, PoliciesContainer
from NetworkPolicy import NetworkPolicy
from IngressPolicy import IngressPolicy
from K8sPolicyYamlParser import K8sPolicyYamlParser
from CalicoPolicyYamlParser import CalicoPolicyYamlParser
from IstioPolicyYamlParser import IstioPolicyYamlParser
from IngressPolicyYamlParser import IngressPolicyYamlParser


class PoliciesFinder:
    """
    This class is responsible for finding the network policies in the relevant input resources
    The class contains several ways to build the set of policies (from cluster, from file-system, from GitHub).
    """
    def __init__(self):
        self.policies_container = PoliciesContainer()
        self._parse_queue = deque()
        self.type = NetworkConfig.ConfigType.Unknown
        self.peer_container = None

    def set_peer_container(self, peer_container):
        """
        Sets the peer_container class member as it is needed when parsing the policies
        :param Peer Container peer_container: a peer container with all topology objects from the input resources
        """
        self.peer_container = peer_container
        self.peer_container.clear_pods_extra_labels()

    def load_policies_from_buffer(self, buffer):
        self._add_policies(buffer, 'buffer')

    def load_policies_from_k8s_cluster(self):
        self._add_policies(CmdlineRunner.get_k8s_resources('networkPolicy'), 'kubectl')
        self._add_policies(CmdlineRunner.get_k8s_resources('ingress'), 'kubectl')

    def load_policies_from_calico_cluster(self):
        self._add_policies(CmdlineRunner.get_calico_resources('profile'), 'calicoctl')
        self._add_policies(CmdlineRunner.get_calico_resources('networkPolicy'), 'calicoctl')
        self._add_policies(CmdlineRunner.get_calico_resources('globalNetworkPolicy'), 'calicoctl')

    def load_istio_policies_from_k8s_cluster(self):
        self._add_policies(CmdlineRunner.get_k8s_resources('authorizationPolicy'), 'kubectl')

    def _add_policy(self, policy):
        """
        This should be the only place where we add policies to the config's set of policies from input resources
        :param policy: The policy to add
        :return: None
        """
        if not policy:
            return
        if policy.full_name() in self.policies_container.policies:
            raise Exception('A policy named ' + policy.full_name() + ' already exists')
        policy_type = NetworkConfig.get_policy_type(policy)
        if policy_type == NetworkConfig.ConfigType.Unknown:
            raise Exception('Unknown policy type')
        if self.type == NetworkConfig.ConfigType.Unknown or not self.policies_container.policies or \
                self.type == NetworkConfig.ConfigType.Ingress:
            self.type = policy_type
        elif self.type != policy_type and policy_type != NetworkConfig.ConfigType.Ingress:
            raise Exception('Cannot mix NetworkPolicies from different platforms')

        self.policies_container.policies[policy.full_name()] = policy
        if policy_type == NetworkConfig.ConfigType.Ingress:
            assert policy.action == IngressPolicy.ActionType.Deny
            insort(self.policies_container.ingress_deny_policies, policy)
        else:
            insort(self.policies_container.sorted_policies, policy)

    def _add_profile(self, profile):
        if not profile:
            return
        if profile.full_name() in self.policies_container.profiles:
            raise Exception('A profile named ' + profile.full_name() + ' already exists')
        if self.type == NetworkConfig.ConfigType.Unknown:
            self.type = NetworkConfig.ConfigType.Calico
        elif self.type != NetworkConfig.ConfigType.Calico:
            raise Exception('Cannot mix NetworkPolicies from different platforms')
        self.policies_container.profiles[profile.full_name()] = profile

    def parse_policies_in_parse_queue(self):
        for policy, file_name, policy_type in self._parse_queue:
            if policy_type == NetworkPolicy.PolicyType.CalicoProfile:
                parsed_element = CalicoPolicyYamlParser(policy, self.peer_container, file_name)
                self._add_profile(parsed_element.parse_policy())
            elif policy_type == NetworkPolicy.PolicyType.K8sNetworkPolicy:
                parsed_element = K8sPolicyYamlParser(policy, self.peer_container, file_name)
                self._add_policy(parsed_element.parse_policy())
            elif policy_type == NetworkPolicy.PolicyType.IstioAuthorizationPolicy:
                parsed_element = IstioPolicyYamlParser(policy, self.peer_container, file_name)
                self._add_policy(parsed_element.parse_policy())
            elif policy_type == NetworkPolicy.PolicyType.Ingress:
                parsed_element = IngressPolicyYamlParser(policy, self.peer_container, file_name)
                self._add_policy(parsed_element.parse_policy())
            else:
                parsed_element = CalicoPolicyYamlParser(policy, self.peer_container, file_name)
                self._add_policy(parsed_element.parse_policy())

    def parse_yaml_code_for_policy(self, policy_object, file_name):
        policy_type = NetworkPolicy.get_policy_type(policy_object)
        if policy_type == NetworkPolicy.PolicyType.Unknown:
            return
        if policy_type == NetworkPolicy.PolicyType.List:
            self._add_policies_to_parse_queue(policy_object.get('items', []), file_name)
        elif policy_type == NetworkPolicy.PolicyType.CalicoProfile:
            self._parse_queue.appendleft((policy_object, file_name, policy_type))  # profiles must be parsed first
        else:
            self._parse_queue.append((policy_object, file_name, policy_type))

    def _add_policies_to_parse_queue(self, policy_list, file_name):
        for policy in policy_list:
            self.parse_yaml_code_for_policy(policy, file_name)

    def _add_policies(self, doc, file_name):
        yaml1 = YAML()
        code = yaml1.load_all(doc)
        for policy_list in code:
            if isinstance(policy_list, dict):
                self._add_policies_to_parse_queue(policy_list.get('items', []), file_name)
            else:  # we got a list of lists, e.g., when combining calico np, gnp and profiles
                for policy_list_list in policy_list:
                    if isinstance(policy_list_list, dict):
                        self._add_policies_to_parse_queue(policy_list_list.get('items', []), file_name)

    def has_empty_containers(self):
        return not self.policies_container.policies and not self.policies_container.profiles
