#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from bisect import insort
from sys import stderr
from enum import Enum
from collections import deque
import os
from ruamel.yaml import YAML, error
import Peer
from PeerContainer import PeerContainer
from NetworkPolicy import PolicyConnections, NetworkPolicy
from K8sPolicyYamlParser import K8sPolicyYamlParser
from CalicoPolicyYamlParser import CalicoPolicyYamlParser
from K8sNetworkPolicy import K8sNetworkPolicy
from CalicoNetworkPolicy import CalicoNetworkPolicy
from ConnectionSet import ConnectionSet
from CmdlineRunner import CmdlineRunner
from GitScanner import GitScanner


class NetworkConfig:
    """
    Represents a network configuration - the set of endpoints, their partitioning to namespaces and a set of policies
    that limit the allowed connectivity.
    The class contains several ways to build the set of policies (from cluster, from file-system, from GitHub).
    The class also contains the core algorithm of computing allowed connections between two endpoints.
    """
    class ConfigType(Enum):
        Unknown = 0
        K8s = 1
        Calico = 2
        Istio = 3

    def __init__(self, name, peer_container, entry_list=None, config_type=None):
        """
        :param str name: A name for this config
        :param PeerContainer peer_container: The set of endpoints and their namespaces
        :param list entry_list: A list of entries to generate the policies from
        :param ConfigType config_type: The type of configuration
        """
        self.name = name
        self.peer_container = peer_container
        self._parse_queue = deque()  # This deque makes sure Profiles get parsed first (because of 'labelToApply')
        self.policies = {}
        self.sorted_policies = []
        self.profiles = {}
        self.referenced_ip_blocks = None
        self.type = config_type or NetworkConfig.ConfigType.Unknown
        peer_container.clear_pods_extra_labels()
        for entry in entry_list or []:
            self.add_policies_from_entry(entry)
        self._parse_policies_in_parse_queue()

    def __eq__(self, other):
        if not isinstance(other, NetworkConfig):
            return NotImplemented
        return self.name == other.name and self.peer_container == other.peer_container and \
            self.policies == other.policies

    def __str__(self):
        return self.name

    def __bool__(self):
        return len(self.policies) > 0

    def get_num_findings(self):
        """
        :return: The number of findings stored in the policies and profiles
        """
        res = 0
        for policy in self.policies.values():
            res += len(policy.findings)
        for profile in self.profiles.values():
            res += len(profile.findings)
        return res

    def find_policy(self, policy_name):
        """
        :param policy_name: The name of a policy (either fully-qualified or just policy name)
        :return: A list of all policy objects matching the policy name
        :rtype: list[NetworkPolicy]
        """
        res = []
        if policy_name in self.policies:
            res.append(self.policies[policy_name])
        elif policy_name.count('//') == 0:
            for policy in self.policies.values():
                if policy_name == policy.name:
                    res.append(policy)
        return res

    @staticmethod
    def _get_policy_type(policy):
        if isinstance(policy, K8sNetworkPolicy):
            return NetworkConfig.ConfigType.K8s
        if isinstance(policy, CalicoNetworkPolicy):
            return NetworkConfig.ConfigType.Calico
        return NetworkConfig.ConfigType.Unknown

    def add_policy(self, policy):
        """
        This should be the only place where we add policies to the config's set of policies
        :param policy: The policy to add
        :return: None
        """
        if not policy:
            return
        if policy.full_name() in self.policies:
            raise Exception('A policy named ' + policy.full_name() + ' already exists')
        policy_type = self._get_policy_type(policy)
        if policy_type == NetworkConfig.ConfigType.Unknown:
            raise Exception('Unknown policy type')
        if self.type == NetworkConfig.ConfigType.Unknown:
            self.type = policy_type
        elif self.type != policy_type:
            raise Exception('Cannot mix NetworkPolicies from different platforms')

        self.policies[policy.full_name()] = policy
        insort(self.sorted_policies, policy)

    def add_exclusive_policy_given_profiles(self, policy, profiles):
        self.profiles = profiles
        self.add_policy(policy)

    def _add_profile(self, profile):
        if not profile:
            return
        if profile.full_name() in self.profiles:
            raise Exception('A profile named ' + profile.full_name() + ' already exists')
        self.profiles[profile.full_name()] = profile

    def _parse_policies_in_parse_queue(self):
        for policy, file_name, policy_type in self._parse_queue:
            if policy_type == NetworkPolicy.PolicyType.CalicoProfile:
                parsed_element = CalicoPolicyYamlParser(policy, self.peer_container, file_name)
                self._add_profile(parsed_element.parse_policy())
            elif policy_type == NetworkPolicy.PolicyType.K8sNetworkPolicy:
                parsed_element = K8sPolicyYamlParser(policy, self.peer_container, file_name)
                self.add_policy(parsed_element.parse_policy())
            else:
                parsed_element = CalicoPolicyYamlParser(policy, self.peer_container, file_name)
                self.add_policy(parsed_element.parse_policy())

    def _add_policy_to_parse_queue(self, policy_object, file_name):
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
            self._add_policy_to_parse_queue(policy, file_name)

    def _add_policies(self, doc, file_name, is_list=False):
        yaml = YAML()
        code = yaml.load_all(doc)
        if is_list:
            for policy_list in code:
                if isinstance(policy_list, dict):
                    self._add_policies_to_parse_queue(policy_list.get('items', []), file_name)
                else:  # we got a list of lists, e.g., when combining calico np, gnp and profiles
                    for policy_list_list in policy_list:
                        if isinstance(policy_list_list, dict):
                            self._add_policies_to_parse_queue(policy_list_list.get('items', []), file_name)
        else:
            self._add_policies_to_parse_queue(code, file_name)

    def add_policies_from_file(self, filename):
        with open(filename) as doc:
            try:
                self._add_policies(doc, filename)
            except error.MarkedYAMLError as parse_error:
                print(parse_error.problem_mark.name + ':' + str(parse_error.problem_mark.line) + ':' +
                      str(parse_error.problem_mark.column) + ':', 'Parse Error:', parse_error.problem,  file=stderr)
                return
            except error.YAMLError:
                print(filename + ': Error: Bad yaml file')

    def add_policies_from_fs_dir(self, path):
        for root, _, files in os.walk(path):
            for file in files:
                if not file.endswith('.yaml') and not file.endswith('.yml'):
                    continue
                file_with_path = os.path.join(root, file)
                self.add_policies_from_file(file_with_path)

    def add_policies_from_github(self, url):
        yaml_files = GitScanner(url).get_yamls_in_repo()
        for yaml_file in yaml_files:
            for policy in yaml_file.data:
                self._add_policy_to_parse_queue(policy, yaml_file.path)

    def add_policies_from_k8s_cluster(self):
        PeerContainer.locate_kube_config_file()
        self._add_policies(CmdlineRunner.get_k8s_resources('networkPolicy'), 'kubectl', True)

    def add_policies_from_calico_cluster(self):
        self._add_policies(CmdlineRunner.get_calico_resources('profile'), 'calicoctl', True)
        self._add_policies(CmdlineRunner.get_calico_resources('networkPolicy'), 'calicoctl', True)
        self._add_policies(CmdlineRunner.get_calico_resources('globalNetworkPolicy'), 'calicoctl', True)

    def add_policies_from_entry(self, entry):
        if entry == 'k8s':
            self.add_policies_from_k8s_cluster()
        elif entry == 'calico':
            self.add_policies_from_calico_cluster()
        elif entry.startswith('https://github'):
            self.add_policies_from_github(entry)
        elif entry.startswith('buffer: '):
            self._add_policies(entry[8:], 'buffer', True)
        elif os.path.isfile(entry):
            self.add_policies_from_file(entry)
        elif os.path.isdir(entry):
            self.add_policies_from_fs_dir(entry)
        else:
            raise Exception(entry + ' is not a file or directory')

    def clone_without_policies(self, name):
        """
        :return: A clone of the config without any policies
        :rtype: NetworkConfig
        """
        res = NetworkConfig(name, self.peer_container, [], self.type)
        res.profiles = self.profiles
        return res

    def clone_without_policy(self, policy_to_exclude):
        """
        :param str policy_to_exclude: A policy name
        :return: A clone of the config having all policies but the one specified
        :rtype: NetworkConfig
        """
        res = self.clone_without_policies(self.name)
        for other_policy in self.policies.values():
            if other_policy != policy_to_exclude:
                res.add_policy(other_policy)
        return res

    def clone_with_just_one_policy(self, name_of_policy_to_include):
        """
        :param str name_of_policy_to_include: A policy name
        :return: A clone of the config having just a single policy as specified
        :rtype: NetworkConfig
        """
        if name_of_policy_to_include not in self.policies:
            raise Exception('No policy named ' + name_of_policy_to_include + ' in ' + self.name)

        res = self.clone_without_policies(self.name + '/' + name_of_policy_to_include)
        res.add_policy(self.policies[name_of_policy_to_include])
        return res

    def get_captured_pods(self):
        """
        :return: All pods captured by any policy
        :rtype: Peer.PeerSet
        """
        captured_pods = Peer.PeerSet()
        for policy in self.sorted_policies:
            captured_pods |= policy.selected_peers

        for profile in self.profiles.values():
            captured_pods |= profile.selected_peers

        return captured_pods

    def get_affected_pods(self, is_ingress):
        """
        :param bool is_ingress: Whether we return pods affected for ingress or for egress connection
        :return: All pods captured by any policy that affects ingress/egress (excluding profiles)
        :rtype: Peer.PeerSet
        """
        affected_pods = Peer.PeerSet()
        for policy in self.sorted_policies:
            if (is_ingress and policy.affects_ingress) or (not is_ingress and policy.affects_egress):
                affected_pods |= policy.selected_peers

        return affected_pods

    def get_referenced_ip_blocks(self):
        """
        :return: All ip ranges, referenced in any of the policies' rules
        :rtype: Peer.PeerSet
        """
        if self.referenced_ip_blocks is not None:
            return self.referenced_ip_blocks

        self.referenced_ip_blocks = Peer.PeerSet()
        for policy in self.policies.values():
            self.referenced_ip_blocks |= policy.referenced_ip_blocks()
        for profile in self.profiles.values():
            self.referenced_ip_blocks |= profile.referenced_ip_blocks()

        return self.referenced_ip_blocks

    def _get_profile_conns(self, from_peer, to_peer, is_ingress):
        peer = to_peer if is_ingress else from_peer
        assert isinstance(peer, Peer.ClusterEP)
        profile_name = peer.get_first_profile_name()
        if not profile_name:
            return PolicyConnections(False)
        profile = self.profiles.get(profile_name)
        if not profile:
            raise Exception(peer.full_name() + ' refers to a non-existing profile ' + profile_name)
        return profile.allowed_connections(from_peer, to_peer, is_ingress)

    def _allowed_xgress_conns(self, from_peer, to_peer, is_ingress, only_captured=False):
        allowed_conns = ConnectionSet()
        denied_conns = ConnectionSet()
        pass_conns = ConnectionSet()
        policy_captured = False
        for policy in self.sorted_policies:
            policy_conns = policy.allowed_connections(from_peer, to_peer, is_ingress)
            assert isinstance(policy_conns, PolicyConnections)
            if policy_conns.captured:
                policy_captured = True
                policy_conns.denied_conns -= allowed_conns
                policy_conns.denied_conns -= pass_conns
                denied_conns |= policy_conns.denied_conns
                policy_conns.allowed_conns -= denied_conns
                policy_conns.allowed_conns -= pass_conns
                allowed_conns |= policy_conns.allowed_conns
                policy_conns.pass_conns -= denied_conns
                policy_conns.pass_conns -= allowed_conns
                pass_conns |= policy_conns.pass_conns

        if not policy_captured:
            if self.type == NetworkConfig.ConfigType.K8s:
                allowed_conns = ConnectionSet(True)  # default Allow-all ingress in k8s
            else:
                if only_captured:
                    allowed_conns = ConnectionSet()
                else:
                    allowed_conns = self._get_profile_conns(from_peer, to_peer, is_ingress).allowed_conns
        elif pass_conns:
            allowed_conns |= pass_conns & self._get_profile_conns(from_peer, to_peer, is_ingress).allowed_conns
        return PolicyConnections(policy_captured, allowed_conns, denied_conns)

    def allowed_connections(self, from_peer, to_peer, only_captured=False):
        """
        This is the core of the whole application - computes the set of allowed connections from one peer to another.
        In our connectivity model, this function computes the labels for the edges in our directed graph.
        :param Peer.Peer from_peer: The source peer
        :param Peer.Peer to_peer: The target peer
        :param bool only_captured: whether to only consider explicitly allowed/denied connections (ignore defaults)
        :return: A triplet: whether any policy captured the pods, the allowed connections, the denied connections
        :rtype: bool, ConnectionSet, ConnectionSet
        """
        if isinstance(to_peer, Peer.IpBlock):
            ingress_conns = PolicyConnections(False, ConnectionSet(True))
        else:
            ingress_conns = self._allowed_xgress_conns(from_peer, to_peer, True, only_captured)

        if isinstance(from_peer, Peer.IpBlock):
            egress_conns = PolicyConnections(False, ConnectionSet(True))
        else:
            egress_conns = self._allowed_xgress_conns(from_peer, to_peer, False, only_captured)

        captured = ingress_conns.captured or egress_conns.captured
        allowed_conns = ingress_conns.allowed_conns & egress_conns.allowed_conns
        denied_conns = ingress_conns.denied_conns | egress_conns.denied_conns
        return captured, allowed_conns, denied_conns
