#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from bisect import insort
from enum import Enum
from collections import deque
from ruamel.yaml import YAML
import Peer
from PeerContainer import PeerContainer
from NetworkPolicy import PolicyConnections, NetworkPolicy
from K8sPolicyYamlParser import K8sPolicyYamlParser
from CalicoPolicyYamlParser import CalicoPolicyYamlParser
from K8sNetworkPolicy import K8sNetworkPolicy
from CalicoNetworkPolicy import CalicoNetworkPolicy
from IstioNetworkPolicy import IstioNetworkPolicy
from IstioPolicyYamlParser import IstioPolicyYamlParser
from ConnectionSet import ConnectionSet
from CmdlineRunner import CmdlineRunner
from GenericTreeScanner import TreeScannerFactory


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

    def __init__(self, name, peer_container, entry_list=None, config_type=None, buffer=None):
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
        self.allowed_labels = set()
        peer_container.clear_pods_extra_labels()
        if buffer is not None:
            self._add_policies(buffer, 'buffer', True)
        else:  # if entry_list is not None:
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
        if isinstance(policy, IstioNetworkPolicy):
            return NetworkConfig.ConfigType.Istio
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

        self.allowed_labels |= policy.referenced_labels

    def add_exclusive_policy_given_profiles(self, policy, profiles):
        self.profiles = profiles
        self.add_policy(policy)

    def _add_profile(self, profile):
        if not profile:
            return
        if profile.full_name() in self.profiles:
            raise Exception('A profile named ' + profile.full_name() + ' already exists')
        if self.type == NetworkConfig.ConfigType.Unknown:
            self.type = NetworkConfig.ConfigType.Calico
        elif self.type != NetworkConfig.ConfigType.Calico:
            raise Exception('Cannot mix NetworkPolicies from different platforms')
        self.profiles[profile.full_name()] = profile

    def _parse_policies_in_parse_queue(self):
        for policy, file_name, policy_type in self._parse_queue:
            if policy_type == NetworkPolicy.PolicyType.CalicoProfile:
                parsed_element = CalicoPolicyYamlParser(policy, self.peer_container, file_name)
                self._add_profile(parsed_element.parse_policy())
            elif policy_type == NetworkPolicy.PolicyType.K8sNetworkPolicy:
                parsed_element = K8sPolicyYamlParser(policy, self.peer_container, file_name)
                self.add_policy(parsed_element.parse_policy())
            elif policy_type == NetworkPolicy.PolicyType.IstioAuthorizationPolicy:
                parsed_element = IstioPolicyYamlParser(policy, self.peer_container, file_name)
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

    def scan_entry_for_policies(self, entry):
        entry_scanner = TreeScannerFactory.get_scanner(entry, rt_load=True)
        if entry_scanner is None:
            return False
        yaml_files = entry_scanner.get_yamls()
        if not yaml_files:
            return False
        for yaml_file in yaml_files:
            for policy in yaml_file.data:
                self._add_policy_to_parse_queue(policy, yaml_file.path)
        return True

    def add_policies_from_k8s_cluster(self):
        self._add_policies(CmdlineRunner.get_k8s_resources('networkPolicy'), 'kubectl', True)

    def add_policies_from_calico_cluster(self):
        self._add_policies(CmdlineRunner.get_calico_resources('profile'), 'calicoctl', True)
        self._add_policies(CmdlineRunner.get_calico_resources('networkPolicy'), 'calicoctl', True)
        self._add_policies(CmdlineRunner.get_calico_resources('globalNetworkPolicy'), 'calicoctl', True)

    def add_istio_policies_from_k8s_cluster(self):
        self._add_policies(CmdlineRunner.get_k8s_resources('authorizationPolicy'), 'kubectl', True)

    def add_policies_from_entry(self, entry):
        if entry == 'k8s':
            self.add_policies_from_k8s_cluster()
        elif entry == 'calico':
            self.add_policies_from_calico_cluster()
        elif entry == 'istio':
            self.add_istio_policies_from_k8s_cluster()
        elif not self.scan_entry_for_policies(entry):
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

    def _allowed_xgress_conns(self, from_peer, to_peer, is_ingress):
        """
        get allowed and denied ingress/egress connections between from_peer and to_peer,
        considering all config's policies (and defaults)
        :param from_peer: the source peer
        :param to_peer: the dest peer
        :param is_ingress: flag to indicate if should return ingress connections or egress connections
        :return: PolicyConnections object with:
          - captured: flag to indicate if any of the policies captured one of the peers (src/dst)
          - allowed_conns: allowed captured connections (can be used only if the captured flag is True)
          - denied_conns: connections denied by the policies (captured)
          - pass_conns: irrelevant , always empty
          - all_allowed_conns: all allowed connections (captured/non-captured)
        :rtype: PolicyConnections
        """
        allowed_conns = ConnectionSet()
        denied_conns = ConnectionSet()
        pass_conns = ConnectionSet()

        policy_captured = False
        has_allow_policies_for_target = False
        for policy in self.sorted_policies:
            policy_conns = policy.allowed_connections(from_peer, to_peer, is_ingress)
            assert isinstance(policy_conns, PolicyConnections)
            if policy_conns.captured:
                policy_captured = True
                if isinstance(policy, IstioNetworkPolicy) and policy.action == IstioNetworkPolicy.ActionType.Allow:
                    has_allow_policies_for_target = True
                policy_conns.denied_conns -= allowed_conns
                policy_conns.denied_conns -= pass_conns
                denied_conns |= policy_conns.denied_conns
                policy_conns.allowed_conns -= denied_conns
                policy_conns.allowed_conns -= pass_conns
                allowed_conns |= policy_conns.allowed_conns
                policy_conns.pass_conns -= denied_conns
                policy_conns.pass_conns -= allowed_conns
                pass_conns |= policy_conns.pass_conns

        if self.type == NetworkConfig.ConfigType.Istio:
            # for istio initialize non-captured conns with non-TCP connections
            allowed_non_captured_conns = ConnectionSet.get_non_tcp_connections()
            if not is_ingress:
                allowed_non_captured_conns = ConnectionSet(True)  # egress currently always allowed and not captured
            elif not has_allow_policies_for_target:
                # add connections allowed by default that are not captured
                allowed_non_captured_conns |= (ConnectionSet(True) - denied_conns)

            return PolicyConnections(has_allow_policies_for_target, allowed_conns, denied_conns,
                                     all_allowed_conns=allowed_conns | allowed_non_captured_conns)

        allowed_non_captured_conns = ConnectionSet()
        if not policy_captured:
            if self.type in [NetworkConfig.ConfigType.K8s, NetworkConfig.ConfigType.Unknown]:
                allowed_non_captured_conns = ConnectionSet(True)  # default Allow-all ingress in k8s or in case of no policy
            else:
                if self.profiles:
                    allowed_non_captured_conns = self._get_profile_conns(from_peer, to_peer, is_ingress).allowed_conns
        elif pass_conns:
            allowed_conns |= pass_conns & self._get_profile_conns(from_peer, to_peer, is_ingress).allowed_conns
        return PolicyConnections(policy_captured, allowed_conns, denied_conns,
                                 all_allowed_conns=allowed_conns | allowed_non_captured_conns)

    def allowed_connections(self, from_peer, to_peer):
        """
        This is the core of the whole application - computes the set of allowed connections from one peer to another.
        In our connectivity model, this function computes the labels for the edges in our directed graph.
        :param Peer.Peer from_peer: The source peer
        :param Peer.Peer to_peer: The target peer
        :return: a 4-tuple with:
          - allowed_conns: all allowed connections (captured/non-captured)
          - captured_flag: flag to indicate if any of the policies captured one of the peers (src/dst)
          - allowed_captured_conns: allowed captured connections (can be used only if the captured flag is True)
          - denied_conns: connections denied by the policies (captured)
        :rtype: ConnectionSet, bool, ConnectionSet, ConnectionSet
        """
        if isinstance(to_peer, Peer.IpBlock):
            ingress_conns = PolicyConnections(captured=False, all_allowed_conns=ConnectionSet(True))
        else:
            ingress_conns = self._allowed_xgress_conns(from_peer, to_peer, True)

        if isinstance(from_peer, Peer.IpBlock):
            egress_conns = PolicyConnections(captured=False, all_allowed_conns=ConnectionSet(True))
        else:
            egress_conns = self._allowed_xgress_conns(from_peer, to_peer, False)

        captured_flag = ingress_conns.captured or egress_conns.captured
        denied_conns = ingress_conns.denied_conns | egress_conns.denied_conns
        allowed_conns = ingress_conns.all_allowed_conns & egress_conns.all_allowed_conns
        # captured connections are where at least one if ingress / egress is captured
        allowed_captured_conns = (ingress_conns.allowed_conns & egress_conns.all_allowed_conns) | \
            (egress_conns.allowed_conns & ingress_conns.all_allowed_conns)

        return allowed_conns, captured_flag, allowed_captured_conns, denied_conns
