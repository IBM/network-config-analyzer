#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from bisect import insort
from enum import Enum
from dataclasses import dataclass, field
import Peer
from PeerContainer import PeerContainer
from NetworkPolicy import PolicyConnections, NetworkPolicy
from K8sNetworkPolicy import K8sNetworkPolicy
from CalicoNetworkPolicy import CalicoNetworkPolicy
from IstioNetworkPolicy import IstioNetworkPolicy
from IngressPolicy import IngressPolicy
from ConnectionSet import ConnectionSet


@dataclass
class PoliciesContainer:
    """
    A class for holding policies, profiles etc.
    """
    policies: dict = field(default_factory=dict)
    sorted_policies: list = field(default_factory=list)
    ingress_deny_policies: list = field(default_factory=list)
    profiles: dict = field(default_factory=dict)


class NetworkConfig:
    """
    Represents a network configuration - the set of endpoints, their partitioning to namespaces and a set of policies
    that limit the allowed connectivity.
    The class also contains the core algorithm of computing allowed connections between two endpoints.
    """

    class ConfigType(Enum):
        Unknown = 0
        K8s = 1
        Calico = 2
        Istio = 3
        Ingress = 4

    def __init__(self, name, peer_container, policies_container, config_type=None):
        """
        :param str name: A name for this config
        :param PeerContainer peer_container: The set of endpoints and their namespaces
        :param PoliciesContainer policies_container : The container of policies, profiles,
        and sorted policies
        :param ConfigType config_type: The type of configuration
        """
        self.name = name
        self.peer_container = peer_container
        self.policies = policies_container.policies or {}
        self.sorted_policies = policies_container.sorted_policies or []
        self.ingress_deny_policies = policies_container.ingress_deny_policies or []
        self.profiles = policies_container.profiles or {}
        self.allowed_labels = set()
        if self.policies:
            self._set_allowed_labels()
        self.referenced_ip_blocks = None
        self.type = config_type or NetworkConfig.ConfigType.Unknown

    def __eq__(self, other):
        if not isinstance(other, NetworkConfig):
            return False
        return self.name == other.name and self.peer_container == other.peer_container and \
            self.policies == other.policies

    def __str__(self):
        return self.name

    def __bool__(self):
        return len(self.policies) > 0

    def _set_allowed_labels(self):
        for policy in self.policies.values():
            self.allowed_labels |= policy.referenced_labels

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

    def clone_without_policies(self, name):
        """
        :return: A clone of the config without any policies
        :rtype: NetworkConfig
        """
        policies_container = PoliciesContainer(profiles=self.profiles)
        res = NetworkConfig(name, peer_container=self.peer_container, policies_container=policies_container,
                            config_type=self.type)
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
                res.append_policy_to_config(other_policy)
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
        res.append_policy_to_config(self.policies[name_of_policy_to_include])
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

        # consider ingress only if the config contains only ingress policies
        if not self.sorted_policies and not self.profiles:
            for ingress in self.ingress_deny_policies:
                captured_pods |= ingress.selected_peers

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
        # TODO: if changing the full name of policy to include the layer, should consider it as follows
        # profile = self.profiles.get(f'[CalicoNetworkPolicy]{profile_name}')
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
        ingress_denied_conns = ConnectionSet()
        pass_conns = ConnectionSet()

        if not is_ingress:
            for policy in self.ingress_deny_policies:
                policy_conns = policy.allowed_connections(from_peer, to_peer, is_ingress)
                ingress_denied_conns |= policy_conns.denied_conns

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
                # egress currently always allowed and not captured (unless denied by Ingress resource)
                allowed_non_captured_conns = ConnectionSet(True) - ingress_denied_conns
            elif not has_allow_policies_for_target:
                # add connections allowed by default that are not captured
                allowed_non_captured_conns |= (ConnectionSet(True) - denied_conns)

            return PolicyConnections(has_allow_policies_for_target, allowed_conns, denied_conns,
                                     all_allowed_conns=allowed_conns | allowed_non_captured_conns)

        allowed_non_captured_conns = ConnectionSet()
        if not policy_captured:
            if self.type in [NetworkConfig.ConfigType.K8s, NetworkConfig.ConfigType.Ingress,
                             NetworkConfig.ConfigType.Unknown]:
                # default Allow-all (not denied by ingress) in k8s or in case of no policy
                allowed_non_captured_conns = ConnectionSet(True)
            else:
                if self.profiles:
                    allowed_non_captured_conns = self._get_profile_conns(from_peer, to_peer, is_ingress).allowed_conns
        elif pass_conns:
            allowed_conns |= pass_conns & self._get_profile_conns(from_peer, to_peer, is_ingress).allowed_conns
        allowed_conns -= ingress_denied_conns
        allowed_non_captured_conns -= ingress_denied_conns
        # It's enough that ingress impacts allowed_conns.
        # We don't want to mix the denied_conns of the network policy by ingress,
        # we want to preserve the specific network policy's denied connections for the output report.
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

    @staticmethod
    def get_policy_type(policy):
        if isinstance(policy, K8sNetworkPolicy):
            return NetworkConfig.ConfigType.K8s
        if isinstance(policy, CalicoNetworkPolicy):
            return NetworkConfig.ConfigType.Calico
        if isinstance(policy, IstioNetworkPolicy):
            return NetworkConfig.ConfigType.Istio
        if isinstance(policy, IngressPolicy):
            return NetworkConfig.ConfigType.Ingress
        return NetworkConfig.ConfigType.Unknown

    def append_policy_to_config(self, policy):
        """
        appends a policy to an existing config
        :param NetworkPolicy policy: The policy to append
        :return: None
        """
        if not policy:
            return
        policy_type = self.get_policy_type(policy)
        if self.type == NetworkConfig.ConfigType.Unknown or not self.policies or \
                self.type == NetworkConfig.ConfigType.Ingress:
            self.type = policy_type
        self.policies[policy.full_name()] = policy
        self.allowed_labels |= policy.referenced_labels
        if policy_type == NetworkConfig.ConfigType.Ingress:
            insort(self.ingress_deny_policies, policy)
        else:
            insort(self.sorted_policies, policy)
