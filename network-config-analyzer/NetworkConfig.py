#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from enum import Enum
from dataclasses import dataclass, field
import Peer
from PeerContainer import PeerContainer
from K8sNetworkPolicy import K8sNetworkPolicy
from CalicoNetworkPolicy import CalicoNetworkPolicy
from IstioNetworkPolicy import IstioNetworkPolicy
from IngressPolicy import IngressPolicy
from NetworkLayer import NetworkLayersContainer, NetworkLayerName


@dataclass
class PoliciesContainer:
    """
    A class for holding policies map and layers map containing sorted policies per layer
    policies: map from tuples (policy name, policy type) to policy objects
    layers: map from layer name to layer object
    """
    policies: dict = field(default_factory=dict)
    layers: NetworkLayersContainer = field(default_factory=NetworkLayersContainer)


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

        @staticmethod
        def input_layer_name_str_to_config_type(layer_name):
            if layer_name == "k8s":
                return NetworkConfig.ConfigType.K8s
            elif layer_name == "calico":
                return NetworkConfig.ConfigType.Calico
            elif layer_name == "istio":
                return NetworkConfig.ConfigType.Istio
            elif layer_name == "ingress":
                return NetworkConfig.ConfigType.Ingress
            return None

        def config_type_to_layer(self):
            if self == NetworkConfig.ConfigType.K8s:
                return NetworkLayerName.K8s_Calico
            elif self == NetworkConfig.ConfigType.Calico:
                return NetworkLayerName.K8s_Calico
            elif self == NetworkConfig.ConfigType.Istio:
                return NetworkLayerName.Istio
            elif self == NetworkConfig.ConfigType.Ingress:
                return NetworkLayerName.Ingress
            return None

    def __init__(self, name, peer_container, policies_container):
        """
        :param str name: A name for this config
        :param PeerContainer peer_container: The set of endpoints and their namespaces
        """
        self.name = name
        self.peer_container = peer_container
        self.policies = policies_container.policies or {}  # map from policy name to policy object
        self.layers = policies_container.layers or NetworkLayersContainer()  # map from layer name to layer object
        self.allowed_labels = None
        self.referenced_ip_blocks = None

    def __eq__(self, other):
        if not isinstance(other, NetworkConfig):
            return False
        return self.name == other.name and self.peer_container == other.peer_container and self.policies == other.policies

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
        # for profile in self.profiles.values():
        #    res += len(profile.findings)
        return res

    def find_policy(self, policy_name, required_policy_type=None):
        """
        :param str policy_name: The name of a policy (either fully-qualified or just policy name)
        :param NetworkConfig.ConfigType required_policy_type: The type of policy to find
        :return: A list of all policy objects matching the policy name
        :rtype: list[NetworkPolicy.NetworkPolicy]
        """
        res = []
        possible_policy_types = [required_policy_type] if required_policy_type else NetworkConfig.ConfigType
        for policy_type in possible_policy_types:
            if (policy_name, policy_type) in self.policies:
                res.append(self.policies[(policy_name, policy_type)])
        if not res and policy_name.count('//') == 0:
            for policy in self.policies.values():
                policy_type = NetworkConfig.get_policy_type(policy)
                if policy_name == policy.name and (not required_policy_type or policy_type == required_policy_type):
                    res.append(policy)
        return res

    def clone_without_policies(self, name):
        """
        :return: A clone of the config without any policies
        :rtype: NetworkConfig
        """
        policies_container = PoliciesContainer()  # PoliciesContainer(profiles=self.profiles)
        res = NetworkConfig(name, peer_container=self.peer_container, policies_container=policies_container)
        # res.layers.finalize_layers()
        return res

    def clone_without_policy(self, policy_to_exclude):
        """
        :param NetworkPolicy policy_to_exclude: A policy object to exclude from the clone
        :return: A clone of the config having all policies but the one specified
        :rtype: NetworkConfig
        """
        res = self.clone_without_policies(self.name)
        for other_policy in self.policies.values():
            if other_policy != policy_to_exclude:
                res.append_policy_to_config(other_policy)
        return res

    def clone_with_just_one_policy(self, name_of_policy_to_include, policy_type=None):
        """
        :param str name_of_policy_to_include: A policy name
        :param PolicyType policy_type: The type of policy to include
        :return: A clone of the config having just a single policy as specified
        :rtype: NetworkConfig
        """
        matching_policies = self.find_policy(name_of_policy_to_include, policy_type)
        if not matching_policies:
            raise Exception(f'No policy named {name_of_policy_to_include} in {self.name}')
        elif len(matching_policies) > 1:
            raise Exception(f'More than one policy named {name_of_policy_to_include} in {self.name}')
        policy = matching_policies[0]

        # here we do not want to preserve active layers from orig config, only have the layer of the relevant policy as active
        res = self.clone_without_policies(self.name + '/' + name_of_policy_to_include)
        res.append_policy_to_config(policy)
        # res.layers.finalize_layers()
        # res.layers = res.get_config_layers_dict()
        return res

    def get_captured_pods(self, layer_name=None):
        """
        :param NetworkLayerName layer_name: The name of a layer to get the pods from
        :return: All pods captured by any policy, in at least one layer
        :rtype: Peer.PeerSet
        """
        # TODO: should ignore Ingress layer?
        captured_pods = Peer.PeerSet()
        # get all policies list (of all layers) or all policies per input layer
        if layer_name is None:
            policies_list = self.policies.values()
        else:
            policies_list = self.layers[layer_name].policies_list if layer_name in self.layers else []

        for policy in policies_list:
            captured_pods |= policy.selected_peers

        # TODO:  why was profile.selected_peers considered captured, if profiles may be used for nan captured conns?
        # for profile in self.profiles.values():
        #    captured_pods |= profile.selected_peers

        # consider ingress only if the config contains only ingress policies
        # if not self.sorted_policies and not self.profiles:
        #    for ingress in self.ingress_deny_policies:
        #        captured_pods |= ingress.selected_peers

        return captured_pods

    def get_affected_pods(self, is_ingress, layer_name):
        """
        :param bool is_ingress: Whether we return pods affected for ingress or for egress connection
        :param NetworkLayerName layer_name: The name of the layer to use
        :return: All pods captured by any policy that affects ingress/egress (excluding profiles)
        :rtype: Peer.PeerSet
        """
        affected_pods = Peer.PeerSet()
        policies_list = self.layers[layer_name].policies_list
        for policy in policies_list:
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
        # for profile in self.profiles.values():
        #    self.referenced_ip_blocks |= profile.referenced_ip_blocks()

        return self.referenced_ip_blocks

    def get_allowed_labels(self):
        if self.allowed_labels is not None:
            return self.allowed_labels
        self.allowed_labels = set()
        for policy in self.policies.values():
            self.allowed_labels |= policy.referenced_labels
        return self.allowed_labels

    # return the allowed connections considering all layers in the config
    def allowed_connections(self, from_peer, to_peer, layer_name=None):
        """
        This is the core of the whole application - computes the set of allowed connections from one peer to another.
        In our connectivity model, this function computes the labels for the edges in our directed graph.
        :param Peer.Peer from_peer: The source peer
        :param Peer.Peer to_peer: The target peer
        :param NetworkLayerName layer_name: The name of the layer to use, if requested to use a specific layer only
        :return: a 4-tuple with:
          - allowed_conns: all allowed connections (captured/non-captured)
          - captured_flag: flag to indicate if any of the policies captured one of the peers (src/dst)
          - allowed_captured_conns: allowed captured connections (can be used only if the captured flag is True)
          - denied_conns: connections denied by the policies (captured)
        :rtype: ConnectionSet, bool, ConnectionSet, ConnectionSet
        """
        if layer_name is not None:
            if layer_name not in self.layers:
                self.layers.add_empty_layer(layer_name)
            return self.layers[layer_name].allowed_connections(from_peer, to_peer)

        # TODO initialize differently?
        allowed_conns_res = None
        allowed_captured_conns_res = None
        captured_flag_res = None
        denied_conns_res = None

        # connectivity of hostEndpoints is only determined by calico layer
        if isinstance(from_peer, Peer.HostEP) or isinstance(to_peer, Peer.HostEP):
            # maintain K8s_Calico layer as active if peer container has hostEndpoint
            if NetworkLayerName.K8s_Calico not in self.layers:
                self.layers.add_empty_layer(NetworkLayerName.K8s_Calico)
            return self.layers[NetworkLayerName.K8s_Calico].allowed_connections(from_peer, to_peer)

        for layer, layer_obj in self.layers.items():

            allowed_conns_per_layer, captured_flag_per_layer, allowed_captured_conns_per_layer, denied_conns_per_layer = layer_obj.allowed_connections(
                from_peer, to_peer)

            if allowed_conns_res is None:
                allowed_conns_res = allowed_conns_per_layer
                allowed_captured_conns_res = allowed_captured_conns_per_layer
                captured_flag_res = captured_flag_per_layer
                denied_conns_res = denied_conns_per_layer
            else:
                # all allowed connections: intersection of all allowed connections from all layers
                allowed_conns_res &= allowed_conns_per_layer

                # all allowed captured connections: should be captured by at least one layer
                allowed_captured_conns_res |= allowed_captured_conns_per_layer
                captured_flag_res |= captured_flag_per_layer

                # denied conns: should be denied by at least one layer
                denied_conns_res |= denied_conns_per_layer

        # an allowed captured conn (by at least one layer) has to be allowed by all layers (either implicitly or explicitly)
        allowed_captured_conns_res &= allowed_conns_res

        return allowed_conns_res, captured_flag_res, allowed_captured_conns_res, denied_conns_res

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

    @staticmethod
    def append_policy(policy, policies_map, layers_map):
        # validate input policy
        if not policy:
            return
        policy_type = NetworkConfig.get_policy_type(policy)
        if policy_type == NetworkConfig.ConfigType.Unknown:
            raise Exception('Unknown policy type')
        if (policy.full_name(), policy_type) in policies_map:
            raise Exception(f'A policy named {policy.full_name()} of type {policy_type} already exists')

        # update policies map
        policies_map[(policy.full_name(), policy_type)] = policy
        # add policy to the corresponding layer's list (sorted) of policies
        layers_map.add_policy(policy, policy_type.config_type_to_layer())

    def append_policy_to_config(self, policy):
        """
        appends a policy to an existing config
        :param NetworkPolicy.NetworkPolicy policy: The policy to append
        :return: None
        """
        self.append_policy(policy, self.policies, self.layers)

    '''
    @staticmethod
    def append_policy_old(policy, policies_map, sorted_policies, ingress_policies, current_config_type):
        """
        Append a new policy into current config and determine the updated config type
        :param NetworkPolicy.NetworkPolicy policy: the policy to append
        :param dict policies_map: the map of policies by (name,type) to policy objects
        :param sorted_policies: the sorted list of policies
        :param list ingress_policies: the list of ingress policies
        :param NetworkConfig.ConfigType current_config_type: the current config type
        :return: the new config type after adding the policy
        :rtype: NetworkConfig.ConfigType
        """
        new_config_type = current_config_type

        # validate input policy
        if not policy:
            return new_config_type
        policy_type = NetworkConfig.get_policy_type(policy)
        if policy_type == NetworkConfig.ConfigType.Unknown:
            raise Exception('Unknown policy type')
        if (policy.full_name(), policy_type) in policies_map:
            raise Exception(f'A policy named {policy.full_name()} of type {policy_type} already exists')

        # determine new config type
        if current_config_type == NetworkConfig.ConfigType.Unknown or not policies_map or \
                current_config_type == NetworkConfig.ConfigType.Ingress:
            new_config_type = policy_type
        elif {current_config_type, policy_type} == {NetworkConfig.ConfigType.Calico, NetworkConfig.ConfigType.K8s}:
            new_config_type = NetworkConfig.ConfigType.Calico
        # elif current_config_type != policy_type and policy_type != NetworkConfig.ConfigType.Ingress:
        #    raise Exception('Cannot mix NetworkPolicies from different platforms')

        # update policies map and sorted policies list
        policies_map[(policy.full_name(), policy_type)] = policy
        if policy_type != NetworkConfig.ConfigType.Ingress:
            insort(sorted_policies, policy)
        else:
            ingress_policies.append(policy)

        return new_config_type
    '''
    '''
    @staticmethod
    def append_profile(profile, profiles_map, current_config_type):
        """
        Append a new profile into current config and determine the updated config type
        :param CalicoNetworkPolicy profile: the profile to append
        :param dict profiles_map: the map of profiles by name to profile objects
        :param NetworkConfig.ConfigType current_config_type:
        :return: the new config type after adding the profile
        :rtype: NetworkConfig.ConfigType
        """
        new_config_type = current_config_type

        # validate input profile
        if not profile:
            return new_config_type
        if profile.full_name() in profiles_map:
            raise Exception(f'A profile named {profile.full_name()} already exists')

        # determine new config type
        if current_config_type in {NetworkConfig.ConfigType.Unknown, NetworkConfig.ConfigType.K8s,
                                   NetworkConfig.ConfigType.Ingress}:
            new_config_type = NetworkConfig.ConfigType.Calico
        elif current_config_type != NetworkConfig.ConfigType.Calico:
            raise Exception('Cannot mix NetworkPolicies from different platforms')

        # update profiles map
        profiles_map[profile.full_name()] = profile

        return new_config_type
    '''

    '''
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
    '''

    '''
    def _allowed_xgress_conns_old(self, from_peer, to_peer, is_ingress):
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
    '''

    '''
    def allowed_connections_old(self, from_peer, to_peer):
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
    '''
