#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
from bisect import insort
from enum import Enum

from nca.CoreDS.Peer import IpBlock, HostEP, PeerSet
from nca.CoreDS.ConnectivityCube import ConnectivityCube
from nca.CoreDS.ConnectivityProperties import ConnectivityProperties
from nca.CoreDS.ProtocolSet import ProtocolSet
from nca.Resources.PolicyResources.IstioNetworkPolicy import IstioNetworkPolicy
from nca.Resources.PolicyResources.GatewayPolicy import GatewayPolicy
from nca.Resources.PolicyResources.NetworkPolicy import PolicyConnections, NetworkPolicy, \
    PolicyConnectionsFilter
from nca.Utils.ExplTracker import ExplTracker


# TODO: add a layer for connectivity based on service type (culsterIP / LB / NodePort)? / containers ports?


class NetworkLayerName(Enum):
    K8s_Calico = 0
    Istio = 1
    K8sGateway = 2
    IstioGateway = 3

    def create_network_layer(self, policies):
        if self == NetworkLayerName.K8s_Calico:
            return K8sCalicoNetworkLayer(policies)
        if self == NetworkLayerName.Istio:
            return IstioNetworkLayer(policies)
        if self == NetworkLayerName.K8sGateway:
            return K8sGatewayLayer(policies)
        if self == NetworkLayerName.IstioGateway:
            return IstioGatewayLayer(policies)
        return None

    @staticmethod
    def policy_type_to_layer(policy_type):
        if policy_type in {NetworkPolicy.PolicyType.K8sNetworkPolicy, NetworkPolicy.PolicyType.CalicoNetworkPolicy,
                           NetworkPolicy.PolicyType.CalicoGlobalNetworkPolicy, NetworkPolicy.PolicyType.CalicoProfile}:
            return NetworkLayerName.K8s_Calico
        elif policy_type in {NetworkPolicy.PolicyType.IstioAuthorizationPolicy, NetworkPolicy.PolicyType.IstioSidecar}:
            return NetworkLayerName.Istio
        elif policy_type in {NetworkPolicy.PolicyType.Ingress}:
            return NetworkLayerName.K8sGateway
        elif policy_type in {NetworkPolicy.PolicyType.GatewayPolicy}:
            return NetworkLayerName.IstioGateway
        return None


class NetworkLayersContainer(dict):
    """
    NetworkLayersContainer contains all relevant network layers with their associated policies.
    It is a map from NetworkLayerName to NetworkLayer object.
    The following assumptions should always hold:
    (1) If none of the layers have policies, the map should have the default layer (calico_k8s), without policies, only.
    (2) If a layer has no policies, it should not be in the map (except for the case of the default layer if required)
    """
    default_layer = NetworkLayerName.K8s_Calico

    def __init__(self):
        initial_layers_dict = {NetworkLayersContainer.default_layer: K8sCalicoNetworkLayer([])}
        super().__init__(initial_layers_dict)

    def __getattr__(self, name):
        return super().__getitem__(name)

    def add_policy(self, policy, layer_name):
        """
        Adds a policy to the given layer.
        :param NetworkPolicy.NetworkPolicy policy: the policy to add
        :param NetworkLayerName layer_name: the relevant layer to add the policy to
        :return: None
        """
        if not isinstance(layer_name, NetworkLayerName):
            return
        if layer_name not in self:
            self[layer_name] = layer_name.create_network_layer([policy])
        else:
            self[layer_name].add_policy(policy)
        if self.default_layer in self and not self[self.default_layer].policies_list:
            del self[self.default_layer]

    def does_contain_only_gateway_layers(self):
        """
        Checks if the map contains only gateway layers.
        :return: True if the map contains only gateway layers, False otherwise
        """
        return bool(self) and set(self.keys()).issubset({NetworkLayerName.K8sGateway, NetworkLayerName.IstioGateway})

    def does_contain_istio_layers(self):
        """
        Checks if any of Istio layers is in the map.
        :return: True if any of Istio layers is in the map, False otherwise
        """
        return bool({NetworkLayerName.Istio, NetworkLayerName.IstioGateway} & set(self.keys()))

    @staticmethod
    def empty_layer_allowed_connections(peer_container, layer_name, res_conns_filter=PolicyConnectionsFilter()):
        """
        Get allowed connections between for all relevant peers for an empty layer (no policies).
        :param PeerContainer peer_container: holds all the peers
        :param NetworkLayerName layer_name: The empty layer name
        :param PolicyConnectionsFilter res_conns_filter: filter of the required resulting connections
        (connections with None value will not be calculated)
        :rtype: PolicyConnections
        """
        empty_layer_obj = layer_name.create_network_layer([])
        return empty_layer_obj.allowed_connections(peer_container, res_conns_filter)


class NetworkLayer:
    """
    NetworkLayer can be one of the layers: K8s_Calico, Istio, Ingress
    It contains the layer name and a sorted list of its relevant policies
    """

    def __init__(self, policies_list):
        """
        :param list[NetworkPolicy.NetworkPolicy] policies_list: the sorted list of policies in the layer
        """
        self.policies_list = policies_list  # sorted list of policies for this layer

    def add_policy(self, policy):
        """
        Adds a policy to the layer.
        :param NetworkPolicy.NetworkPolicy policy: the policy to add
        """
        insort(self.policies_list, policy)

    def allowed_connections(self, peer_container, res_conns_filter=PolicyConnectionsFilter()):
        """
        Compute per network layer the allowed connections between any relevant peers,
        considering all layer's policies (and defaults)
        :param PeerContainer peer_container: the peer container holding the peers
        :param PolicyConnectionsFilter res_conns_filter: filter of the required resulting connections
        (connections with None value will not be calculated)
        :return: all allowed, denied and captured connections
        :rtype: PolicyConnections
        """
        res_conns = PolicyConnections()
        ingress_conns = self._allowed_xgress_conns(True, peer_container, res_conns_filter)
        egress_conns = self._allowed_xgress_conns(False, peer_container, res_conns_filter)
        all_pods_peer_set = peer_container.get_all_peers_group()
        all_ips_peer_set = IpBlock.get_all_ips_block_peer_set()
        if res_conns_filter.calc_all_allowed:
            # for ingress, all possible connections to IpBlocks are allowed
            ingress_conns.all_allowed_conns |= \
                ConnectivityProperties.make_conn_props_from_dict({"src_peers": all_pods_peer_set,
                                                                  "dst_peers": all_ips_peer_set})
            # for egress, all possible connections from IpBlocks are allowed
            egress_conns.all_allowed_conns |= \
                ConnectivityProperties.make_conn_props_from_dict({"src_peers": all_ips_peer_set,
                                                                  "dst_peers": all_pods_peer_set})
            res_conns.all_allowed_conns = ingress_conns.all_allowed_conns & egress_conns.all_allowed_conns
        res_conns.captured = ingress_conns.captured | egress_conns.captured
        if res_conns_filter.calc_denied:
            res_conns.denied_conns = ingress_conns.denied_conns | egress_conns.denied_conns
        if res_conns_filter.calc_allowed:
            res_conns.allowed_conns = (ingress_conns.allowed_conns & egress_conns.all_allowed_conns) | \
                                      (egress_conns.allowed_conns & ingress_conns.all_allowed_conns)
        return res_conns

    def _allowed_xgress_conns(self, is_ingress, peer_container, res_conns_filter=PolicyConnectionsFilter()):
        """
        Implemented by derived classes to get ingress/egress connections between any relevant peers
        :rtype: PolicyConnections
        """
        return NotImplemented

    def collect_policies_conns_optimized(self, is_ingress, captured_func=lambda policy: True):
        """
        Collect all connections (between all relevant peers), considering all layer's policies that capture the
        relevant peers.
        :param bool is_ingress: indicates whether to return ingress connections or egress connections
        :param captured_func: callable that returns True if the policy satisfies additional conditions required for
         considering captured pods instead of applying the default connections.
        :return: allowed_conns, denied_conns and set of peers to be added to captured peers
        :rtype: PolicyConnections
        """
        res_conns = PolicyConnections()
        for policy in self.policies_list:
            policy_conns = policy.allowed_connections(is_ingress)
            if policy_conns.captured:  # not empty
                if captured_func(policy):
                    res_conns.captured |= policy_conns.captured
                policy_conns.denied_conns -= res_conns.allowed_conns
                policy_conns.denied_conns -= res_conns.pass_conns
                policy_conns.allowed_conns -= res_conns.denied_conns
                policy_conns.allowed_conns -= res_conns.pass_conns
                policy_conns.pass_conns -= res_conns.denied_conns
                policy_conns.pass_conns -= res_conns.allowed_conns
                res_conns.allowed_conns |= policy_conns.allowed_conns
                res_conns.denied_conns |= policy_conns.denied_conns
                res_conns.pass_conns |= policy_conns.pass_conns

        return res_conns


class K8sCalicoNetworkLayer(NetworkLayer):

    def _allowed_xgress_conns(self, is_ingress, peer_container, res_conns_filter=PolicyConnectionsFilter()):
        res_conns = self.collect_policies_conns_optimized(is_ingress)
        # Note: The below computation of non-captured conns cannot be done during the parse stage,
        # since before computing non-captured conns we should collect all policies conns

        # compute non-captured connections
        all_peers_and_ips = peer_container.get_all_peers_group(add_external_ips=True, include_dns_entries=True)
        all_peers_no_ips = peer_container.get_all_peers_group(add_external_ips=False, include_dns_entries=True)
        base_peer_set_no_hep = PeerSet(set([peer for peer in all_peers_no_ips if not isinstance(peer, HostEP)]))
        not_captured_not_hep = base_peer_set_no_hep - res_conns.captured
        if not_captured_not_hep and res_conns_filter.calc_all_allowed:
            # default Allow-all in k8s / calico
            # (assuming only calico's default profiles for pods with connectivity rules exist)
            # assuming host endpoints have no profiles
            conn_cube = ConnectivityCube()
            if is_ingress:
                conn_cube.update({"src_peers": all_peers_and_ips, "dst_peers": not_captured_not_hep})
            else:
                conn_cube.update({"src_peers": not_captured_not_hep, "dst_peers": all_peers_and_ips})
            not_captured_not_hep_conns = ConnectivityProperties.make_conn_props(conn_cube)
            if ExplTracker().is_active():
                src_peers, dst_peers = ExplTracker().extract_peers(not_captured_not_hep_conns)
                ExplTracker().add_default_policy(src_peers,
                                                 dst_peers,
                                                 is_ingress
                                                 )
            res_conns.all_allowed_conns |= not_captured_not_hep_conns

        captured_not_hep = base_peer_set_no_hep & res_conns.captured
        if captured_not_hep and res_conns.pass_conns:
            # assuming only default profiles generated by calico exist, which allow all for pods
            conn_cube = ConnectivityCube()
            if is_ingress:
                conn_cube.update({"src_peers": all_peers_and_ips, "dst_peers": captured_not_hep})
            else:
                conn_cube.update({"src_peers": captured_not_hep, "dst_peers": all_peers_and_ips})
            captured_not_hep_conns = ConnectivityProperties.make_conn_props(conn_cube)
            res_conns.allowed_conns |= res_conns.pass_conns & captured_not_hep_conns
        if res_conns_filter.calc_all_allowed:
            res_conns.all_allowed_conns |= res_conns.allowed_conns

        return res_conns


class IstioNetworkLayer(NetworkLayer):
    @staticmethod
    def captured_cond_func(policy):
        if policy.policy_kind == NetworkPolicy.PolicyType.IstioAuthorizationPolicy:
            return policy.action == IstioNetworkPolicy.ActionType.Allow
        if policy.policy_kind == NetworkPolicy.PolicyType.GatewayPolicy:
            return policy.action == GatewayPolicy.ActionType.Allow
        return True  # only for Istio AuthorizationPolicy the captured condition is more refined with 'Allow' policies

    def _allowed_xgress_conns(self, is_ingress, peer_container, res_conns_filter=PolicyConnectionsFilter()):
        res_conns = self.collect_policies_conns_optimized(is_ingress, IstioNetworkLayer.captured_cond_func)
        if not res_conns_filter.calc_all_allowed:
            return res_conns
        # all the calculations below update res_conns.all_allowed_conns
        all_peers_and_ips = peer_container.get_all_peers_group(add_external_ips=True)
        all_peers_no_ips = peer_container.get_all_peers_group(add_external_ips=False)
        dns_entries = peer_container.get_all_dns_entries()
        # for istio initialize non-captured conns with all possible non-TCP connections
        # This is a compact way to represent all peers connections, but it is an over-approximation also containing
        # IpBlock->IpBlock connections. Those redundant connections will be eventually filtered out.
        all_all_conns = \
            ConnectivityProperties.make_conn_props_from_dict({"src_peers": all_peers_and_ips,
                                                              "dst_peers": all_peers_and_ips,
                                                              "protocols": ProtocolSet.get_non_tcp_protocols()})
        res_conns.all_allowed_conns |= res_conns.allowed_conns | all_all_conns
        non_captured_peers = all_peers_no_ips - res_conns.captured
        if non_captured_peers:
            tcp_protocol = ProtocolSet.get_protocol_set_with_single_protocol('TCP')
            if is_ingress:
                all_nc_conns = ConnectivityProperties.make_conn_props_from_dict({"src_peers": all_peers_and_ips,
                                                                                 "dst_peers": non_captured_peers})
                non_captured_dns_entries = dns_entries - res_conns.captured
                non_captured_conns = all_nc_conns - res_conns.denied_conns
                if non_captured_dns_entries:
                    # update allowed non-captured conns to DNSEntry dst with TCP only
                    all_nc_dns_conns = \
                        ConnectivityProperties.make_conn_props_from_dict({"src_peers": all_peers_and_ips,
                                                                          "dst_peers": non_captured_dns_entries,
                                                                          "protocols": tcp_protocol})
                    non_captured_conns |= (all_nc_dns_conns - res_conns.denied_conns)
            else:
                nc_all_conns = ConnectivityProperties.make_conn_props_from_dict({"src_peers": non_captured_peers,
                                                                                 "dst_peers": all_peers_and_ips})
                # update allowed non-captured conns to DNSEntry dst with TCP only
                nc_dns_conns = ConnectivityProperties.make_conn_props_from_dict({"src_peers": non_captured_peers,
                                                                                 "dst_peers": dns_entries,
                                                                                 "protocols": tcp_protocol})
                non_captured_conns = (nc_all_conns | nc_dns_conns) - res_conns.denied_conns
            res_conns.all_allowed_conns |= non_captured_conns
            if ExplTracker().is_active():
                src_peers, dst_peers = ExplTracker().extract_peers(non_captured_conns)
                ExplTracker().add_default_policy(src_peers,
                                                 dst_peers,
                                                 is_ingress
                                                 )
        return res_conns


class K8sGatewayLayer(K8sCalicoNetworkLayer):
    pass


class IstioGatewayLayer(IstioNetworkLayer):
    pass
