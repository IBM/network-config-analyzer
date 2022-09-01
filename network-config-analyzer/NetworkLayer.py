from bisect import insort
from enum import Enum

from ConnectionSet import ConnectionSet
from IstioNetworkPolicy import IstioNetworkPolicy
from NetworkPolicy import PolicyConnections, NetworkPolicy
from Peer import IpBlock, HostEP


# TODO: add a layer for connectivity based on service type (culsterIP / LB / NodePort)? / containers ports?


class NetworkLayerName(Enum):
    K8s_Calico = 0
    Istio = 1
    Ingress = 2

    def create_network_layer(self, policies):
        if self == NetworkLayerName.K8s_Calico:
            return K8sCalicoNetworkLayer(policies)
        if self == NetworkLayerName.Istio:
            return IstioNetworkLayer(policies)
        if self == NetworkLayerName.Ingress:
            return IngressNetworkLayer(policies)
        return None

    @staticmethod
    def policy_type_to_layer(policy_type):
        if policy_type in {NetworkPolicy.PolicyType.K8sNetworkPolicy, NetworkPolicy.PolicyType.CalicoNetworkPolicy,
                           NetworkPolicy.PolicyType.CalicoGlobalNetworkPolicy, NetworkPolicy.PolicyType.CalicoProfile}:
            return NetworkLayerName.K8s_Calico
        elif policy_type in {NetworkPolicy.PolicyType.IstioAuthorizationPolicy, NetworkPolicy.PolicyType.IstioSidecar}:
            return NetworkLayerName.Istio
        elif policy_type == NetworkPolicy.PolicyType.Ingress:
            return NetworkLayerName.Ingress
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

    def does_contain_single_layer(self, layer_name):
        """
        Checks if the given layer is the only layer in the map.
        :param NetworkLayerName layer_name: the layer to check
        :return: True if the layer is the only layer in the map, False otherwise
        """
        return len(self) == 1 and list(self.keys())[0] == layer_name

    @staticmethod
    def empty_layer_allowed_connections(layer_name, from_peer, to_peer):
        """
        Get allowed connections between two peers for an empty layer (no policies).
        :param NetworkLayerName layer_name: The empty layer name
        :param Peer.Peer from_peer: the source peer
        :param Peer.Peer to_peer: the target peer
        :rtype: ConnectionSet, bool, ConnectionSet, ConnectionSet
        """
        empty_layer_obj = layer_name.create_network_layer([])
        return empty_layer_obj.allowed_connections(from_peer, to_peer)


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

    def allowed_connections(self, from_peer, to_peer):
        """
        Compute per network layer the allowed connections between from_peer and to_peer, considering
        all layer's policies (and defaults)
        :param Peer.Peer from_peer: The source peer
        :param Peer.Peer to_peer: The target peer
        :return: a 4-tuple with:
          - allowed_conns: all allowed connections (captured/non-captured)
          - captured_flag: flag to indicate if any of the policies captured one of the peers (src/dst)
          - allowed_captured_conns: allowed captured connections (can be used only if the captured flag is True)
          - denied_conns: connections denied by the policies (captured)
        :rtype: ConnectionSet, bool, ConnectionSet, ConnectionSet
        """
        if isinstance(to_peer, IpBlock):
            ingress_conns = PolicyConnections(captured=False, all_allowed_conns=ConnectionSet(True))
        else:
            ingress_conns = self._allowed_xgress_conns(from_peer, to_peer, True)

        if isinstance(from_peer, IpBlock):
            egress_conns = PolicyConnections(captured=False, all_allowed_conns=ConnectionSet(True))
        else:
            egress_conns = self._allowed_xgress_conns(from_peer, to_peer, False)

        captured_flag = ingress_conns.captured or egress_conns.captured
        denied_conns = ingress_conns.denied_conns | egress_conns.denied_conns
        allowed_conns = ingress_conns.all_allowed_conns & egress_conns.all_allowed_conns
        # captured connections are where at least one of ingress / egress is captured
        allowed_captured_conns = (ingress_conns.allowed_conns & egress_conns.all_allowed_conns) | \
                                 (egress_conns.allowed_conns & ingress_conns.all_allowed_conns)

        return allowed_conns, captured_flag, allowed_captured_conns, denied_conns

    def _allowed_xgress_conns(self, from_peer, to_peer, is_ingress):
        """
        Implemented by derived classes to get allowed and denied ingress/egress connections between from_peer and to_pee
        """
        return NotImplemented

    def collect_policies_conns(self, from_peer, to_peer, is_ingress,
                               captured_func=lambda policy: True):
        """
        Collect allowed/denied/pass connections between two peers, considering all layer's policies that capture the
        relevant peers.
        :param Peer.Peer from_peer:  the source peer
        :param Peer.Peer to_peer: the dest peer
        :param bool is_ingress: indicates whether to return ingress connections or egress connections
        :param captured_func: callable that returns True if the policy satisfies additional conditions required for
        considering the target pod as captured and not applying the default connections to it.
        :return: (allowed_conns, denied_conns, pass_conns, captured_res)
        :rtype: (ConnectionSet, ConnectionSet, ConnectionSet, bool)
        """
        allowed_conns = ConnectionSet()
        denied_conns = ConnectionSet()
        pass_conns = ConnectionSet()
        captured_res = False
        for policy in self.policies_list:
            policy_conns = policy.allowed_connections(from_peer, to_peer, is_ingress)
            if policy_conns.captured:
                captured_res |= captured_func(policy)
                policy_conns.denied_conns -= allowed_conns
                policy_conns.denied_conns -= pass_conns
                policy_conns.allowed_conns -= denied_conns
                policy_conns.allowed_conns -= pass_conns
                policy_conns.pass_conns -= denied_conns
                policy_conns.pass_conns -= allowed_conns
                denied_conns |= policy_conns.denied_conns
                allowed_conns |= policy_conns.allowed_conns
                pass_conns |= policy_conns.pass_conns
        return allowed_conns, denied_conns, pass_conns, captured_res


class K8sCalicoNetworkLayer(NetworkLayer):

    def _allowed_xgress_conns(self, from_peer, to_peer, is_ingress):
        allowed_conns, denied_conns, pass_conns, captured_res = self.collect_policies_conns(from_peer, to_peer,
                                                                                            is_ingress)

        allowed_non_captured_conns = ConnectionSet()
        captured_peer_is_host_endpoint = (is_ingress and isinstance(to_peer, HostEP)) or \
                                         (not is_ingress and isinstance(from_peer, HostEP))
        if not captured_res and not captured_peer_is_host_endpoint:
            # default Allow-all in k8s / calico
            # (assuming only calico's default profiles for pods with connectivity rules exist)
            # assuming host endpoints have no profiles
            allowed_non_captured_conns = ConnectionSet(True)
        elif pass_conns and not captured_peer_is_host_endpoint:
            # assuming only default profiles generated by calico exist, which allow all for pods
            allowed_conns |= pass_conns
        return PolicyConnections(captured_res, allowed_conns, denied_conns,
                                 all_allowed_conns=allowed_conns | allowed_non_captured_conns)


class IstioNetworkLayer(NetworkLayer):

    def _allowed_xgress_conns(self, from_peer, to_peer, is_ingress):
        # in istio applying default-allow if there is no capturing policy with action allow
        def captured_cond_func(policy):
            if isinstance(policy, IstioNetworkPolicy):
                return policy.action == IstioNetworkPolicy.ActionType.Allow
            return True  # sidecar always defines allowed connections

        allowed_conns, denied_conns, _, captured_res = self.collect_policies_conns(from_peer, to_peer, is_ingress,
                                                                                   captured_cond_func)
        # for istio initialize non-captured conns with non-TCP connections
        allowed_non_captured_conns = ConnectionSet.get_non_tcp_connections()
        if not captured_res:  # no allow policies for target
            # add connections allowed by default that are not captured
            allowed_non_captured_conns |= (ConnectionSet(True) - denied_conns)
        return PolicyConnections(captured_res, allowed_conns, denied_conns,
                                 all_allowed_conns=allowed_conns | allowed_non_captured_conns)


class IngressNetworkLayer(NetworkLayer):

    def _allowed_xgress_conns(self, from_peer, to_peer, is_ingress):
        allowed_conns = ConnectionSet()
        all_allowed_conns = ConnectionSet(True)
        captured_res = False
        if not is_ingress:
            allowed_conns, _, _, captured_res = self.collect_policies_conns(from_peer, to_peer, is_ingress)
            if captured_res:
                all_allowed_conns = allowed_conns
        return PolicyConnections(captured=captured_res, allowed_conns=allowed_conns, denied_conns=ConnectionSet(),
                                 all_allowed_conns=all_allowed_conns)
