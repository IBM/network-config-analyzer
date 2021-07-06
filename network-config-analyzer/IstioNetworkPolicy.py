from enum import Enum

from NetworkPolicy import PolicyConnections, NetworkPolicy
from ConnectionSet import ConnectionSet
from Peer import PeerSet, Pod, IpBlock


class IstioPolicyRule:
    """
    A class representing a single ingress rule in a Istio AuthorizationPolicy object
    """

    def __init__(self, peer_set, port_set):
        """
        :param Peer.PeerSet peer_set: The set of peers this rule allows connection from
        :param ConnectionSet port_set: The set of connections allowed by this rule
        """
        # TODO: extend connection set (port_set) to represent HTTP/grpc requests attributes
        self.peer_set = peer_set
        self.port_set = port_set

    def __eq__(self, other):
        return self.peer_set == other.peer_set and self.port_set == other.port_set

    def contained_in(self, other):
        """
        :param IstioPolicyRule other: Another rule
        :return: whether the self rule is contained in the other rule (self doesn't allow anything that other does not)
        :type: bool
        """
        return self.peer_set.issubset(other.peer_set) and self.port_set.contained_in(other.port_set)


class IstioNetworkPolicy(NetworkPolicy):
    """
    This class implements istio-specific logic for AuthorizationPolicies
    A class to hold processed information about a single Istio network Authorization Policy
    """

    class ActionType(Enum):
        """
        Allowed actions for Istio's network authorization policy
        """
        # currently skipping CUSTOM and AUDIT
        # https://istio.io/latest/docs/reference/config/security/authorization-policy/#AuthorizationPolicy-Action
        Deny = 0
        Allow = 1

    def __init__(self, name, namespace):
        super().__init__(name, namespace)
        # default action type is Allow
        self.action = IstioNetworkPolicy.ActionType.Allow

    def __eq__(self, other):
        return super().__eq__(other) and self.action == other.action

    # 'deny' policies should be evaluated before 'allow' policies
    def __lt__(self, other):  # required so we can evaluate the policies according to their order
        if isinstance(other, IstioNetworkPolicy):
            return self.action == IstioNetworkPolicy.ActionType.Deny
        return NotImplemented

    # TODO: should only handle ingress rules?
    def allowed_connections(self, from_peer, to_peer, is_ingress):
        """
        Evaluate the set of connections this policy allows/denies/passes between two peers
        :param Peer.Peer from_peer: The source peer
        :param Peer.Peer to_peer:  The target peer
        :param bool is_ingress: whether we evaluate ingress rules only or egress rules only
        :return: A PolicyConnections object containing sets of allowed/denied/pass connections
        :rtype: PolicyConnections
        """

        # TODO: currently not handling egress, istio authorization policies have no egress rules
        if not is_ingress:
            return NotImplemented

        captured = to_peer in self.selected_peers
        if not captured:
            return PolicyConnections(False)

        allowed_conns = ConnectionSet()
        denied_conns = ConnectionSet()

        rules = self.ingress_rules
        collected_conns = allowed_conns if self.action == IstioNetworkPolicy.ActionType.Allow else denied_conns
        for rule in rules:
            if from_peer in rule.peer_set:
                rule_conns = rule.port_set   #.copy()  # we need a copy because convert_named_ports is destructive
                collected_conns |= rule_conns

        return PolicyConnections(True, allowed_conns, denied_conns)

    def referenced_ip_blocks(self):
        """
        :return: A set of all ipblocks referenced in one of the policy rules (one Peer object per one ip range)
        :rtype: Peer.PeerSet
        """
        res = PeerSet()
        for rule in self.ingress_rules:
            for pod in rule.peer_set:
                if isinstance(pod, IpBlock):
                    res |= pod.split()
        return res
