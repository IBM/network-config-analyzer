#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from enum import Enum
from nca.CoreDS.ConnectivityProperties import ConnectivityProperties
from nca.CoreDS.Peer import PeerSet
from nca.Resources.PolicyResources.NetworkPolicy import PolicyConnections, NetworkPolicy


class GatewayPolicyRule:
    """
    A class representing a single rule in a GatewayPolicy object
    """
    def __init__(self, peer_set, props):
        """
        :param Peer.PeerSet peer_set: The set of peers this rule allows connection to
        :param ConnectivityProperties props: the connections
        """
        self.peer_set = peer_set
        self.props = props
        # copy of props (used by src_peers/dst_peers domain-updating mechanism)
        self.props_copy = ConnectivityProperties()

    def __eq__(self, other):
        return self.props == other.props

    def contained_in(self, other):
        """
        :param GatewayPolicyRule other: Another rule
        :return: whether the self rule is contained in the other rule (self doesn't allow anything that other does not)
        :type: bool
        """
        return self.props.contained_in(other.props)


class GatewayPolicy(NetworkPolicy):
    """
    This class implements gateway connectivity logic for incoming/outgoing http requests (to/from the cluster)
    The logic is kept similarly to NetworkPolicy.
    This class is used to represent "policies" from `k8s Ingress`, `istio IngressGateway` and `istio EgresGateway`
    resources.

    For representation of policies from `k8s Ingress`, `istio IngressGateway`, the generated GatewayPolicies
    will be of 'Allow' type - representing the connections configured from the gateway to the cluster's workloads.

    For representation of policies from 'istio EgressGateway', there will be GatewayPolicies
    of both 'Allow' and 'Deny' types:
    The 'Allow' policy types represent the connections configured from the mesh to the gateway + from the gateway
    to external destinations.
    The 'Deny' policy type will be generated to represent denied connections
    from mesh to those DNS entries whose egress traffic is sent via egress gateways, as defined in virtual services.
    """

    class ActionType(Enum):
        """
        Allowed actions for GatewayPolicy policies
        """
        Deny = 0
        Allow = 1

    def __init__(self, name, namespace, action, file_name="", line_number=0, origin=""):
        """
        :param str name: gateway poilcy name
        :param K8sNamespace namespace: the namespace containing this policy
        :param ActionType action: whether Allow or Deny
        """
        super().__init__(name, namespace)
        self.action = action
        self.vs_file_name = file_name
        self.line_number = line_number
        self.origin = origin or name  # originating virtual service/route/destination/gateway for this policy

    def __eq__(self, other):
        return super().__eq__(other) and self.action == other.action

    def add_ingress_rules(self, rules):
        """
        Adding a given list of rules to the list of ingress rules
        :param list rules: The list of rules to add
        :return: None
        """
        self.ingress_rules.extend(rules)

    def add_egress_rules(self, rules):
        """
        Adding a given list of rules to the list of egress rules
        :param list rules: The list of rules to add
        :return: None
        """
        self.egress_rules.extend(rules)

    def sync_props(self):
        """
        If props of the policy are not synchronized (self.props_in_sync is False),
        compute props of the policy according to the props of its rules
        """
        if self.props_in_sync:
            return
        self._init_props()
        for rule in self.ingress_rules:
            if self.action == GatewayPolicy.ActionType.Allow:
                self._allow_ingress_props |= rule.props
            elif self.action == GatewayPolicy.ActionType.Deny:
                self._deny_ingress_props |= rule.props
        for rule in self.egress_rules:
            if self.action == GatewayPolicy.ActionType.Allow:
                self._allow_egress_props |= rule.props
            elif self.action == GatewayPolicy.ActionType.Deny:
                self._deny_egress_props |= rule.props
        self.props_in_sync = True

    def allowed_connections(self, is_ingress):
        """
        Evaluate the set of connections this ingress resource allows between any two peers
        :param bool is_ingress: whether we evaluate ingress rules only or egress rules only.
        :return: A OptimizedPolicyConnections object containing all allowed/denied connections for any peers
            and the peer set of captured peers by this policy.
        :rtype: PolicyConnections
        """
        res_conns = PolicyConnections()
        if is_ingress:
            res_conns.allowed_conns = self.allow_ingress_props().copy()
            res_conns.denied_conns = self.deny_ingress_props().copy()
            res_conns.captured = self.selected_peers if self.affects_ingress else PeerSet()
        else:
            res_conns.allowed_conns = self.allow_egress_props().copy()
            res_conns.denied_conns = self.deny_egress_props().copy()
            res_conns.captured = self.selected_peers if self.affects_egress else PeerSet()
        return res_conns

    def has_empty_rules(self, _config_name=''):
        """
        Checks whether the policy contains empty rules (rules that do not select any peers)
        :param str _config_name: is not used. Kept for compatibility with other policies.
        :return: A list of strings describing the emptiness + two sets of indexes of empty ingress/egress rules
        :rtype: list[str], set, set
        """
        emptiness_explanation = []
        empty_ingress_rules = set()
        empty_egress_rules = set()
        full_name = self.full_name(_config_name)
        for rule_index, ingress_rule in enumerate(self.ingress_rules, start=1):
            if not ingress_rule.peer_set:
                emptiness = f'The generated policy {full_name} has an ingress rule that does not select any pods'
                emptiness_explanation.append(emptiness)
                empty_ingress_rules.add(rule_index)

        for rule_index, egress_rule in enumerate(self.egress_rules, start=1):
            if not egress_rule.peer_set:
                emptiness = f'The generated policy {full_name} has an egress rule that does not select any pods'
                emptiness_explanation.append(emptiness)
                empty_egress_rules.add(rule_index)

        return emptiness_explanation, empty_ingress_rules, empty_egress_rules

    def clone_without_rule(self, rule_to_exclude, ingress_rule):
        """
        Makes a copy of 'self' without a given policy rule
        :param GatewayPolicyRule rule_to_exclude: The one rule not to include in the copy
        :param bool ingress_rule: Whether the rule is an ingress or egress rule
        :return: A copy of 'self' without the provided rule
        :rtype: GatewayPolicy
        """
        res = GatewayPolicy(self.name, self.namespace, self.action, self.vs_file_name, self.line_number, self.origin)
        res.selected_peers = self.selected_peers
        res.affects_egress = self.affects_egress
        res.affects_ingress = self.affects_ingress
        res.policy_kind = self.policy_kind
        for rule in self.egress_rules:
            if ingress_rule or rule != rule_to_exclude:
                res.add_egress_rule(rule)
        for rule in self.ingress_rules:
            if not ingress_rule or rule != rule_to_exclude:
                res.add_ingress_rule(rule)
        return res

    def has_allow_rules(self):
        """
        :return: Whether the policy has rules that allow connections.
        :rtype: bool
        """
        if self.action == self.ActionType.Deny:
            return False

        for ingress_rule in self.ingress_rules:
            if ingress_rule.peer_set:
                return True

        for egress_rule in self.egress_rules:
            if egress_rule.peer_set:
                return True
        return False

    def has_deny_rules(self):
        """
        :return: Whether the policy has rules that allow connections.
        :rtype: bool
        """
        if self.action == self.ActionType.Allow:
            return False

        for ingress_rule in self.ingress_rules:
            if ingress_rule.peer_set:
                return True

        for egress_rule in self.egress_rules:
            if egress_rule.peer_set:
                return True
        return False
