#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import Peer
from ConnectionSet import ConnectionSet
from PortSet import PortSet, PortSetPair
from GenericYamlParser import GenericYamlParser
from K8sNetworkPolicy import K8sNetworkPolicy, K8sPolicyRule
from PeerContainer import PeerContainer


class K8sPolicyYamlParser(GenericYamlParser):
    """
    A parser for k8s NetworkPolicy objects
    """
    def __init__(self, policy, peer_container, policy_file_name=''):
        """
        :param dict policy: The policy object as provided by the yaml parser
        :param PeerContainer peer_container: The policy will be evaluated against this set of peers
        :param str policy_file_name: The name of the file in which the policy resides
        """
        GenericYamlParser.__init__(self, policy_file_name)
        self.policy = policy
        self.peer_container = peer_container
        self.namespace = peer_container.get_namespace('default')  # value to be replaced if the netpol has ns defined
        self.allowed_labels = set()

    def parse_label_selector_requirement(self, requirement, namespace_selector):
        """
        Parse a LabelSelectorRequirement element
        :param dict requirement: The element to parse
        :param bool namespace_selector: Whether or not this is in the context of namespaceSelector
        :return: A PeerSet containing the peers that satisfy the requirement
        :rtype: Peer.PeerSet
        """
        self.check_keys_are_legal(requirement, 'requirement', {'key': 1, 'operator': 1, 'values': 0})
        key = requirement['key']
        operator = requirement['operator']

        if operator in ['In', 'NotIn']:
            values = requirement.get('values')
            if not values:
                self.syntax_error('A requirement with In/NotIn operator but without values', requirement)
            if namespace_selector:
                return self.peer_container.get_namespace_pods_with_label(key, values, operator == 'NotIn')
            return self.peer_container.get_peers_with_label(key, values, operator == 'NotIn')

        if operator in ['Exists', 'DoesNotExist']:
            if 'values' in requirement and requirement['values']:
                self.syntax_error('A requirement with Exist/DoesNotExist operator must not have values', requirement)
            if namespace_selector:
                return self.peer_container.get_namespace_pods_with_key(key, operator == 'DoesNotExist')
            return self.peer_container.get_peers_with_key(self.namespace, key, operator == 'DoesNotExist')

        self.syntax_error('A requirement with invalid operator', requirement)
        return None

    def parse_label_selector(self, label_selector, namespace_selector=False):
        """
        Parse a LabelSelector element (can also come from a NamespaceSelector)
        :param dict label_selector: The element to parse
        :param bool namespace_selector: Whether or not this is a namespaceSelector
        :return: A PeerSet containing all the pods captured by this selection
        :rtype: Peer.PeerSet
        """
        if label_selector is None:
            return Peer.PeerSet()  # A None value means the selector selects nothing
        if not label_selector:
            return self.peer_container.get_all_peers_group()  # An empty value means the selector selects everything

        allowed_elements = {'matchLabels': 0, 'match_labels': 0, 'matchExpressions': 0, 'match_expressions': 0}
        self.check_keys_are_legal(label_selector, 'pod/namespace selector', allowed_elements)

        res = self.peer_container.get_all_peers_group()
        match_labels = label_selector.get('matchLabels', label_selector.get('match_labels'))
        if match_labels:
            keys_set = set()
            for key, val in match_labels.items():
                if namespace_selector:
                    res &= self.peer_container.get_namespace_pods_with_label(key, [val])
                else:
                    res &= self.peer_container.get_peers_with_label(key, [val])
                keys_set.add(key)
            if len(keys_set) == 1:
                self.allowed_labels.add(list(keys_set)[0])
            else:
                self.allowed_labels.add('_AND_' + ':'.join(k for k in keys_set))



        match_expressions = label_selector.get('matchExpressions', label_selector.get('match_expressions'))
        if match_expressions:
            keys_set = set()
            for requirement in match_expressions:
                res &= self.parse_label_selector_requirement(requirement, namespace_selector)
                key = requirement['key']
                keys_set.add(key)
            if len(keys_set) == 1:
                self.allowed_labels.add(list(keys_set)[0])
            else:
                self.allowed_labels.add('_AND_' + ':'.join(k for k in keys_set))

        if not res:
            if namespace_selector:
                self.warning('A namespaceSelector selects no pods. Better use "namespaceSelector: Null"',
                             label_selector)
            else:
                self.warning('A podSelector selects no pods. Better use "podSelector: Null"', label_selector)
        elif namespace_selector and res == self.peer_container.get_all_peers_group():
            self.warning('A non-empty namespaceSelector selects all pods. Better use "namespaceSelector: {}"',
                         label_selector)

        return res

    def parse_ip_block(self, block):
        """
        Parse an ipBlock element
        :param dict block: The element to parse
        :return: A PeerSet containing the relevant IP ranges
        :rtype: Peer.PeerSet
        """
        self.check_keys_are_legal(block, 'ipBlock', {'cidr': 1, 'except': 0})
        res = Peer.PeerSet()
        res.add(Peer.IpBlock(block['cidr'], block.get('except')))
        return res

    def parse_peer(self, peer):
        """
        Parse a NetworkPolicyPeer inside a rule (an element of the 'to'/'from' array)
        :param dict peer: The object to parse
        :return: A PeerSet object containing the set of peers defined by the selectors/ipblocks
        :rtype: Peer.PeerSet
        """
        allowed_elements = {'podSelector': 0, 'pod_selector': 0, 'namespaceSelector': 0, 'namespace_selector': 0,
                            'ipBlock': 0, 'ip_block': 0}
        self.check_keys_are_legal(peer, 'network policy peer', allowed_elements)

        pod_selector = peer.get('podSelector', peer.get('pod_selector'))
        ns_selector = peer.get('namespaceSelector', peer.get('namespace_selector'))
        ip_block = peer.get('ipBlock', peer.get('ip_block'))

        if pod_selector is None and ns_selector is None and ip_block is None:
            self.syntax_error('A NetworkPolicyPeer must have at least one field', peer)

        if ip_block is not None:
            if pod_selector is not None or ns_selector is not None:
                self.syntax_error('ipBlock cannot be specified in combination with podSelector or namespaceSelector')
            return self.parse_ip_block(ip_block)

        if ns_selector is not None:
            res = self.parse_label_selector(ns_selector, True)
        else:
            res = self.peer_container.get_namespace_pods(self.namespace)

        if pod_selector is not None:
            selected_pods = self.parse_label_selector(pod_selector) & res
            if pod_selector and selected_pods == res:
                self.warning('A podSelector selects all pods in the current context; it should better be removed.',
                             pod_selector)
            res = selected_pods
        return res

    def parse_port(self, port):
        """
        Parse an element of the "ports" phrase of a policy rule
        :param dict port: The element to parse
        :return: A ConnectionSet representing the allowed connections by this element (protocols X port numbers)
        :rtype: ConnectionSet
        """
        self.check_keys_are_legal(port, 'port', {'port': 0, 'endPort': 0, 'protocol': 0})
        port_id = port.get('port')
        protocol = port.get('protocol')
        endport_id = port.get('endPort')
        if not protocol:
            protocol = 'TCP'
        if protocol not in ['TCP', 'UDP', 'SCTP']:
            self.syntax_error('protocol must be "TCP" or "UDP" or "SCTP"', port)

        res = ConnectionSet()
        dest_port_set = PortSet(port_id is None)
        if port_id and endport_id:
            if isinstance(port_id, str):
                self.syntax_error('endPort cannot be specified when port is a string (named port)', port)
            if port_id > endport_id:
                self.syntax_error('endPort must be equal or larger than port', port)
            dest_port_set.add_port_range(port_id, endport_id)
        elif port_id:
            dest_port_set.add_port(port_id)
        elif endport_id:
            self.syntax_error('endPort cannot be specified without Port being specified', port)

        res.add_connections(protocol, PortSetPair(PortSet(True), dest_port_set))  # K8s doesn't reason about src ports

        return res

    def parse_ingress_egress_rule(self, rule, peer_array_key):
        """
        Parse a single ingres/egress rule, producing a K8sPolicyRule
        :param dict rule: The rule to parse
        :param str peer_array_key: The key which defined the peer set ('from' for ingress, 'to' for egress)
        :return: A K8sPolicyRule with the proper PeerSet and ConnectionSet
        :rtype: K8sPolicyRule
        """
        self.check_keys_are_legal(rule, 'ingress/egress rule', {peer_array_key: 0, '_' + peer_array_key: 0, 'ports': 0})
        peer_array = rule.get(peer_array_key, rule.get('_' + peer_array_key))
        if peer_array:
            res_pods = Peer.PeerSet()
            for peer in peer_array:
                res_pods |= self.parse_peer(peer)
        else:
            res_pods = self.peer_container.get_all_peers_group(True)

        ports_array = rule.get('ports', None)
        if ports_array:
            res_ports = ConnectionSet()
            for port in rule.get('ports', []):
                res_ports |= self.parse_port(port)
        else:
            res_ports = ConnectionSet(True)

        if not res_pods:
            self.warning('Rule selects no pods', rule)

        return K8sPolicyRule(res_pods, res_ports)

    def verify_named_ports(self, rule, rule_pods, rule_conns):
        """
        Check the validity of named ports in a given rule: whether a relevant pod refers to the named port and whether
        the protocol defined in the policy matches the protocol defined by the Pod. Issue warnings as required.
        :param dict rule: The unparsed rule (for reference in warnings)
        :param Peer.PeerSet rule_pods: The set of Pods in which the named ports should be defined
        :param ConnectionSet rule_conns: The rule-specified connections, possibly containing named ports
        :return: None
        """
        if not rule_conns.has_named_ports():
            return
        named_ports = rule_conns.get_named_ports()
        for protocol, rule_ports in named_ports:
            for port in rule_ports:
                port_used = False
                for pod in rule_pods:
                    pod_named_port = pod.named_ports.get(port)
                    if pod_named_port:
                        port_used = True
                        if ConnectionSet.protocol_name_to_number(pod_named_port[1]) != protocol:
                            self.warning(f'Protocol mismatch for named port {port} (vs. Pod {pod.full_name()})',
                                         rule['ports'])

                if not port_used:
                    self.warning(f'Named port {port} is not defined in any selected pod', rule['ports'])

    def parse_ingress_rule(self, rule, policy_selected_pods):
        """
        Parse a single ingress rule, producing a K8sPolicyRule.
        Also, checking validity of named ports w.r.t. the policy's captured pods
        :param dict rule: The dict with the rule fields
        :param Peer.PeerSet policy_selected_pods: The set of pods the policy applies to
        :return: A K8sPolicyRule with the proper PeerSet and ConnectionSet
        :rtype: K8sPolicyRule
        """
        res = self.parse_ingress_egress_rule(rule, 'from')
        self.verify_named_ports(rule, policy_selected_pods, res.port_set)
        return res

    def parse_egress_rule(self, rule):
        """
        Parse a single egress rule, producing a K8sPolicyRule.
        Also, checking validity of named ports w.r.t. the rule's peer set
        :param dict rule: The dict with the rule fields
        :return: A K8sPolicyRule with the proper PeerSet and ConnectionSet
        :rtype: K8sPolicyRule
        """
        res = self.parse_ingress_egress_rule(rule, 'to')
        self.verify_named_ports(rule, res.peer_set, res.port_set)
        return res

    def parse_policy(self):
        """
        Parses the input object to create a K8sNetworkPolicy object
        :return: a K8sNetworkPolicy object with proper PeerSets and ConnectionSets
        :rtype: K8sNetworkPolicy
        """
        if not isinstance(self.policy, dict):
            self.syntax_error('Top ds is not a map')
        if self.policy.get('kind') != 'NetworkPolicy':
            return None  # Not a NetworkPolicy object
        api_version = self.policy.get('apiVersion', self.policy.get('api_version', ''))
        if not api_version:
            self.syntax_error('An object with no specified apiVersion', self.policy)
        if 'k8s' not in api_version and api_version != 'extensions/v1beta1':
            return None  # apiVersion is not properly set
        if api_version not in ['networking.k8s.io/v1', 'extensions/v1beta1']:
            raise Exception('Unsupported apiVersion: ' + api_version)
        self.check_keys_are_legal(self.policy, 'networkPolicy', {'kind': 1, 'metadata': 1, 'spec': 1,
                                                                 'apiVersion': 0, 'api_version': 0})
        if 'name' not in self.policy['metadata']:
            self.syntax_error('NetworkPolicy has no name', self.policy)
        if 'namespace' in self.policy['metadata']:
            self.namespace = self.peer_container.get_namespace(self.policy['metadata']['namespace'])
        res_policy = K8sNetworkPolicy(self.policy['metadata']['name'], self.namespace)

        policy_spec = self.policy['spec']
        allowed_spec_keys = {'podSelector': 0, 'pod_selector': 0, 'ingress': 0, 'egress': 0,
                             'policyTypes': 0, 'policy_types': 0}
        self.check_keys_are_legal(policy_spec, 'network policy spec', allowed_spec_keys)

        policy_types = policy_spec.get('policyTypes', policy_spec.get('policy_types', []))
        if not policy_types:
            self.warning('policyTypes is missing/empty in the spec of ' + res_policy.full_name(), policy_spec)
        else:
            allowed_types = {'Egress', 'Ingress'}
            bad_types = set(policy_types).difference(allowed_types)
            if bad_types:
                self.syntax_error('Bad type in policyTypes (policy ' + res_policy.full_name() + '): ' + bad_types.pop(),
                                  policy_types)
        res_policy.affects_ingress = not policy_types or 'Ingress' in policy_types
        if not res_policy.affects_ingress and policy_spec.get('ingress') is not None:
            self.syntax_error('A NetworkPolicy with ingress field but no "Ingress" in its policyTypes', policy_spec)
        res_policy.affects_egress = (policy_types and 'Egress' in policy_types) or \
                                    (not policy_types and 'egress' in policy_spec)
        if not res_policy.affects_egress and policy_spec.get('egress') is not None:
            self.syntax_error('A NetworkPolicy with egress field but no "Egress" in its policyTypes', policy_spec)

        pod_selector = policy_spec.get('podSelector', policy_spec.get('pod_selector'))
        if pod_selector is None:
            self.syntax_error('A NetworkPolicy with no podSelector specified in its spec', policy_spec)
        res_policy.selected_peers = self.parse_label_selector(pod_selector)
        res_policy.selected_peers &= self.peer_container.get_namespace_pods(self.namespace)

        for ingress_rule in policy_spec.get('ingress', []):
            res_policy.add_ingress_rule(self.parse_ingress_rule(ingress_rule, res_policy.selected_peers))

        for egress_rule in policy_spec.get('egress', []):
            res_policy.add_egress_rule(self.parse_egress_rule(egress_rule))

        res_policy.findings = self.warning_msgs
        return res_policy
