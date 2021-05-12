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

    def parse_label_selector_requirement(self, requirement, namespace_selector):
        """
        Parse a LabelSelectorRequirement element
        :param dict requirement: The element to parse
        :param bool namespace_selector: Whether or not this is in the context of namespaceSelector
        :return: A PeerSet containing the peers that satisfy the requirement
        :rtype: Peer.PeerSet
        """
        self.check_keys_are_legal(requirement, 'LabelSelectorRequirement', {'key': 1, 'operator': 1, 'values': 0},
                                  {'operator': ['In', 'NotIn', 'Exists', 'DoesNotExist']})
        key = requirement['key']
        if not isinstance(key, str):
            self.syntax_error('type of key field is not a string in LabelSelectorRequirement', requirement)
        operator = requirement['operator']

        if operator in ['In', 'NotIn']:
            values = requirement.get('values')
            if not values:
                self.syntax_error('A requirement with In/NotIn operator but without values', requirement)
            if not isinstance(values, list):
                self.syntax_error('type of values field is not an array in LabelSelectorRequirement', requirement)
            if namespace_selector:
                return self.peer_container.get_namespace_pods_with_label(key, values, operator == 'NotIn')
            return self.peer_container.get_peers_with_label(key, values, operator == 'NotIn')

        if operator in ['Exists', 'DoesNotExist']:
            if 'values' in requirement and requirement['values']:
                self.syntax_error('A requirement with Exist/DoesNotExist operator must not have values', requirement)
            if namespace_selector:
                return self.peer_container.get_namespace_pods_with_key(key, operator == 'DoesNotExist')
            return self.peer_container.get_peers_with_key(self.namespace, key, operator == 'DoesNotExist')

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
        if not label_selector:  # empty
            return self.peer_container.get_all_peers_group()  # An empty value means the selector selects everything
        allowed_elements = {'matchLabels': 0, 'match_labels': 0, 'matchExpressions': 0, 'match_expressions': 0}
        self.check_keys_are_legal(label_selector, 'pod/namespace selector', allowed_elements)

        res = self.peer_container.get_all_peers_group()
        match_labels = label_selector.get('matchLabels', label_selector.get('match_labels'))
        if match_labels:
            if not isinstance(match_labels, dict):
                self.syntax_error('type of matchLabels is not a map in LabelSelector', label_selector)
            for key, val in match_labels.items():
                if namespace_selector:
                    res &= self.peer_container.get_namespace_pods_with_label(key, [val])
                else:
                    res &= self.peer_container.get_peers_with_label(key, [val])

        match_expressions = label_selector.get('matchExpressions', label_selector.get('match_expressions'))
        if match_expressions:
            if not isinstance(match_expressions, list):
                self.syntax_error('type of matchExpressions is not an array in LabelSelector', label_selector)
            for requirement in match_expressions:
                res &= self.parse_label_selector_requirement(requirement, namespace_selector)

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
        self.check_keys_are_legal(peer, 'NetworkPolicyPeer', allowed_elements)

        pod_selector = peer.get('podSelector', peer.get('pod_selector', 'not_present'))
        ns_selector = peer.get('namespaceSelector', peer.get('namespace_selector', 'not_present'))
        ip_block = peer.get('ipBlock', peer.get('ip_block'))

        if pod_selector == 'not_present' and ns_selector == 'not_present' and ip_block is None:
            self.syntax_error('A NetworkPolicyPeer must have at least one field', peer)

        if ip_block is not None:
            if pod_selector != 'not_present' or ns_selector != 'not_present':
                self.syntax_error('If ipBlock is set then neither of podSelector or namespaceSelector can be', peer)
            return self.parse_ip_block(ip_block)

        if ns_selector != 'not_present':
            res = self.parse_label_selector(ns_selector, True)
        else:
            res = self.peer_container.get_namespace_pods(self.namespace)

        if pod_selector != 'not_present':
            selected_pods = self.parse_label_selector(pod_selector) & res
            if pod_selector and selected_pods == res:
                self.warning('A podSelector selects all pods in the current namespace; it should better be removed.',
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
        self.check_keys_are_legal(port, 'NetworkPolicyPort', {'port': 0, 'protocol': 0, 'endPort': 0},
                                  {'protocol': ['TCP', 'UDP', 'SCTP']})
        port_id = port.get('port')
        protocol = port.get('protocol')
        end_port_num = port.get('endPort')
        if not protocol:
            protocol = 'TCP'

        res = ConnectionSet()
        dest_port_set = PortSet(port_id is None)
        if port_id and end_port_num:
            if isinstance(port_id, str):
                self.syntax_error('endPort cannot be defined if the port field is defined '
                                  'as a named (string) port', port)
            if not isinstance(port_id, int) or not isinstance(end_port_num, int):
                self.syntax_error('type of port or endPort is not numerical in NetworkPolicyPort', port)
            if port_id > end_port_num:
                self.syntax_error('endPort must be equal or greater than port', port)
            dest_port_set.add_port_range(port_id, end_port_num)
        elif port_id:
            if not isinstance(port_id, str) and not isinstance(port_id, int):
                self.syntax_error('type of port is not numerical or named (string) in NetworkPolicyPort', port)
            dest_port_set.add_port(port_id)
        elif end_port_num:
            self.syntax_error('endPort cannot be defined if the port field is not defined ', port)

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
            if not isinstance(peer_array, list):
                self.syntax_error('type of ' + peer_array_key +
                                  ' rule is not an array in egress/ingress of NetworkPolicy', rule)
            res_pods = Peer.PeerSet()
            for peer in peer_array:
                res_pods |= self.parse_peer(peer)
        else:
            res_pods = self.peer_container.get_all_peers_group(True)

        ports_array = rule.get('ports', None)
        if ports_array:
            if not isinstance(ports_array, list):
                self.syntax_error('type of ports is not an array in egress/ingress rule of NetworkPolicy', ports_array)
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
            self.syntax_error('type of Top ds is not a map')
        if self.policy.get('kind') != 'NetworkPolicy':
            return None  # Not a NetworkPolicy object
        api_version = self.policy.get('apiVersion', self.policy.get('api_version'))
        if not api_version:  # when apiVersion doesn't exist/ has empty value we don't get here
            self.syntax_error('An object with no specified apiVersion', self.policy)
        if not isinstance(api_version, str):
            self.syntax_error('type of apiVersion is not a string in NetworkPolicy', self.policy)
        if 'k8s' not in api_version and api_version != 'extensions/v1beta1':
            return None  # apiVersion is not properly set
        self.check_keys_are_legal(self.policy, 'networkPolicy', {'kind': 1, 'metadata': 1, 'spec': 1, 'apiVersion': 0,
                                                                 'api_version': 0},
                                  {'apiVersion': ['networking.k8s.io/v1', 'extensions/v1beta1']})

        policy_metadata = self.policy['metadata']
        allowed_metadata_keys = {'name': 1, 'namespace': 0, 'annotations': 0, 'clusterName': 0, 'creationTimestamp': 0,
                                 'deletionGracePeriodSeconds': 0, 'deletionTimestamp': 0, 'finalizers': 0,
                                 'generateName': 0, 'generation': 0, 'labels': 0, 'managedFields': 0,
                                 'ownerReferences': 0, 'resourceVersion': 0, 'selfLink': 0, 'uid': 0}
        self.check_keys_are_legal(policy_metadata, 'network policy metadata', allowed_metadata_keys)
        if not isinstance(policy_metadata['name'], str):
            self.syntax_error('type of name is not a string in metadata of NetworkPolicy', policy_metadata['name'])
        if 'namespace' in policy_metadata:
            if not isinstance(policy_metadata['namespace'], str):
                self.syntax_error('type of namespace is not a string in metadata of NetworkPolicy',
                                  policy_metadata['namespace'])
            self.namespace = self.peer_container.get_namespace(policy_metadata['namespace'])
        res_policy = K8sNetworkPolicy(policy_metadata['name'], self.namespace)

        policy_spec = self.policy['spec']
        allowed_spec_keys = {'podSelector': 0, 'pod_selector': 0, 'ingress': 0, 'egress': 0,
                             'policyTypes': 0, 'policy_types': 0}
        self.check_keys_are_legal(policy_spec, 'network policy spec', allowed_spec_keys,
                                  {'policyTypes': [['Ingress'], ['Egress'], ['Ingress', 'Egress']]})

        policy_types = policy_spec.get('policyTypes', policy_spec.get('policy_types', []))
        if not policy_types:
            self.warning('policyTypes is missing/empty in the spec of ' + res_policy.full_name(), policy_spec)

        res_policy.affects_ingress = not policy_types or 'Ingress' in policy_types
        if not res_policy.affects_ingress and policy_spec.get('ingress') is not None:
            self.syntax_error('A NetworkPolicy with ingress field but no "Ingress" in its policyTypes', policy_spec)
        res_policy.affects_egress = (policy_types and 'Egress' in policy_types) or \
                                    (not policy_types and 'egress' in policy_spec)
        if not res_policy.affects_egress and policy_spec.get('egress') is not None:
            self.syntax_error('A NetworkPolicy with egress field but no "Egress" in its policyTypes', policy_spec)

        pod_selector = policy_spec.get('podSelector', policy_spec.get('pod_selector', 'not_present'))
        if pod_selector == 'not_present':
            self.syntax_error('podSelector is missing in the spec of ' + res_policy.full_name(), policy_spec)
        res_policy.selected_peers = self.parse_label_selector(pod_selector)
        res_policy.selected_peers &= self.peer_container.get_namespace_pods(self.namespace)

        ingress_rules = policy_spec.get('ingress', [])
        if not isinstance(ingress_rules, list):
            self.syntax_error('type of ingress rules is not an array in spec of ' +
                              res_policy.full_name(), policy_spec)
        for ingress_rule in ingress_rules:
            res_policy.add_ingress_rule(self.parse_ingress_rule(ingress_rule, res_policy.selected_peers))

        egress_rules = policy_spec.get('egress', [])
        if not isinstance(egress_rules, list):
            self.syntax_error('type of egress rules is not an array in spec of ' +
                              res_policy.full_name(), policy_spec)
        for egress_rule in egress_rules:
            res_policy.add_egress_rule(self.parse_egress_rule(egress_rule))

        res_policy.findings = self.warning_msgs
        return res_policy
