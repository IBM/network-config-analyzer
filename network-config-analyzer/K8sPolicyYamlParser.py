#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import re
import Peer
from ConnectionSet import ConnectionSet
from PortSet import PortSet
from TcpLikeProperties import TcpLikeProperties
from GenericYamlParser import GenericYamlParser
from K8sNetworkPolicy import K8sNetworkPolicy, K8sPolicyRule
from PeerContainer import PeerContainer
from ProtocolNameResolver import ProtocolNameResolver


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
        self.namespace = None
        self.referenced_labels = set()

    def check_dns_subdomain_name(self, value, key_container):
        """
        checking validity of the resource name
        :param string value : The value assigned for the key
        :param dict key_container : where the key appears
        :return: None
        """
        if len(value) > 253:
            self.syntax_error(f'invalid subdomain name : "{value}", DNS subdomain name must '
                              f'be no more than 253 characters', key_container)
        pattern = r"[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*"
        if re.fullmatch(pattern, value) is None:
            self.syntax_error(f'invalid DNS subdomain name : "{value}", it must consist of lower case alphanumeric '
                              f'characters, "-" or ".", and must start and end with an alphanumeric character',
                              key_container)

    def check_dns_label_name(self, value, key_container):
        """
        checking validity of the label name
        :param string value : The value assigned for the key
        :param dict key_container : where the key appears
        :return: None
        """
        if len(value) > 63:
            self.syntax_error(f'invalid label: "{value}" ,DNS label name must be no more than 63 characters',
                              key_container)
        pattern = r"[a-z0-9]([-a-z0-9]*[a-z0-9])?"
        if re.fullmatch(pattern, value) is None:
            self.syntax_error(f'invalid DNS label : "{value}", it must consist of lower case alphanumeric characters '
                              f'or "-", and must start and end with an alphanumeric character', key_container)

    def check_label_key_syntax(self, key_label, key_container):
        """
        checking validity of the label's key
        :param string key_label: The key name
        :param dict key_container : The label selector's part where the key appears
        :return: None
        """
        if key_label.count('/') > 1:
            self.syntax_error(f'Invalid key "{key_label}", a valid label key may have two segments: '
                              f'an optional prefix and name, separated by a slash (/).', key_container)
        if key_label.count('/') == 1:
            prefix = key_label.split('/')[0]
            if not prefix:
                self.syntax_error(f'invalid key "{key_label}", prefix part must be non-empty', key_container)
            self.check_dns_subdomain_name(prefix, key_container)
            name = key_label.split('/')[1]
        else:
            name = key_label
        if not name:
            self.syntax_error(f'invalid key "{key_label}", name segment is required in label key', key_container)
        if len(name) > 63:
            self.syntax_error(f'invalid key "{key_label}", a label key name must be no more than 63 characters',
                              key_container)
        pattern = r"([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]"
        if re.fullmatch(pattern, name) is None:
            self.syntax_error(f'invalid key "{key_label}", a label key name part must consist of alphanumeric '
                              f'characters, "-", "_" or ".", and must start and end with an alphanumeric character',
                              key_container)

    def check_label_value_syntax(self, val, key, key_container):
        """
        checking validity of the label's value
        :param string val : the value to be checked
        :param string key: The key name which the value is assigned for
        :param dict key_container : The label selector's part where the key: val appear
        :return: None
        """
        if val is None:
            self.syntax_error(f'value label of "{key}" can not be null', key_container)
        if val:
            if len(val) > 63:
                self.syntax_error(f'invalid value in "{key}: {val}", a label value must be no more than 63 characters',
                                  key_container)
            pattern = r"(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?"
            if re.fullmatch(pattern, val) is None:
                self.syntax_error(f'invalid value in "{key}: {val}", value label must be an empty string or consist'
                                  f' of alphanumeric characters, "-", "_" or ".", and must start and end with an '
                                  f'alphanumeric character ', key_container)

    def parse_label_selector_requirement(self, requirement, namespace_selector):
        """
        Parse a LabelSelectorRequirement element
        :param dict requirement: The element to parse
        :param bool namespace_selector: Whether or not this is in the context of namespaceSelector
        :return: A PeerSet containing the peers that satisfy the requirement
        :rtype: Peer.PeerSet
        """
        self.check_fields_validity(requirement, 'LabelSelectorRequirement', {'key': [1, str], 'operator': [1, str],
                                                                             'values': [0, list]},
                                   {'operator': ['In', 'NotIn', 'Exists', 'DoesNotExist']})
        key = requirement['key']
        operator = requirement['operator']
        self.check_label_key_syntax(key, requirement)
        if operator in ['In', 'NotIn']:
            values = requirement.get('values')
            if not values:
                self.syntax_error('A requirement with In/NotIn operator but without values', requirement)
            action = self.FilterActionType.In if operator == 'In' else self.FilterActionType.NotIn
            if namespace_selector:
                return self.peer_container.get_namespace_pods_with_label(key, values, action)
            return self.peer_container.get_peers_with_label(key, values, action)

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
        allowed_elements = {'matchLabels': [0, dict], 'matchExpressions': [0, list]}
        self.check_fields_validity(label_selector, 'pod/namespace selector', allowed_elements)

        res = self.peer_container.get_all_peers_group()
        match_labels = label_selector.get('matchLabels')
        if match_labels:
            keys_set = set()
            for key, val in match_labels.items():
                self.check_label_key_syntax(key, match_labels)
                self.check_label_value_syntax(val, key, match_labels)
                if namespace_selector:
                    res &= self.peer_container.get_namespace_pods_with_label(key, [val])
                else:
                    res &= self.peer_container.get_peers_with_label(key, [val])
                keys_set.add(key)
            self.referenced_labels.add(':'.join(keys_set))

        match_expressions = label_selector.get('matchExpressions')
        if match_expressions:
            keys_set = set()
            for requirement in match_expressions:
                res &= self.parse_label_selector_requirement(requirement, namespace_selector)
                key = requirement['key']
                keys_set.add(key)
            self.referenced_labels.add(':'.join(keys_set))

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
        self.check_fields_validity(block, 'ipBlock', {'cidr': [1, str], 'except': [0, list]})
        res = Peer.PeerSet()
        try:
            res.add(Peer.IpBlock(block['cidr'], block.get('except')))
        except ValueError as e:
            self.syntax_error(str(e.args), block)
        except TypeError as e:
            self.syntax_error(str(e.args), block)
        return res

    def parse_peer(self, peer):
        """
        Parse a NetworkPolicyPeer inside a rule (an element of the 'to'/'from' array)
        :param dict peer: The object to parse
        :return: A PeerSet object containing the set of peers defined by the selectors/ipblocks
        :rtype: Peer.PeerSet
        """
        allowed_elements = {'podSelector': [0, dict], 'namespaceSelector': [0, dict], 'ipBlock': [0, dict]}
        self.check_fields_validity(peer, 'NetworkPolicyPeer', allowed_elements)

        pod_selector = peer.get('podSelector')
        ns_selector = peer.get('namespaceSelector')
        ip_block = peer.get('ipBlock')

        if pod_selector is None and ns_selector is None and ip_block is None:
            self.syntax_error('A NetworkPolicyPeer must have at least one field', peer)

        if ip_block is not None:
            if pod_selector is not None or ns_selector is not None:
                self.syntax_error('If ipBlock is set then neither of podSelector or namespaceSelector can be', peer)
            return self.parse_ip_block(ip_block)

        if ns_selector is not None:
            res = self.parse_label_selector(ns_selector, True)
        else:
            res = self.peer_container.get_namespace_pods(self.namespace)

        if pod_selector is not None:
            selected_pods = self.parse_label_selector(pod_selector) & res
            if pod_selector and selected_pods == res and res:
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
        self.check_fields_validity(port, 'NetworkPolicyPort', {'port': 0, 'protocol': [0, str], 'endPort': [0, int]},
                                   {'protocol': ['TCP', 'UDP', 'SCTP']})
        port_id = port.get('port')
        protocol = port.get('protocol')
        end_port_num = port.get('endPort')
        if not protocol:
            protocol = 'TCP'

        res = ConnectionSet()
        dest_port_set = PortSet(port_id is None)
        if port_id is not None and end_port_num is not None:
            if isinstance(port_id, str):
                self.syntax_error('endPort cannot be defined if the port field is defined '
                                  'as a named (string) port', port)
            if not isinstance(port_id, int):
                self.syntax_error('type of port is not numerical in NetworkPolicyPort', port)
            self.validate_value_in_domain(port_id, 'dst_ports', port, 'Port number')
            self.validate_value_in_domain(end_port_num, 'dst_ports', port, 'endPort number')
            if port_id > end_port_num:
                self.syntax_error('endPort must be equal or greater than port', port)
            dest_port_set.add_port_range(port_id, end_port_num)
        elif port_id is not None:
            if not isinstance(port_id, str) and not isinstance(port_id, int):
                self.syntax_error('type of port is not numerical or named (string) in NetworkPolicyPort', port)
            if isinstance(port_id, int):
                self.validate_value_in_domain(port_id, 'dst_ports', port, 'Port number')
            if isinstance(port_id, str):
                if len(port_id) > 15:
                    self.syntax_error('port name  must be no more than 15 characters', port)
                if re.fullmatch(r"[a-z\d]([-a-z\d]*[a-z\d])?", port_id) is None:
                    self.syntax_error('port name should contain only lowercase alphanumeric characters or "-", '
                                      'and start and end with alphanumeric characters', port)

            dest_port_set.add_port(port_id)
        elif end_port_num:
            self.syntax_error('endPort cannot be defined if the port field is not defined ', port)

        res.add_connections(protocol, TcpLikeProperties(PortSet(True), dest_port_set))  # K8s doesn't reason about src ports
        return res

    def parse_ingress_egress_rule(self, rule, peer_array_key):
        """
        Parse a single ingres/egress rule, producing a K8sPolicyRule
        :param dict rule: The rule to parse
        :param str peer_array_key: The key which defined the peer set ('from' for ingress, 'to' for egress)
        :return: A K8sPolicyRule with the proper PeerSet and ConnectionSet
        :rtype: K8sPolicyRule
        """
        self.check_fields_validity(rule, 'ingress/egress rule', {peer_array_key: [0, list], 'ports': [0, list]})
        peer_array = rule.get(peer_array_key, [])
        if peer_array:
            res_pods = Peer.PeerSet()
            for peer in peer_array:
                res_pods |= self.parse_peer(peer)
        else:
            res_pods = self.peer_container.get_all_peers_group(True)

        ports_array = rule.get('ports', [])
        if ports_array:
            res_ports = ConnectionSet()
            for port in ports_array:
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
                        if ProtocolNameResolver.get_protocol_number(pod_named_port[1]) != protocol:
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
        if not isinstance(self.policy, dict):  # we don't get here
            self.syntax_error('type of Top ds is not a map')
        if self.policy.get('kind') != 'NetworkPolicy':
            return None  # Not a NetworkPolicy object
        api_version = self.policy.get('apiVersion')
        if 'k8s' not in api_version and api_version != 'extensions/v1beta1':
            return None  # apiVersion is not properly set
        self.check_fields_validity(self.policy, 'NetworkPolicy', {'kind': [1, str], 'metadata': [1, dict],
                                                                  'spec': [0, dict], 'apiVersion': [1, str]},
                                   {'apiVersion': ['networking.k8s.io/v1', 'extensions/v1beta1']})

        policy_metadata = self.policy['metadata']
        allowed_metadata_keys = {'name': [1, str], 'namespace': [0, str], 'annotations': 0, 'clusterName': 0,
                                 'creationTimestamp': 0, 'deletionGracePeriodSeconds': 0, 'deletionTimestamp': 0,
                                 'finalizers': 0, 'generateName': 0, 'generation': 0, 'labels': 0, 'managedFields': 0,
                                 'ownerReferences': 0, 'resourceVersion': 0, 'selfLink': 0, 'uid': 0}
        self.check_fields_validity(policy_metadata, 'metadata', allowed_metadata_keys)
        self.check_dns_subdomain_name(policy_metadata['name'], policy_metadata)
        if 'namespace' in policy_metadata and policy_metadata['namespace'] is not None:
            self.check_dns_label_name(policy_metadata['namespace'], policy_metadata)
            self.namespace = self.peer_container.get_namespace(policy_metadata['namespace'])
        else:
            self.namespace = self.peer_container.get_namespace('default')
        res_policy = K8sNetworkPolicy(policy_metadata['name'], self.namespace)

        if 'spec' not in self.policy or self.policy['spec'] is None:
            self.warning('spec is missing or null in NetworkPolicy ' + res_policy.full_name())
            return res_policy

        policy_spec = self.policy['spec']
        allowed_spec_keys = {'podSelector': [1, dict], 'ingress': [0, list], 'egress': [0, list],
                             'policyTypes': [0, list]}
        self.check_fields_validity(policy_spec, 'spec', allowed_spec_keys,
                                   {'policyTypes': [['Ingress'], ['Egress'], ['Ingress', 'Egress']]})

        policy_types = policy_spec.get('policyTypes', [])
        if not policy_types:
            self.warning('policyTypes is missing/empty in the spec of ' + res_policy.full_name(), policy_spec)

        res_policy.affects_ingress = not policy_types or 'Ingress' in policy_types
        if not res_policy.affects_ingress and policy_spec.get('ingress') is not None:
            self.syntax_error('A NetworkPolicy with ingress field but no "Ingress" in its policyTypes', policy_spec)
        res_policy.affects_egress = (policy_types and 'Egress' in policy_types) or \
                                    (not policy_types and 'egress' in policy_spec)
        if not res_policy.affects_egress and policy_spec.get('egress') is not None:
            self.syntax_error('A NetworkPolicy with egress field but no "Egress" in its policyTypes', policy_spec)

        pod_selector = policy_spec.get('podSelector')
        res_policy.selected_peers = self.parse_label_selector(pod_selector)
        res_policy.selected_peers &= self.peer_container.get_namespace_pods(self.namespace)

        ingress_rules = policy_spec.get('ingress', [])
        if ingress_rules:
            for ingress_rule in ingress_rules:
                res_policy.add_ingress_rule(self.parse_ingress_rule(ingress_rule, res_policy.selected_peers))

        egress_rules = policy_spec.get('egress', [])
        if egress_rules:
            for egress_rule in egress_rules:
                res_policy.add_egress_rule(self.parse_egress_rule(egress_rule))

        res_policy.findings = self.warning_msgs
        res_policy.referenced_labels = self.referenced_labels
        return res_policy
