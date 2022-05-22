#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import re
from ruamel.yaml import comments
from Peer import PeerSet, IpBlock
from PortSet import PortSet
from TcpLikeProperties import TcpLikeProperties
from ICMPDataSet import ICMPDataSet
from ConnectionSet import ConnectionSet
from GenericYamlParser import GenericYamlParser
from CalicoNetworkPolicy import CalicoNetworkPolicy, CalicoPolicyRule
from PeerContainer import PeerContainer
from K8sNamespace import K8sNamespace
from ProtocolNameResolver import ProtocolNameResolver


class CalicoPolicyYamlParser(GenericYamlParser):
    """
    A parser for Calico NetworkPolicy/GlobalNetworkPolicy/Profile objects
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
        # collecting labels used in calico network policy for fw-rules computation
        self.referenced_labels = set()

    def _parse_selector_expr(self, expr, origin_map, namespace, is_namespace_selector):
        """
        Parses an atomic expression (not containing a && or ||)
        :param str expr: The string expression to parse
        :param dict origin_map: The EntityRule object in which those expressions reside (for reporting errors)
        :param K8sNamespace namespace: Restrict pods to this given Namespace
        :param bool is_namespace_selector: whether the containing selector is a namespaceSelector
        :return: the set of peers selected by the selector expression
        :rtype: PeerSet
        """
        expr = expr.strip()  # remove leading and trailing spaces
        expr = ' '.join(expr.split())  # remove redundant spaces
        if is_namespace_selector and expr == 'global()':
            return self.peer_container.get_all_global_peers()
        elif is_namespace_selector:
            all_peers = self.peer_container.get_all_peers_group(include_globals=False)
        else:
            all_peers = self.peer_container.get_namespace_pods(namespace)
        if expr == 'all()':
            return all_peers

        # expressions like "has(key)" or "!has(key)"
        has_re = re.compile('has\\(([\\w.\\-/]+)\\)')
        has_match = has_re.match(expr)
        if has_match:
            label = has_match.group(1)
            # TODO: currently misses ANDing of keys
            self.referenced_labels.add(label)
            if is_namespace_selector:
                return all_peers & self.peer_container.get_namespace_pods_with_key(label, False)
            return all_peers & self.peer_container.get_peers_with_key(namespace, label, False)

        # expressions like "key==val" or "key!=val"
        key_val_re = re.compile("([\\w.\\-/]+)\\s?([=!])=\\s?'([\\w.\\-/]+)'")
        key_val_match = key_val_re.match(expr)
        if key_val_match:
            key = key_val_match.group(1)
            equality = key_val_match.group(2)
            val = key_val_match.group(3)
            action = self.FilterActionType.In if equality == '=' else self.FilterActionType.NotIn
            self.referenced_labels.add(key)
            if is_namespace_selector:
                return all_peers & self.peer_container.get_namespace_pods_with_label(key, [val], action)
            return all_peers & self.peer_container.get_peers_with_label(key, [val], action)

        # expressions like key in "key in {val1, val2}" or "key not in {val1, val2}"
        in_re = re.compile("([\\w.\\-/]+)\\s(not\\s)?in\\s?{\\s?'[\\w.\\-/]+'\\s?(,\\s?'[\\w.\\-/]+'\\s?)*}")
        in_match = in_re.match(expr)
        if in_match:
            key = in_match.group(1)
            no_not = in_match.group(2) is None
            values = re.findall("'([\\w.\\-/]*)'", expr)
            action = self.FilterActionType.In if no_not else self.FilterActionType.NotIn
            self.referenced_labels.add(key)
            if is_namespace_selector:
                return all_peers & self.peer_container.get_namespace_pods_with_label(key, values, action)
            return all_peers & self.peer_container.get_peers_with_label(key, values, action)

        # expressions like key in "key contains substr"
        str_re = re.compile("([\\w.\\-/]+)\\s?(contains|starts\\swith|ends\\swith)\\s?'([\\w.\\-/]+)'")
        str_match = str_re.match(expr)
        if str_match:
            key = str_match.group(1)
            substr = str_match.group(3)
            action = self.FilterActionType.Contain
            if str_match.group(2).startswith('starts'):
                action = self.FilterActionType.StartWith
            elif str_match.group(2).startswith('ends'):
                action = self.FilterActionType.EndWith
            self.referenced_labels.add(key)
            if is_namespace_selector:
                return all_peers & self.peer_container.get_namespace_pods_with_label(key, [substr], action)
            return all_peers & self.peer_container.get_peers_with_label(key, [substr], action)

        self.syntax_error('Invalid expression', origin_map)
        return None

    def _strip_selector(self, origin_map, expression):
        """
        removing brackets and spaces
        :param dict origin_map: The EntityRule object (for reporting errors)
        :param str expression: The selector expression to parse
        :return: striped expression
        :rtype: str
        """
        expression = expression.strip()
        if expression.count('(') != expression.count(')'):
            self.syntax_error('number of brackets are not even: ' + expression, origin_map)
        while expression.startswith('(') and expression.endswith(')'):
            n_brackets = 0
            do_not_remove = False
            for c in expression[0:len(expression) - 1]:
                if c == '(':
                    n_brackets += 1
                if c == ')':
                    n_brackets -= 1
                if n_brackets == 0:
                    do_not_remove = True
            if do_not_remove:
                break
            expression = expression[1:len(expression) - 1]
            expression = expression.strip()
        return expression

    @staticmethod
    def _split_selector(expression, operator):
        """
        split the expression by an operator, considering brackets. i.e. "(a || b) || c" is being split to ["(a || b)", "c"]
        :param str expression: The selector expression to parse
        :param str operator: The operator to split with
        :return: a list of expressions
        :rtype: list of str
        """
        expressions = expression.split(operator)
        current_expr = ""
        split_expr = []
        for expr in expressions:
            current_expr += expr
            if current_expr.count('(') == current_expr.count(')'):
                split_expr.append(current_expr)
                current_expr = ""
            else:
                current_expr += operator
        return split_expr

    def _recursive_parse_label_selector(self, label_selector, origin_map, namespace, namespace_selector):
        """
        Recursive Parse a label selector expression appearing in selector/notSelector/namespaceSelector parts of the EntityRule
        :param str label_selector: The selector expression to parse
        :param dict origin_map: The EntityRule object (for reporting errors)
        :param K8sNamespace namespace: Restrict pods to the given namespace
        :param bool namespace_selector: True if this is a namespaceSelector
        :return: the set of peers selected by the selector expression
        :rtype: PeerSet
        """

        include_globals = not namespace_selector or 'global()' in label_selector
        label_selector = self._strip_selector(origin_map, label_selector)
        # We are handling the operators according to the "order of operation" - '!', '&&', '||'.
        # i.e. we will first try to spit the label by '||',
        # if the label does not contain '||', we will split by '&&',
        # if the label does not contain &&, we will look for the prefix '!',
        # and if there is no '!', we will evaluate the expression.
        # handling '||' :
        split_expr = self._split_selector(label_selector, '||')
        if len(split_expr) != 1:
            res = PeerSet()
            for expr in split_expr:
                res |= self._recursive_parse_label_selector(expr, origin_map, namespace, namespace_selector)
            return res

        # there is no '||', handling '&&' :
        split_expr = self._split_selector(label_selector, '&&')
        if len(split_expr) != 1:
            res = self.peer_container.get_all_peers_group(include_globals=include_globals)
            for expr in split_expr:
                res &= self._recursive_parse_label_selector(expr, origin_map, namespace, namespace_selector)
            return res

        # there is no '&&', handling '!' :
        if label_selector[0] == '!':
            if namespace_selector:
                all_peers = self.peer_container.get_all_peers_group(include_globals=include_globals)
            else:
                all_peers = self.peer_container.get_namespace_pods(namespace)
            return all_peers - self._recursive_parse_label_selector(label_selector[1:], origin_map, namespace,
                                                                    namespace_selector)

        # there is no operator, parsing the expression:
        return self._parse_selector_expr(split_expr[0], origin_map, namespace, namespace_selector)

    def _parse_label_selector(self, label_selector, origin_map, namespace=None, namespace_selector=False):
        """
        Parse a label selector expression appearing in selector/notSelector/namespaceSelector parts of the EntityRule
        :param str label_selector: The selector expression to parse
        :param dict origin_map: The EntityRule object (for reporting errors)
        :param K8sNamespace namespace: Restrict pods to the given namespace
        :param bool namespace_selector: True if this is a namespaceSelector
        :return: the set of peers selected by the selector expression
        :rtype: PeerSet
        """
        if not label_selector or not isinstance(label_selector, str) or label_selector.isspace():  # empty
            self.syntax_error('Missing selector', origin_map)
        res = self._recursive_parse_label_selector(label_selector, origin_map, namespace, namespace_selector)

        selector_type = 'namespaceSelector' if namespace_selector else 'selector'
        if not res:
            self.warning(f'{selector_type} ({label_selector}) selects no endpoints.', origin_map)
        elif res == self.peer_container.get_all_peers_group(include_globals=not namespace_selector) and \
                label_selector and label_selector != 'all()' and 'global()' not in label_selector:
            self.warning(f'{selector_type} ({label_selector}) selects all endpoints - better delete or use "all()".',
                         origin_map)

        return res

    def _parse_port(self, port, array):
        """
        Parse a single port in the array defined in the ports/notPorts part of an EntityRule
        :param port: The port to parse (might be an int, a range of ints or a named port)
        :param list array: The object containing the port (for reporting errors)
        :return: The set of ports defined by port
        :rtype: PortSet
        """
        res_port_set = PortSet()
        if isinstance(port, int):
            self.validate_value_in_domain(port, 'dst_ports', array, 'Port number')
            res_port_set.add_port(port)
        elif isinstance(port, str):
            if port.count(':') == 1:
                port_range = port.split(':')
                try:
                    left_port = int(port_range[0])
                    right_port = int(port_range[1])
                    self.validate_value_in_domain(left_port, 'dst_ports', array, 'Port number')
                    self.validate_value_in_domain(right_port, 'dst_ports', array, 'Port number')
                    if right_port < left_port:
                        self.syntax_error('Invalid port range: ' + port, array)
                    res_port_set.add_port_range(left_port, right_port)
                except ValueError:
                    res_port_set.add_port(port)
            else:
                res_port_set.add_port(port)
        return res_port_set

    @staticmethod
    def _get_value_as_str(dict_to_use, key):
        """
        Safely getting string values that contain '!'.
        Calico uses '!' as negation operator in selectors, while YAML uses it to declare tags
        :param dict dict_to_use: The dictionary to retrieve the value from
        :param str key: The key for which the value should be retrieved
        :return: The proper string value
        """
        val = dict_to_use.get(key)
        if isinstance(val, comments.TaggedScalar):  # negation operator '!' is used to declare tags in YAML
            val = val.tag.value
        return val

    def _get_rule_peers(self, entity_rule):
        """
        Parse the peer-specifying parts of the source/destination parts of a rule
        :param dict entity_rule: The object to parse
        :return: The peers that are specified by nets/notNets/selector/notSelector/namespaceSelector
        :rtype: PeerSet
        """
        nets = entity_rule.get('nets')
        if nets:
            rule_ips = IpBlock(nets[0])
            for cidr in nets[1:]:
                rule_ips |= IpBlock(cidr)
        else:
            rule_ips = IpBlock.get_all_ips_block()

        not_nets = entity_rule.get('notNets', [])
        for cidr in not_nets:
            rule_ips -= IpBlock(cidr)

        ns_selector = self._get_value_as_str(entity_rule, 'namespaceSelector')
        pod_selector = self._get_value_as_str(entity_rule, 'selector')
        not_pod_selector = self._get_value_as_str(entity_rule, 'notSelector')
        if ns_selector:
            rule_peers = self._parse_label_selector(ns_selector, entity_rule, namespace_selector=True)
        elif pod_selector:
            rule_peers = self.peer_container.get_namespace_pods(self.namespace)
        elif nets or not_nets:
            rule_peers = PeerSet()
            rule_peers.add(rule_ips)
        else:
            rule_peers = self.peer_container.get_all_peers_group(True)

        ns_to_use = self.namespace if not ns_selector else None
        if pod_selector is not None:
            selected_pods = self._parse_label_selector(pod_selector, entity_rule, ns_to_use)
            if pod_selector.strip() != 'all()' and selected_pods == rule_peers:
                self.warning('selector has no effect - better delete or use "all()"', entity_rule)
            rule_peers &= selected_pods
        if not_pod_selector:
            rule_peers -= self._parse_label_selector(not_pod_selector, entity_rule, ns_to_use)

        if (nets or not_nets) and (ns_selector or pod_selector):
            rule_peers = PeerSet()
            self.warning('Mixing ip-based selection with label-based selection is likely a mistake', entity_rule)

        return rule_peers

    def _get_rule_ports(self, entity_rule, protocol_supports_ports):
        """
        Parse the port-related parts of the source/destination parts of a rule
        :param dict entity_rule: The object to parse
        :param bool protocol_supports_ports: Whether ports are allowed for the rule's protocol
        :return: The ports that are specified by ports/notPorts
        :rtype: PortSet
        """
        ports_array = entity_rule.get('ports')
        if ports_array is not None:
            if not protocol_supports_ports:
                self.syntax_error('A rule specifying ports must specify a protocol supporting ports', ports_array)
            rule_ports = PortSet()
            for port in ports_array:
                rule_ports |= self._parse_port(port, ports_array)
        else:
            rule_ports = PortSet(True)

        not_ports_array = entity_rule.get('notPorts')
        if not_ports_array is not None:
            if not protocol_supports_ports:
                self.syntax_error('A rule specifying notPorts must specify a protocol supporting ports', ports_array)
            for port in not_ports_array:
                rule_ports -= self._parse_port(port, not_ports_array)

        return rule_ports

    def _parse_entity_rule(self, entity_rule, protocol_supports_ports):
        """
        Parse the source/destination parts of a rule
        :param dict entity_rule: The object to parse
        :param bool protocol_supports_ports: Whether ports are allowed for the rule's protocol
        :return: The peers that are specified by the relevant fields + the ports that are specified by ports/notPorts
        :rtype: PeerSet, PortSet
        """
        allowed_elements = {'nets': 0, 'notNets': 0, 'selector': 0, 'notSelector': 0,
                            'namespaceSelector': 0, 'ports': 0, 'notPorts': 0, 'serviceAccounts': 2}
        self.check_fields_validity(entity_rule, 'network policy peer', allowed_elements)

        return self._get_rule_peers(entity_rule), self._get_rule_ports(entity_rule, protocol_supports_ports)

    def _parse_icmp(self, icmp_data, not_icmp_data):
        """
        Parse the icmp and notICMP parts of a rule
        :param dict icmp_data:
        :param dict not_icmp_data:
        :return: an ICMPDataSet object representing the allowed ICMP connections
        :rtype: ICMPDataSet
        """
        icmp_type = icmp_data.get('type') if icmp_data is not None else None
        icmp_code = icmp_data.get('code') if icmp_data is not None else None
        not_icmp_type = not_icmp_data.get('type') if not_icmp_data is not None else None
        not_icmp_code = not_icmp_data.get('code') if not_icmp_data is not None else None

        allowed_keys = {'type': 0, 'code': 0}
        if icmp_data is not None:
            self.check_fields_validity(icmp_data, 'ICMP', allowed_keys)
            err = ICMPDataSet.check_code_type_validity(icmp_type, icmp_code)
            if err:
                self.syntax_error(err, icmp_data)
        if not_icmp_data is not None:
            self.check_fields_validity(not_icmp_data, 'notICMP', allowed_keys)
            err = ICMPDataSet.check_code_type_validity(not_icmp_type, not_icmp_code)
            if err:
                self.syntax_error(err, not_icmp_data)

        res = ICMPDataSet(icmp_data is None and not_icmp_data is None)
        if icmp_data is not None:
            res.add_to_set(icmp_type, icmp_code)
            if not_icmp_data is not None:
                if icmp_type == not_icmp_type and icmp_code == not_icmp_code:
                    res = ICMPDataSet()
                    self.warning('icmp and notICMP are conflicting - no traffic will be matched', not_icmp_data)
                elif icmp_type == not_icmp_type and icmp_code is None:
                    tmp = ICMPDataSet()  # this is the only case where it makes sense to combine icmp and notICMP
                    tmp.add_to_set(not_icmp_type, not_icmp_code)
                    res -= tmp
                else:
                    self.warning('notICMP has no effect', not_icmp_data)
        elif not_icmp_data is not None:
            res.add_all_but_given_pair(not_icmp_type, not_icmp_code)

        return res

    def _parse_protocol(self, protocol, rule):
        """
        Parse the protocol/notProtocol field in a rule
        :param protocol: The protocol (a string or an int)
        :param dict rule: The parsed rule object (for context)
        :return: The protocol number
        :rtype: int
        """
        if not protocol:
            return None
        if isinstance(protocol, int):
            if protocol < 1 or protocol > 255:
                self.syntax_error('protocol must be a string or an integer in the range 1-255', rule)
            return protocol

        if protocol not in ['TCP', 'UDP', 'ICMP', 'ICMPv6', 'SCTP', 'UDPLite']:
            self.syntax_error('invalid protocol name: ' + protocol, rule)
        return ProtocolNameResolver.get_protocol_number(protocol)

    def _parse_xgress_rule(self, rule, is_ingress, policy_selected_eps, is_profile):
        """
        Parse a single ingres/egress rule, producing a CalicoPolicyRule
        :param dict rule: The rule element to parse
        :param bool is_ingress: Whether this is an ingress rule
        :param PeerSet policy_selected_eps: The endpoints the policy captured
        :param bool is_profile: Whether the parsed policy is a Profile object
        :return: A CalicoPolicyRule with the proper PeerSets, ConnectionSets and Action
        :rtype: CalicoPolicyRule
        """
        allowed_keys = {'action': 1, 'protocol': 0, 'notProtocol': 0, 'icmp': 0, 'notICMP': 0, 'ipVersion': 0,
                        'source': 0, 'destination': 0, 'http': 2}
        self.check_fields_validity(rule, 'ingress/egress rule', allowed_keys)

        action = CalicoPolicyRule.action_str_to_action_type(rule['action'])
        if action is None:
            self.syntax_error('Invalid rule action: ' + rule['action'], rule)
        if is_profile and action == CalicoPolicyRule.ActionType.Pass:
            self.warning('Pass actions in Profile rules will be ignored', rule)

        protocol = self._parse_protocol(rule.get('protocol'), rule)
        protocol_supports_ports = ConnectionSet.protocol_supports_ports(protocol)
        not_protocol = self._parse_protocol(rule.get('notProtocol'), rule)
        src_entity_rule = rule.get('source')
        if src_entity_rule:
            src_res_pods, src_res_ports = self._parse_entity_rule(src_entity_rule, protocol_supports_ports)
        else:
            src_res_pods = self.peer_container.get_all_peers_group(True)
            src_res_ports = PortSet(True)

        dst_entity_rule = rule.get('destination')
        if dst_entity_rule:
            dst_res_pods, dst_res_ports = self._parse_entity_rule(dst_entity_rule, protocol_supports_ports)
        else:
            dst_res_pods = self.peer_container.get_all_peers_group(True)
            dst_res_ports = PortSet(True)

        if is_ingress:  # FIXME: We do not handle well the case where dst_res_pods or src_res_pods contain ipBlocks
            dst_res_pods &= policy_selected_eps
        else:
            src_res_pods &= policy_selected_eps

        connections = ConnectionSet()
        if protocol is not None:
            if not_protocol is not None:
                if protocol == not_protocol:
                    self.warning('Protocol and notProtocol are conflicting, no traffic will be matched', rule)
                else:
                    self.warning('notProtocol field has no effect', rule)
            else:
                if protocol_supports_ports:
                    connections.add_connections(protocol, TcpLikeProperties(src_res_ports, dst_res_ports))
                elif ConnectionSet.protocol_is_icmp(protocol):
                    connections.add_connections(protocol, self._parse_icmp(rule.get('icmp'), rule.get('notICMP')))
                else:
                    connections.add_connections(protocol, True)
        elif not_protocol is not None:
            connections.add_all_connections()
            connections.remove_protocol(not_protocol)
        else:
            connections.allow_all = True

        self._verify_named_ports(rule, dst_res_pods, connections)

        if not src_res_pods and policy_selected_eps and (is_ingress or not is_profile):
            self.warning('Rule selects no source endpoints', rule)
        if not dst_res_pods and policy_selected_eps and (not is_ingress or not is_profile):
            self.warning('Rule selects no destination endpoints', rule)

        return CalicoPolicyRule(src_res_pods, dst_res_pods, connections, action)

    def _verify_named_ports(self, rule, rule_eps, rule_conns):
        """
        Check the validity of named ports in a given rule: whether a relevant ep refers to the named port and whether
        the protocol defined in the policy matches the protocol defined by the ep. Issue warnings as required.
        :param dict rule: The unparsed rule (for reference in warnings)
        :param Peer.PeerSet rule_eps: The set of eps in which the named ports should be defined
        :param ConnectionSet rule_conns: The rule-specified connections, possibly containing named ports
        :return: None
        """
        if not rule_conns.has_named_ports():
            return
        named_ports = rule_conns.get_named_ports()
        for protocol, rule_ports in named_ports:
            for port in rule_ports:
                port_used = False
                for pod in rule_eps:
                    pod_named_port = pod.get_named_ports().get(port)
                    if pod_named_port:
                        port_used = True
                        if ProtocolNameResolver.get_protocol_number(pod_named_port[1]) != protocol:
                            self.warning(f'Protocol mismatch for named port {port} (vs. Pod {pod.full_name()})', rule)

                if not port_used:
                    self.warning(f'Named port {port} is not defined in any selected pod', rule)

    def _apply_extra_labels(self, policy_spec, is_profile, profile_name):
        """
        Add the labels in a profile's labelToApply field to all Pods with this profile
        :param dict policy_spec: The spec part of the yaml object
        :param bool is_profile: Whether we parse a Profile object
        :param str profile_name: The name of the parsed profile
        :return: None
        """
        labels_to_apply = policy_spec.get('labelsToApply')
        if not labels_to_apply:
            return

        if not is_profile:
            self.syntax_error('labelsToApply can only be defined in a Profile', labels_to_apply)

        profile_pods = self.peer_container.get_profile_pods(profile_name, False)
        for pod in profile_pods:
            for label, value in labels_to_apply.items():
                pod.set_extra_label(label, value)

    def _set_affects_ingress_egress(self, policy_spec, is_profile, res_policy):
        """
        Inspect relevant fields in the spec to determine whether the policy affects ingress/egress
        :param dict policy_spec: The spec part of the policy
        :param bool is_profile: whether we parse a Profile object
        :param CalicoNetworkPolicy res_policy: The NetworkPolicy object to update
        :return: None
        """
        allowed_policy_keys = {'order': 0, 'selector': 0, 'ingress': 0, 'egress': 0, 'types': 0, 'labelsToApply': 0,
                               'doNotTrack': 2, 'preDNAT': 2, 'applyOnForward': 2}
        self.check_fields_validity(policy_spec, 'network policy spec', allowed_policy_keys)

        policy_types = policy_spec.get('types', [])
        if not is_profile and not policy_types:
            self.warning('types is missing/empty in the spec of ' + res_policy.full_name(), policy_spec)
        else:
            allowed_types = {'Egress', 'Ingress'}
            bad_types = set(policy_types).difference(allowed_types)
            if bad_types:
                self.syntax_error('Bad type in policyTypes (policy ' + res_policy.full_name() + '): ' + bad_types.pop(),
                                  policy_types)
        res_policy.affects_ingress = 'Ingress' in policy_types or \
                                     (not policy_types and ('ingress' in policy_spec or 'egress' not in policy_spec))
        if not res_policy.affects_ingress and 'ingress' in policy_spec:
            self.syntax_error('A NetworkPolicy with ingress field but no "Ingress" in its policyTypes', policy_spec)
        res_policy.affects_egress = ('Egress' in policy_types) or (not policy_types and 'egress' in policy_spec)
        if not res_policy.affects_egress and 'egress' in policy_spec:
            self.syntax_error('A NetworkPolicy with egress field but no "Egress" in its policyTypes', policy_spec)

    def _set_selected_peers(self, policy_spec, is_profile, res_policy):
        """
        Set the selected_peers member of the policy according to the spec
        :param dict policy_spec: The spec part in the yaml
        :param bool is_profile: Whether we parse a Profile object
        :param CalicoNetworkPolicy res_policy: The NetworkPolicy to update the selected_peers for
        :return: None
        """
        pod_selector = policy_spec.get('selector')
        if pod_selector:
            if is_profile:
                self.syntax_error('selector is not allowed in the spec of a Profile', policy_spec)
            res_policy.selected_peers = self._parse_label_selector(pod_selector, policy_spec, self.namespace)
        else:
            if is_profile:
                res_policy.selected_peers = self.peer_container.get_profile_pods(res_policy.name, True)
            else:
                res_policy.selected_peers = self.peer_container.get_namespace_pods(self.namespace)

    def parse_policy(self):
        """
        Parses the input object to create a CalicoNetworkPolicy object
        :return: a CalicoNetworkPolicy object with proper PeerSets, ConnectionSets and Actions
        :rtype: CalicoNetworkPolicy
        """
        if not isinstance(self.policy, dict):
            self.syntax_error('Top ds is not a map')
        kind = self.policy.get('kind')
        if not kind or kind not in ['NetworkPolicy', 'GlobalNetworkPolicy', 'Profile']:
            return None
        is_profile = (kind == 'Profile')

        api_version = self.policy.get('apiVersion')
        if not api_version:
            self.syntax_error('An object with no specified apiVersion', self.policy)
        if 'calico' not in api_version:
            return None
        if api_version != 'projectcalico.org/v3':
            raise Exception('Unsupported apiVersion: ' + api_version)
        self.check_fields_validity(self.policy, 'networkPolicy', {'kind': 1, 'metadata': 1, 'spec': 1, 'apiVersion': 1})
        metadata = self.policy['metadata']
        if 'name' not in metadata:
            self.syntax_error('NetworkPolicy has no name', metadata)
        if 'namespace' in metadata:
            if kind == 'GlobalNetworkPolicy':
                self.syntax_error('A GlobalNetworkPolicy should not have a namespace', metadata)
            self.namespace = self.peer_container.get_namespace(metadata['namespace'])
        else:
            if kind == 'NetworkPolicy':
                self.namespace = self.peer_container.get_namespace('default')
        res_policy = CalicoNetworkPolicy(metadata['name'], self.namespace)

        policy_spec = self.policy['spec']
        self._set_affects_ingress_egress(policy_spec, is_profile, res_policy)
        self._set_selected_peers(policy_spec, is_profile, res_policy)
        res_policy.order = policy_spec.get('order')
        if res_policy.order and is_profile:
            self.syntax_error('order is not allowed in the spec of a Profile', policy_spec)

        for ingress_rule in policy_spec.get('ingress', []):
            rule = self._parse_xgress_rule(ingress_rule, True, res_policy.selected_peers, is_profile)
            res_policy.add_ingress_rule(rule)

        for egress_rule in policy_spec.get('egress', []):
            rule = self._parse_xgress_rule(egress_rule, False, res_policy.selected_peers, is_profile)
            res_policy.add_egress_rule(rule)

        self._apply_extra_labels(policy_spec, is_profile, res_policy.name)
        res_policy.findings = self.warning_msgs
        res_policy.referenced_labels = self.referenced_labels
        return res_policy
