#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import re

from nca.CoreDS.MinDFA import MinDFA
from nca.CoreDS.DimensionsManager import DimensionsManager
from nca.CoreDS.Peer import IpBlock, PeerSet
from nca.CoreDS.PortSet import PortSet
from nca.CoreDS.ProtocolSet import ProtocolSet
from nca.CoreDS.MethodSet import MethodSet
from nca.CoreDS.ConnectivityProperties import ConnectivityProperties
from nca.Resources.PolicyResources.IstioNetworkPolicy import IstioNetworkPolicy, IstioPolicyRule
from nca.Parsers.IstioGenericYamlParser import istio_root_namespace
from nca.Resources.PolicyResources.NetworkPolicy import NetworkPolicy
from .IstioGenericYamlParser import IstioGenericYamlParser


class IstioPolicyYamlParser(IstioGenericYamlParser):
    """
    A parser for Istio AuthorizationPolicy objects
    """

    def _validate_istio_regex_pattern(self, regex_str):
        """
        validate input regex str is supported by istio authorization policies.
        raise syntax error if invalid.
        :param str regex_str: the input regex str to validate
        """
        if '*' in regex_str:
            if not (regex_str.count('*') == 1 and (regex_str.startswith('*') or regex_str.endswith('*'))):
                self.syntax_error(f'Illegal str value pattern: {regex_str}')

    def _get_all_principals_str_list_from_topology(self):
        """
        Return all pods listed as principals strings in the format :
        cluster.local/ns/{pod.namespace}/sa/{pod.service_account_name}
        :rtype: list[str]
        """
        all_pods = self.peer_container.get_all_peers_group()
        res = []
        for peer in all_pods:
            res.append(f"cluster.local/ns/{peer.namespace}/sa/{peer.service_account_name}")
        return res

    def _parse_istio_regex_from_enumerated_domain(self, regex_str, field_name):
        """
        get the list of matching enumerated domain values for an input regex str.
        value matching for istio regex: https://istio.io/latest/docs/concepts/security/#value-matching
        :param str regex_str: the input regex str
        :param str field_name: the relevant field with enumerated domain (namespaces/principals/methods)
        :return: the list of matching values
        :rtype: list[str]
        """
        self._validate_istio_regex_pattern(regex_str)
        values_list = []
        if field_name == 'namespaces':
            values_list = self.peer_container.get_all_namespaces_str_list()
        elif field_name == 'principals':
            values_list = self._get_all_principals_str_list_from_topology()
        elif field_name == 'methods':
            values_list = MethodSet.all_methods_list

        if '*' not in regex_str:  # exact match
            return [regex_str] if regex_str in values_list else []
        elif regex_str == '*':  # presence match
            return values_list
        elif regex_str.startswith('*'):  # Suffix match
            required_suffix = regex_str[1:]
            return [val for val in values_list if val.endswith(required_suffix)]
        elif regex_str.endswith('*'):  # Prefix match
            required_prefix = regex_str[:-1]
            return [val for val in values_list if val.startswith(required_prefix)]
        return []

    def _parse_ns_str(self, ns):
        """
        parse a namespace string from source component in rule
        :param str ns: the namespace string
        :return: PeerSet: All pods in the namespace ns
        """
        ns_str_values = self._parse_istio_regex_from_enumerated_domain(ns, 'namespaces')
        res = PeerSet()
        if not ns_str_values:
            self.warning(f"no match for namespace: {ns}")
        for ns_str in ns_str_values:
            ns_obj = self.peer_container.get_namespace(ns_str)
            res |= self.peer_container.get_namespace_pods(ns_obj)
        return res

    @staticmethod
    def _get_principal_str_components(principal_str):
        """
        get the namespace and service account values from a principal str
        :param str principal_str: the principal str
        :return: the namespace and service account str values
        """
        ns = None
        sa_name = None
        # TODO: support a more general pattern for principal str (prefix by istio trust-domain)
        #  current supported format example:  "cluster.local/ns/default/sa/sleep"
        #  example for more general format: "spiffe://mytrustdomain.com/ns/default/sa/myname"
        principal_pattern = 'cluster.local/ns/([\\w-]+)/sa/([\\w-]+)'
        match = re.search(principal_pattern, principal_str)
        if match:
            ns = match.group(1)
            sa_name = match.group(2)
        return ns, sa_name

    def _parse_principal_str(self, principal, principals_list):
        """
        parse a principal string from source component in rule
        :param str principal: the principal str, currently assuming in format: "cluster.local/ns/<ns-str>/sa/<sa-str>"
        :param list principals_list: The principals object (for reporting warnings)
        :return: PeerSet: All pods with the given ns + sa_name as extracted from principal str
        """
        principal_str_values = self._parse_istio_regex_from_enumerated_domain(principal, 'principals')
        res = PeerSet()
        if not principal_str_values:
            self.warning(f"no match for principal: {principal}", principals_list)
        for principal_str in principal_str_values:
            ns, sa_name = self._get_principal_str_components(principal_str)
            if ns and sa_name:
                res |= self.peer_container.get_pods_with_service_account_name(sa_name, ns)
        return res

    def parse_principals(self, principals_list, not_principals_list):
        """
        Parse a principals element (within a source component of  a rule)
        :param list[str] principals_list: list of principals patterns/strings
        :param list[str] not_principals_list: negative list of principals patterns/strings
        :return: A PeerSet containing the relevant pods
        :rtype: Peer.PeerSet
        """
        res = PeerSet() if principals_list is not None else self.peer_container.get_all_peers_group()
        for principal in principals_list or []:
            res |= self._parse_principal_str(principal, principals_list)
        for principal in not_principals_list or []:
            res -= self._parse_principal_str(principal, not_principals_list)
        return res

    def parse_namespaces(self, ns_list, not_ns_list):
        """
        Parse a namespaces element (within a source component of  a rule)
        :param list[str] ns_list: list of namespaces patterns/strings
        :param list[str] not_ns_list: negative list of namespaces patterns/strings
        :return: A PeerSet containing the relevant pods
        :rtype: Peer.PeerSet
        """
        # If 'namespaces' not set, any namespace is allowed.
        ns_list = self.peer_container.get_all_namespaces_str_list() if ns_list is None else ns_list
        not_ns_list = [] if not_ns_list is None else not_ns_list
        res = PeerSet()
        for ns in ns_list:
            res |= self._parse_ns_str(ns)
        for ns in not_ns_list:
            res -= self._parse_ns_str(ns)
        return res

    def parse_ip_block(self, ips_list, not_ips_list):
        """
        parse ipBlocks elements (within a source component of  a rule)
        :param list[str] ips_list: list of ip-block addresses (either ip address or ip-block cidr)
        :param list[str] not_ips_list: negative list of ip-block addresses (either ip address or ip-block cidr)
        :return: A PeerSet containing the relevant IpBlocks
        :rtype: Peer.PeerSet
        """
        ips_list = IpBlock.get_all_ips_block() if ips_list is None else ips_list  # If not set, any IP is allowed
        not_ips_list = [] if not_ips_list is None else not_ips_list
        res_ip_block = IpBlock()
        for cidr in ips_list:
            res_ip_block |= IpBlock(cidr)
        for cidr in not_ips_list:
            res_ip_block -= IpBlock(cidr)
        res_peer_set = res_ip_block.split()
        if not self.has_ipv6_addresses:  # if already true, means a previous rule already had ipv6
            # and then policy has ipv6 no need for more checks
            self.check_and_update_has_ipv6_addresses(res_peer_set)
        return res_peer_set

    def parse_key_values(self, key, values, not_values):
        """
        parse key and its values for a given condition component in a rule
        :param str key: the specified key str
        :param list values: a list of strings with values for this key
        :param list not_values: a list of strings with negative values for this key
        :return: PeerSet or ConnectivityProperties (depends on the key) with allowed values
        """
        if key == 'source.ip':
            return self.parse_ip_block(values, not_values)  # PeerSet
        elif key == 'source.namespace':
            return self.parse_namespaces(values, not_values)  # PeerSet
        elif key == 'source.principal':
            return self.parse_principals(values, not_values)  # PeerSet
        elif key == 'destination.port':
            dst_ports = self.get_rule_ports(values, not_values)  # PortSet
            return ConnectivityProperties.make_conn_props_from_dict({"dst_ports": dst_ports})
        return NotImplemented, False

    def parse_condition(self, condition):
        """
        parse a condition component in a rule
        :param dict condition: the condition to parse
        :return: PeerSet or ConnectivityProperties (depends on the key) with allowed values
        """
        allowed_elements = {'key': [1, str], 'values': [0, list], 'notValues': [0, list]}
        allowed_key_values = {'key': ['source.ip', 'source.namespace', 'source.principal', 'destination.port']}
        # https://istio.io/latest/docs/reference/config/security/conditions/
        # TODO: support additional key values: request.headers, remote.ip, request.auth.principal,
        #  request.auth.audiences, request.auth.presenter, request.auth.claims, destination.ip, connection.sni
        self.check_fields_validity(condition, 'authorization policy condition', allowed_elements, allowed_key_values)
        for key_elem in allowed_elements:
            self.validate_existing_key_is_not_null(condition, key_elem)

        key = condition.get('key')
        values = condition.get('values')
        not_values = condition.get('notValues')
        if not values and not not_values:
            self.syntax_error('error parsing condition: at least one of values or not_values must be set. ', condition)

        return self.parse_key_values(key, values, not_values)  # PeerSet or ConnectivityProperties

    # TODO: avoid code duplication with Calico version...
    def _parse_port(self, port, array):
        """
        Parse a single port in the array defined in the ports/notPorts part
        :param Union[int,str] port: The port to parse
        :param list array: The object containing the port (for reporting errors)
        :return: The set of ports defined by port
        :rtype: PortSet
        """
        res_port_set = PortSet()
        try:
            port_num = port if isinstance(port, int) else int(port)
        except ValueError:
            self.syntax_error('error parsing port ', port)
            return None
        self.validate_value_in_domain(port_num, 'dst_ports', array, 'Port number')
        res_port_set.add_port(port_num)
        return res_port_set

    # TODO: avoid code duplication with Calico version...
    def get_rule_ports(self, ports_array, not_ports_array):
        """
        Parse the port-related parts
        :param list ports_array: a positive ports list
        :param list not_ports_array: a negative ports list
        :return: The ports that are specified by ports/notPorts
        :rtype: PortSet
        """
        if ports_array is not None:
            rule_ports = PortSet()
            for port in ports_array:
                rule_ports |= self._parse_port(port, ports_array)
        else:
            rule_ports = PortSet(True)

        if not_ports_array is not None:
            for port in not_ports_array:
                rule_ports -= self._parse_port(port, not_ports_array)

        return rule_ports

    def _parse_str_value(self, str_val_input, dim_name, operation):
        """
        transform input regex/str to the format supported by greenery
        :param str str_val_input: the str/regex from input
        :param str dim_name: the name of the dimension of str_val_input value
        :param dict operation: the operation object being parsed
        :return: str: the result regex/str after conversion
        """
        allowed_chars = "[" + MinDFA.default_dfa_alphabet_chars + "]"
        allowed_chars_with_star_regex = "[*" + MinDFA.default_dfa_alphabet_chars + "]*"
        if not re.fullmatch(allowed_chars_with_star_regex, str_val_input):
            self.syntax_error(f'Illegal characters in {dim_name} {str_val_input} in {operation}')

        # convert str_val_input into regex format supported by greenery
        res = str_val_input.replace(".", "[.]")
        if '*' in res:
            self._validate_istio_regex_pattern(res)
            if res == '*':  # presence match
                res = allowed_chars + "+"  # non-empty string of allowed chars
            elif res.startswith('*') or res.endswith('*'):  # prefix/suffix match
                res = res.replace("*", allowed_chars + '*')
        return res

    def get_values_list_regex(self, values_list, dim_name, operation):
        """
        Given a list of regex str values, return one regex for the entire list (or between all its elements).
        (the goal is to minimize the number of calls to dfa_from_regex).
        :param list[str] values_list: a list of str values, each is a regex
        :param dtr dim_name: the name of the dimension to which values_list belongs
        :param dict operation: the operation object being parsed
        :return: str: the result regex str
        """
        assert len(values_list) > 0
        return '|'.join(self._parse_str_value(str_value, dim_name, operation) for str_value in values_list)

    def parse_regex_dimension_values(self, dim_name, values_list, negative_values_list, operation_dict):
        """
        for dimension of type MinDFA -> return a MinDFA or None for all values
        :param str dim_name: dimension name
        :param list[str] values_list: positive regex values list
        :param list[str] negative_values_list: negative regex values list
        :param dict operation_dict: the parsed operation dict object
        :return: Union[MinDFA, None] object
        """
        dimensions_manager = DimensionsManager()
        dim_type = dimensions_manager.get_dimension_type_by_name(dim_name)
        assert dim_type == DimensionsManager.DimensionType.DFA
        entire_domain_dfa = dimensions_manager.get_dimension_domain_by_name(dim_name)

        if values_list is None and negative_values_list is None:
            return None  # to represent that all is allowed, and this dimension can be inactive in the generated cube
        if values_list is not None:
            positive_regex = self.get_values_list_regex(values_list, dim_name, operation_dict)
            values_dfa = MinDFA.dfa_from_regex(positive_regex)
        else:
            values_dfa = entire_domain_dfa

        if negative_values_list is None:
            return values_dfa
        negative_regex = self.get_values_list_regex(negative_values_list, dim_name, operation_dict)
        negative_values_dfa = MinDFA.dfa_from_regex(negative_regex)
        res = values_dfa - negative_values_dfa
        if not res:
            # adding a warning for empty dfa, which implies empty connection set for this rule's operation
            self.warning(f'Empty values for {dim_name} within operation', operation_dict)
        return res

    def _parse_method(self, method_str, operation):
        """
        parse a method component in a rule operation
        :param str method_str: the method to parse
        :param dict operation: the operation object being parsed
        :return: MethodSet object holding parsed methods
        """
        res = MethodSet()
        matching_methods = self._parse_istio_regex_from_enumerated_domain(method_str, 'methods')
        for method in matching_methods:
            res.add_method(method)

        if not res:
            if method_str:
                self.warning("Illegal method '" + method_str + "' ignored", operation)
            self.warning("Empty values for methods", operation)
        return res

    def _get_methods_set(self, operation):
        """
        get methods on a rule operation
        :param dict operation: the operation containing 'methods' and 'notMethods' properties
        :return: MethodSet object holding methods of the operation
        """
        methods_array = operation.get('methods')
        if methods_array is not None:
            rule_methods = MethodSet()
            for method_str in methods_array:
                rule_methods |= self._parse_method(method_str, operation)
        else:
            rule_methods = MethodSet(True)

        not_methods_array = operation.get('notMethods')
        if not_methods_array is not None:
            for method_str in not_methods_array:
                rule_methods -= self._parse_method(method_str, operation)

        return rule_methods

    def parse_operation(self, operation_dict):
        """
        parse an operation component in a rule
        :param dict operation_dict: the operation to parse
        :return: ConnectivityProperties object with allowed connections
        """

        to_allowed_elements = {'operation': [1, dict]}
        self.check_fields_validity(operation_dict, 'authorization policy rule: to', to_allowed_elements)

        operation = operation_dict.get('operation')
        if operation is None:
            self.syntax_error('Authorization policy to.operation cannot be null. ')

        # TODO: Add support for hosts, methods, paths
        allowed_elements = {'ports': [0, list], 'notPorts': [0, list], 'hosts': [0, list], 'notHosts': [0, list],
                            'methods': [0, list],
                            'notMethods': [0, list], 'paths': [0, list], 'notPaths': [0, list]}
        self.check_fields_validity(operation, 'authorization policy operation', allowed_elements)
        for key_elem in allowed_elements:
            self.validate_existing_key_is_not_null(operation, key_elem)
        self.validate_dict_elem_has_non_empty_array_value(operation, 'to.operation')

        dst_ports = self.get_rule_ports(operation.get('ports'), operation.get('notPorts'))  # PortSet
        methods_set = self._get_methods_set(operation)
        paths_dfa = self.parse_regex_dimension_values("paths", operation.get("paths"), operation.get("notPaths"),
                                                      operation)
        hosts_dfa = self.parse_regex_dimension_values("hosts", operation.get("hosts"), operation.get("notHosts"),
                                                      operation)
        return ConnectivityProperties.make_conn_props_from_dict({"dst_ports": dst_ports, "methods": methods_set,
                                                                 "paths": paths_dfa, "hosts": hosts_dfa})

    def parse_source(self, source_dict):
        """
        Parse a source peer inside a rule (an element of the 'from' array)
        :param dict source_dict: The object to parse
        :return: A PeerSet object containing the set of peers defined by the selectors/ipblocks
        :rtype: Peer.PeerSet
        """

        from_allowed_elements = {'source': [1, dict]}
        self.check_fields_validity(source_dict, 'authorization policy rule: from', from_allowed_elements)

        source_peer = source_dict.get('source')
        if source_peer is None:
            self.syntax_error('Authorization policy from.source cannot be null. ')

        # TODO: support source with multiple attributes ("fields in the source are ANDed together")
        # TODO: add support for allowed elements currently unsupported (principals, requestPrincipals, remoteIpBlocks)
        allowed_elements = {'namespaces': [0, list], 'notNamespaces': [0, list], 'ipBlocks': [0, list],
                            'notIpBlocks': [0, list], 'principals': [0, list], 'notPrincipals': [0, list],
                            'requestPrincipals': 2,
                            'notRequestPrincipals': 2, 'remoteIpBlocks': 2, 'notRemoteIpBlocks': 2}
        # TODO: though specified 'list' value_type, check_fields_validity doesn't fail since value is None (empty)...
        self.check_fields_validity(source_peer, 'authorization policy rule: source', allowed_elements)
        for key_elem in allowed_elements:
            self.validate_existing_key_is_not_null(source_peer, key_elem)
        self.validate_dict_elem_has_non_empty_array_value(source_peer, 'from.source')

        has_ns = 'namespaces' in source_peer or 'notNamespaces' in source_peer
        has_ip = 'ipBlocks' in source_peer or 'notIpBlocks' in source_peer
        has_principals = 'principals' in source_peer or 'notPrincipals' in source_peer

        # TODO: how to support a source peer with both namespace and ip-block properties?
        #  currently assuming ip-block is only outside the cluster
        if has_ip and (has_principals or has_ns):
            self.warning('currently not supporting source with both namespaces/principals and ip block')
            # TODO: should return empty peerSet if has requirements of both ns and ip-block ?
            return PeerSet()

        res = self.peer_container.get_all_peers_group(True)

        if has_principals:
            principals_list = source_peer.get('principals')
            not_principals_list = source_peer.get('notPrincipals')
            res &= self.parse_principals(principals_list, not_principals_list)

        if has_ns:
            ns_list = source_peer.get('namespaces')
            not_ns_list = source_peer.get('notNamespaces')
            res &= self.parse_namespaces(ns_list, not_ns_list)

        elif has_ip:
            ip_blocks = source_peer.get('ipBlocks')
            not_ip_blocks = source_peer.get('notIpBlocks')
            res &= self.parse_ip_block(ip_blocks, not_ip_blocks)

        return res

    #  A match occurs when at least one source, one operation and all conditions matches the request
    # https://istio.io/latest/docs/reference/config/security/authorization-policy/#Rule
    def parse_ingress_rule(self, rule, selected_peers):
        """
        Parse a single ingress rule, producing a IstioPolicyRule.
        :param dict rule: The dict with the rule fields
        :param PeerSet selected_peers: The selected peers of the policy
        :return: A tuple (IstioPolicyRule, ConnectivityProperties) with the proper PeerSet and connectivity properties
        :rtype: tuple(IstioPolicyRule, ConnectivityProperties)
        """
        if rule is None:
            self.syntax_error('Authorization policy rule cannot be null. ')

        allowed_elements = {'from': [0, list], 'to': [0, list], 'when': [0, list]}
        self.check_fields_validity(rule, 'authorization policy rule', allowed_elements)
        for key_elem in allowed_elements:
            self.validate_existing_key_is_not_null(rule, key_elem)

        # collect source peers into res_peers
        from_array = self.get_key_array_and_validate_not_empty(rule, 'from')
        if from_array is not None:
            res_peers = PeerSet()
            for source_dict in from_array:
                res_peers |= self.parse_source(source_dict)
        else:  # no 'from' in the rule => all source peers allowed
            res_peers = self.peer_container.get_all_peers_group(True)

        to_array = self.get_key_array_and_validate_not_empty(rule, 'to')
        # currently parsing only ports
        # TODO: extend operations parsing to include other attributes
        conn_props = ConnectivityProperties.make_empty_props()
        tcp_props = ConnectivityProperties.make_conn_props_from_dict(
            {"protocols": ProtocolSet.get_protocol_set_with_single_protocol('TCP')})
        if to_array is not None:
            for operation_dict in to_array:
                conn_props |= self.parse_operation(operation_dict)
            conn_props &= tcp_props
        else:  # no 'to' in the rule => all connections allowed
            conn_props = ConnectivityProperties.get_all_conns_props_per_config_peers(self.peer_container)

        # condition possible result value:
        #         source-ip (from) , source-namespace (from) [Peerset], destination.port (to) [ConnectivityProperties]
        # should update either res_pods or condition_props according to the condition
        condition_array = rule.get('when')  # this array can be empty (unlike 'to' and 'from')
        # the combined condition ("AND" of all conditions) should be applied
        condition_props = ConnectivityProperties.make_all_props()
        if condition_array is not None:
            for condition in condition_array:
                condition_res = self.parse_condition(condition)
                if isinstance(condition_res, PeerSet):
                    res_peers &= condition_res
                elif isinstance(condition_res, ConnectivityProperties):
                    condition_props &= condition_res
            condition_props &= tcp_props
        if not res_peers:
            self.warning('Rule selects no pods', rule)
        if not res_peers or not selected_peers:
            condition_props = ConnectivityProperties.make_empty_props()
        else:
            condition_props &= ConnectivityProperties.make_conn_props_from_dict({"src_peers": res_peers,
                                                                                 "dst_peers": selected_peers})
        conn_props &= condition_props
        return IstioPolicyRule(res_peers, conn_props)

    @staticmethod
    def parse_policy_action(action):
        """
        :param string action: the action to parse
        :return: IstioNetworkPolicy.ActionType Allow/Deny
        """
        if action == 'ALLOW':
            return IstioNetworkPolicy.ActionType.Allow
        elif action == "DENY":
            return IstioNetworkPolicy.ActionType.Deny
        return NotImplemented

    def parse_policy(self):
        """
        Parses the input object to create a IstioNetworkPolicy object
        :return: a IstioNetworkPolicy object with proper PeerSets and connectivity properties
        :rtype: IstioNetworkPolicy
        """
        policy_name, policy_ns = self.parse_generic_yaml_objects_fields(self.policy, ['AuthorizationPolicy'],
                                                                        ['security.istio.io/v1beta1', 'security.istio.io/v1'],
                                                                        'istio')
        if policy_name is None:
            return None  # not an Istio AuthorizationPolicy
        warn_if_missing = policy_ns != istio_root_namespace
        self.namespace = self.peer_container.get_namespace(policy_ns, warn_if_missing)
        res_policy = IstioNetworkPolicy(policy_name, self.namespace)
        res_policy.policy_kind = NetworkPolicy.PolicyType.IstioAuthorizationPolicy

        policy_spec = self.policy.get('spec')
        if policy_spec is None:
            self.warning('spec is missing or null in AuthorizationPolicy ' + res_policy.full_name())
            return res_policy
        # currently not supporting provider
        allowed_spec_keys = {'action': [0, str], 'rules': [0, list], 'selector': [0, dict], 'provider': 2}
        allowed_key_values = {'action': ['ALLOW', 'DENY']}
        self.check_fields_validity(policy_spec, 'istio authorization policy spec', allowed_spec_keys,
                                   allowed_key_values)

        action = policy_spec.get('action')
        if action:
            res_policy.action = self.parse_policy_action(action)
        res_policy.affects_ingress = True
        res_policy.affects_egress = False
        pod_selector = policy_spec.get('selector')
        res_policy.selected_peers = self.update_policy_peers(pod_selector, 'matchLabels')
        for ingress_rule in policy_spec.get('rules', []):
            rule = self.parse_ingress_rule(ingress_rule, res_policy.selected_peers)
            res_policy.add_ingress_rule(rule)
        if not res_policy.ingress_rules and res_policy.action == IstioNetworkPolicy.ActionType.Deny:
            self.syntax_error("DENY action without rules is meaningless as it will never be triggered")

        res_policy.findings = self.warning_msgs
        res_policy.referenced_labels = self.referenced_labels
        res_policy.has_ipv6_addresses = self.has_ipv6_addresses
        return res_policy
