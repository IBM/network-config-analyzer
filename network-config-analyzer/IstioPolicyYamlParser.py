#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import re
from GenericYamlParser import GenericYamlParser
from IstioNetworkPolicy import IstioNetworkPolicy, IstioPolicyRule
from Peer import IpBlock, PeerSet
from PeerContainer import PeerContainer
from ConnectionSet import ConnectionSet
from PortSet import PortSetPair, PortSet
from MultiLayerPropertiesSet import RequestAttrs, MultiLayerPropertiesSet


class IstioPolicyYamlParser(GenericYamlParser):
    """
    A parser for Istio AuthorizationPolicy objects
    """

    # TODO: root_namespace should be configurable from istio configuration, currently using default value for it
    # If namespace is set to root namespace, the policy applies to all namespaces in a mesh
    root_namespace = 'istio-config'

    def __init__(self, policy, peer_container, policy_file_name=''):
        """
        :param dict policy: The policy object as provided by the yaml parser
        :param PeerContainer peer_container: The policy will be evaluated against this set of peers
        :param str policy_file_name: The name of the file in which the policy resides
        """
        GenericYamlParser.__init__(self, policy_file_name)
        self.policy = policy
        self.peer_container = peer_container
        # TODO: is this relevant for istio? (default namespace ?)
        self.namespace = peer_container.get_namespace('default')  # value to be replaced if the netpol has ns defined
        self.allowed_labels = set()

    def parse_label_selector(self, label_selector):
        """
        Parse a LabelSelector element
        :param dict label_selector: The element to parse
        :return: A PeerSet containing all the pods captured by this selection
        :rtype: Peer.PeerSet
        """
        if label_selector is None:
            return PeerSet()  # A None value means the selector selects nothing
        if not label_selector:
            return self.peer_container.get_all_peers_group()  # An empty value means the selector selects everything

        allowed_elements = {'matchLabels': [0, dict]}
        self.check_fields_validity(label_selector, 'authorization policy WorkloadSelector', allowed_elements)

        res = self.peer_container.get_all_peers_group()
        match_labels = label_selector.get('matchLabels')
        if match_labels:
            for key, val in match_labels.items():
                res &= self.peer_container.get_peers_with_label(key, [val])
            self.allowed_labels.add(':'.join(match_labels.keys()))

        if not res:
            self.warning('A podSelector selects no pods. Better use "podSelector: Null"', label_selector)

        return res

    def parse_ns_str(self, ns):
        """
        parse a namespace string from source component in rule
        :param ns: the namespace string
        :return: PeerSet: All pods in the namespace ns
        """
        # TODO: value matching should be extended to regular expressions patterns
        # TODO: when supporting this, can add validation that * is only used as prefix/suffix
        if '*' in ns:
            self.syntax_error(
                'error parsing namespace regular expr: currently not supporting prefix/suffix patterns ', ns)
        ns_obj = self.peer_container.get_namespace(ns)
        return self.peer_container.get_namespace_pods(ns_obj)

    def parse_principal_str(self, principal):
        """
        parse a principal string from source component in rule
        :param principal: the principal string, currently assuming in format: "cluster.local/ns/<ns-str>/sa/<sa-str>"
        :return: PeerSet: All pods with the given ns + sa_name as extracted from principal str
        """
        if '*' in principal:
            self.syntax_error(
                'error parsing principal regular expr: currently not supporting prefix/suffix patterns ', principal)
        # principal_str_example = "cluster.local/ns/default/sa/sleep"
        # TODO: support a more general pattern for principal str (prefix by istio trust-domain)
        # TODO: tighter checks in parsing the principal str
        principal_pattern = 'cluster.local/ns/([\w-]+)/sa/([\w-]+)'
        match = re.search(principal_pattern, principal)
        if match:
            ns = match.group(1)
            sa_name = match.group(2)
            return self.peer_container.get_pods_with_service_account_name(sa_name, ns)
        self.syntax_error(f'error parsing principal str: {principal}')

    def parse_principals(self, principals_list, not_principals_list):
        """
        Parse a principals element (within a source component of a rule)
        :param principals_list: list[str]  list of principals patterns/strings
        :param not_principals_list: list[str]  negative list of principals patterns/strings
        :return: A PeerSet containing the relevant pods
        :rtype: Peer.PeerSet
        """
        res = PeerSet() if principals_list is not None else self.peer_container.get_all_peers_group()
        for principal in principals_list or []:
            res |= self.parse_principal_str(principal)
        for principal in not_principals_list or []:
            res -= self.parse_principal_str(principal)
        return res

    def parse_namespaces(self, ns_list, not_ns_list):
        """
        Parse a namespaces element (within a source component of a rule)
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
            res |= self.parse_ns_str(ns)
        for ns in not_ns_list:
            res -= self.parse_ns_str(ns)
        return res

    @staticmethod
    def parse_ip_block(ips_list, not_ips_list):
        """
        parse ipBlocks elements (within a source component of a rule)
        :param list[str] ips_list: list of ip-block addresses (either ip address or ip-block cidr)
        :param list[str] not_ips_list: negative list of ip-block addresses (either ip address or ip-block cidr)
        :return: A PeerSet containing the relevant IpBlocks
        :rtype: Peer.PeerSet
        """
        ips_list = ['0.0.0.0/0'] if ips_list is None else ips_list  # If not set, any IP is allowed
        not_ips_list = [] if not_ips_list is None else not_ips_list
        res_ip_block = IpBlock()
        for cidr in ips_list:
            res_ip_block |= IpBlock(cidr)
        for cidr in not_ips_list:
            res_ip_block -= IpBlock(cidr)
        return res_ip_block.split()

    def parse_port(self, port):
        """
        :param port: string of a port number
        :return: ConnectionSet object with TCP restricted to the given port
        :rtype: ConnectionSet
        """
        res = ConnectionSet()
        try:
            port_num = int(port)
            if port_num > 65535:
                self.syntax_error(f"invalid port number: {str(port_num)}")
            dest_port_set = PortSet()
            dest_port_set.add_port(port_num)
            # istio doesn't reason about src ports
            properties = MultiLayerPropertiesSet(PortSetPair(PortSet(True), dest_port_set))
            res.add_connections('TCP', properties)  # istio currently supports TCP only

        except ValueError:
            self.syntax_error('error parsing port ', port)
        return res

    def parse_ports_list(self, ports_list, not_ports_list):
        """
        :param list[str]  ports_list: list of strings for port numbers
        :param list[str]  not_ports_list: negative list of strings for port numbers
        :return: ConnectionSet object with relevant TCP connections
        :rtype: ConnectionSet
        """
        connections = ConnectionSet()
        if ports_list is None:  # If not set, any port is allowed.
            connections = ConnectionSet.get_all_TCP_connections()
        else:
            for port in ports_list:
                connections |= self.parse_port(port)
        for port in not_ports_list or []:
            connections -= self.parse_port(port)
        return connections

    def validate_methods_list(self, methods):
        if methods and not set(methods).issubset(RequestAttrs.http_methods):
            self.syntax_error(f"error parsing method: invalid method in to.operation: {methods}")

    def parse_methods_list(self, methods_list, not_methods_list):
        """
        Parse methods and notMethods elements (within an operation component of a rule)
        :param methods_list: list[str]  list of methods
        :param not_methods_list: list[str]  negative list of methods
        :return: A ConnectionSet object with allowed connections
        :rtype: ConnectionSet
        """
        self.validate_methods_list(methods_list)
        self.validate_methods_list(not_methods_list)
        request_attributes = RequestAttrs(True)
        request_attributes.set_methods(methods_list, not_methods_list)
        properties = MultiLayerPropertiesSet(PortSetPair(PortSet(True), PortSet(True)), request_attributes)

        res = ConnectionSet()
        res.add_connections('TCP', properties)
        return res

    def validate_paths_list(self, paths):
        pass    # ToDo validating legal url paths
        # self.syntax_error(f"error parsing paths: invalid path in to.operation: {paths}")

    def validate_hosts_list(self, hosts):
        pass    # ToDo validating legal hosts
        # self.syntax_error(f"error parsing hosts: invalid path in to.operation: {hosts}")

    def parse_paths_list(self, paths_list, not_paths_list):
        """
        Parse paths and notPaths elements (within an operation component of a rule)
        :param paths_list: list[str]  list of paths
        :param not_paths_list: list[str]  negative list of paths
        :return: A ConnectionSet object with allowed connections
        :rtype: ConnectionSet
        """
        self.validate_paths_list(paths_list)
        self.validate_paths_list(not_paths_list)
        request_attributes = RequestAttrs(True)
        request_attributes.set_paths(paths_list, not_paths_list)
        properties = MultiLayerPropertiesSet(PortSetPair(PortSet(True), PortSet(True)), request_attributes)

        res = ConnectionSet()
        res.add_connections('TCP', properties)
        return res

    def parse_hosts_list(self, hosts_list, not_hosts_list):
        """
        Parse hosts and notHosts elements (within an operation component of a rule)
        :param hosts_list: list[str]  list of hosts
        :param not_hosts_list: list[str]  negative list of hosts
        :return: A ConnectionSet object with allowed connections
        :rtype: ConnectionSet
        """
        self.validate_hosts_list(hosts_list)
        self.validate_hosts_list(not_hosts_list)
        request_attributes = RequestAttrs(True)
        request_attributes.set_hosts(hosts_list, not_hosts_list)
        properties = MultiLayerPropertiesSet(PortSetPair(PortSet(True), PortSet(True)), request_attributes)

        res = ConnectionSet()
        res.add_connections('TCP', properties)
        return res

    def parse_key_values(self, key, values, not_values):
        """
        parse key and its values for a given condition component in a rule
        :param string key: the specified key str
        :param values: a list of strings with values for this key
        :param not_values: a list of strings with negative values for this key
        :return: PeerSet or ConnectionSet (depends on the key) with allowed values
        """
        if key == 'source.ip':
            return self.parse_ip_block(values, not_values)  # PeerSet
        elif key == 'source.namespace':
            return self.parse_namespaces(values, not_values)  # PeerSet
        elif key == 'source.principal':
            return self.parse_principals(values, not_values)  # PeerSet
        elif key == 'destination.port':
            return self.parse_ports_list(values, not_values)  # ConnectionSet
        return NotImplemented, False

    def parse_condition(self, condition):
        """
        parse a condition component in a rule
        :param dict condition: the condition to parse
        :return: PeerSet or ConnectionSet (depends on the key) with allowed values
        """
        allowed_elements = {'key': [1, str], 'values': [0, list], 'notValues': [0, list]}
        allowed_key_values = {'key': ['source.ip', 'source.namespace', 'source.principal', 'destination.port']}
        # https://istio.io/latest/docs/reference/config/security/conditions/
        # TODO: support additional key values: request.headers, remote.ip, request.auth.principal,
        #  request.auth.audiences, request.auth.presenter, request.auth.claims, destination.ip, connection.sni
        self.check_fields_validity(condition, 'authorization policy condition', allowed_elements, allowed_key_values)
        for key_elem in allowed_elements.keys():
            self.validate_existing_key_is_not_null(condition, key_elem)

        key = condition.get('key')
        values = condition.get('values')
        not_values = condition.get('notValues')
        if not values and not not_values:
            self.syntax_error('error parsing condition: at least one of values or not_values must be set. ', condition)

        return self.parse_key_values(key, values, not_values)  # PeerSet or ConnectionSet

    def parse_operation(self, operation_dict):
        """
        parse an operation component in a rule
        :param dict operation_dict: the operation to parse
        :return: ConnectionSet object with allowed connections
        :rtype: ConnectionSet
        """

        to_allowed_elements = {'operation': [1, dict]}
        self.check_fields_validity(operation_dict, 'authorization policy rule: to', to_allowed_elements)

        operation = operation_dict.get('operation')
        if operation is None:
            self.syntax_error('Authorization policy to.operation cannot be null. ')

        allowed_elements = {'ports': [0, list], 'notPorts': [0, list], 'hosts': 2, 'notHosts': 2, 'methods': [0, list],
                            'notMethods': [0, list], 'paths': [0, list], 'notPaths': [0, list], 'hosts': [0, list], 'notHosts': [0, list]}
        self.check_fields_validity(operation, 'authorization policy operation', allowed_elements)
        for key_elem in allowed_elements.keys():
            self.validate_existing_key_is_not_null(operation, key_elem)
        self.validate_dict_elem_has_non_empty_array_value(operation, 'to.operation')

        connections = ConnectionSet(True)

        ports_list = operation.get('ports')
        not_ports_list = operation.get('notPorts')
        connections &= self.parse_ports_list(ports_list, not_ports_list)

        methods_list = operation.get('methods')
        not_methods_list = operation.get('notMethods')
        if methods_list is not None or not_methods_list is not None:
            connections &= self.parse_methods_list(methods_list, not_methods_list)

        paths_list = operation.get('paths')
        not_paths_list = operation.get('notPaths')

        if paths_list is not None or not_paths_list is not None:
            connections &= self.parse_paths_list(paths_list, not_paths_list)

        hosts_list = operation.get('hosts')
        not_hosts_list = operation.get('notHosts')

        if hosts_list is not None or not_hosts_list is not None:
            connections &= self.parse_hosts_list(hosts_list, not_hosts_list)

        return connections

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
                            'notIpBlocks': [0, list], 'principals': [0, list], 'notPrincipals': [0, list], 'requestPrincipals': 2,
                            'notRequestPrincipals': 2, 'remoteIpBlocks': 2, 'notRemoteIpBlocks': 2}
        # TODO: though specified 'list' value_type, check_fields_validity doesn't fail since value is None (empty)...
        self.check_fields_validity(source_peer, 'authorization policy rule: source', allowed_elements)
        for key_elem in allowed_elements.keys():
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
    def parse_ingress_rule(self, rule):
        """
        Parse a single ingress rule, producing a IstioPolicyRule.
        :param dict rule: The dict with the rule fields
        :return: A IstioPolicyRule with the proper PeerSet and ConnectionSet
        :rtype: IstioPolicyRule
        """
        if rule is None:
            self.syntax_error('Authorization policy rule cannot be null. ')

        allowed_elements = {'from': [0, list], 'to': [0, list], 'when': [0, list]}
        self.check_fields_validity(rule, 'authorization policy rule', allowed_elements)
        for key_elem in allowed_elements.keys():
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
        if to_array is not None:
            connections = ConnectionSet()
            for operation_dict in to_array:
                connections |= self.parse_operation(operation_dict)
        else:  # no 'to' in the rule => all connections allowed
            connections = ConnectionSet(True)

        # condition possible result value: source-ip (from) , source-namespace (from) [Peerset], dstination.port (to) [ConnectionSet]
        # should update either res_pods or connections according to the condition
        condition_array = rule.get('when')  # this array can be empty (unlike 'to' and 'from')
        # the combined condition ("AND" of all conditions) should be applied
        if condition_array is not None:
            for condition in condition_array:
                condition_res = self.parse_condition(condition)
                if isinstance(condition_res, PeerSet):
                    res_peers &= condition_res
                elif isinstance(condition_res, ConnectionSet):
                    connections &= condition_res

        if not res_peers:
            self.warning('Rule selects no pods', rule)

        return IstioPolicyRule(res_peers, connections)

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
        :return: a IstioNetworkPolicy object with proper PeerSets and ConnectionSets
        :rtype: IstioNetworkPolicy
        """
        if not isinstance(self.policy, dict):
            self.syntax_error('Top ds is not a map')
        if self.policy.get('kind') != 'AuthorizationPolicy':
            return None  # Not a AuthorizationPolicy object
        api_version = self.policy.get('apiVersion', self.policy.get('api_version', ''))
        if not api_version:
            self.syntax_error('An object with no specified apiVersion', self.policy)
        if 'istio' not in api_version:
            return None  # apiVersion is not properly set
        if api_version not in ['security.istio.io/v1beta1']:
            raise Exception('Unsupported apiVersion: ' + api_version)
        self.check_fields_validity(self.policy, 'AuthorizationPolicy', {'kind': 1, 'metadata': 1, 'spec': 1,
                                                                        'apiVersion': 0, 'api_version': 0})
        if 'name' not in self.policy['metadata']:
            self.syntax_error('AuthorizationPolicy has no name', self.policy)
        # TODO: what if namespace is not specified in istio policy?
        if 'namespace' in self.policy['metadata']:
            self.namespace = self.peer_container.get_namespace(self.policy['metadata']['namespace'])

        res_policy = IstioNetworkPolicy(self.policy['metadata']['name'], self.namespace)

        policy_spec = self.policy['spec']
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
        if pod_selector is None:
            res_policy.selected_peers = self.peer_container.get_all_peers_group()
        else:
            res_policy.selected_peers = self.parse_label_selector(pod_selector)
        # if policy's namespace is the root namespace, then it applies to all cluster's namespaces
        if self.namespace.name != IstioPolicyYamlParser.root_namespace:
            res_policy.selected_peers &= self.peer_container.get_namespace_pods(self.namespace)
        for ingress_rule in policy_spec.get('rules', []):
            res_policy.add_ingress_rule(self.parse_ingress_rule(ingress_rule))
        if not res_policy.ingress_rules and res_policy.action == IstioNetworkPolicy.ActionType.Deny:
            self.syntax_error("DENY action without rules is meaningless as it will never be triggered")

        res_policy.findings = self.warning_msgs

        return res_policy
