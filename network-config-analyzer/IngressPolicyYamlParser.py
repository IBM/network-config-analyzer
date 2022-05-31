#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import re

from MinDFA import MinDFA
from DimensionsManager import DimensionsManager
from GenericYamlParser import GenericYamlParser
from IngressPolicy import IngressPolicy, IngressPolicyRule
from Peer import PeerSet, IpBlock
from PeerContainer import PeerContainer
from PortSet import PortSet
from MethodSet import MethodSet
from ConnectionSet import ConnectionSet
from TcpLikeProperties import TcpLikeProperties


class IngressPolicyYamlParser(GenericYamlParser):
    """
    A parser for Ingress objects
    """

    def __init__(self, policy, peer_container, ingress_file_name=''):
        """
        :param dict policy: The ingress policy object as provided by the yaml parser
        :param PeerContainer peer_container: The ingress policy will be evaluated against this set of peers
        :param str ingress_file_name: The name of the ingress resource file
        """
        GenericYamlParser.__init__(self, ingress_file_name)
        self.policy = policy
        self.peer_container = peer_container
        self.namespace = None
        self.default_backend_peers = PeerSet()
        self.default_backend_ports = PortSet()

    def validate_path_value(self, path_value, path):
        if path_value[0] != '/':
            self.syntax_error(f'Illegal path {path_value} in the rule path', path)
        pattern = "[" + DimensionsManager().default_dfa_alphabet_chars + "]*"
        if not re.fullmatch(pattern, path_value):
            self.syntax_error(f'Illegal characters in path {path_value} in {path}')

    def parse_regex_host_value(self, regex_value, rule):
        """
        for 'hosts' dimension of type MinDFA -> return a MinDFA, or None for all values
        :param str regex_value: input regex host value
        :param dict rule: the parsed rule object
        :return: Union[MinDFA, None] object
        """
        dim_type = DimensionsManager().get_dimension_type_by_name("hosts")
        assert dim_type == DimensionsManager.DimensionType.DFA

        if regex_value is None:
            return None  # to represent that all is allowed, and this dimension can be inactive in the generated cube

        allowed_chars = "[\\w]"
        allowed_chars_with_star_regex = "[*" + DimensionsManager().default_dfa_alphabet_chars + "]*"
        if not re.fullmatch(allowed_chars_with_star_regex, regex_value):
            self.syntax_error(f'Illegal characters in host {regex_value} in {rule}')

        # convert regex_value into regex format supported by greenery
        regex_value = regex_value.replace(".", "[.]")
        if '*' in regex_value:
            if not regex_value.startswith('*.'):
                self.syntax_error(f'Illegal host value pattern: {regex_value}')
            regex_value = regex_value.replace("*", allowed_chars + '*')
        return MinDFA.dfa_from_regex(regex_value)

    def parse_backend(self, backend, is_default=False):
        """
        Parses ingress backend and returns the set of pods and ports referenced by it.
        :param dict backend: the backend resource
        :param bool is_default: whether this is the default backend
        :return: a tuple PeerSet and PortSet: the sets of pods and ports referenced by the backend,
        or None and all ports when the default backend is None,
        or None and None when the non-default backend is None.
        """
        if backend is None:
            return (None, PortSet(True)) if is_default else (None, None)
        allowed_elements = {'resource': [0, dict], 'service': [0, dict]}
        self.check_fields_validity(backend, 'backend', allowed_elements)
        resource = backend.get('resource')
        service = backend.get('service')
        if resource and service:
            self.syntax_error(f'Resource and service are not mutually exclusive'
                              f'in the ingress {"default" if is_default else ""} backend', backend)
        if resource:
            self.warning('Resource is not yet supported in an ingress backend. Ignoring', backend)
            return (None, PortSet(True)) if is_default else (None, None)
        allowed_service_elements = {'name': [1, str], 'port': [1, dict]}
        self.check_fields_validity(service, 'backend service', allowed_service_elements)
        service_name = service.get('name')
        service_port = service.get('port')
        allowed_port_elements = {'name': [0, str], 'number': [0, int]}
        self.check_fields_validity(service_port, 'backend service port', allowed_port_elements)
        port_name = service_port.get('name')
        port_number = service_port.get('number')
        if port_name and port_number:
            self.syntax_error(f'Port name and port number are mutually exclusive'
                              f'in the ingress {"default" if is_default else ""} backend', service)
        if port_number:
            self.validate_value_in_domain(port_number, 'dst_ports', backend, 'Port number')
        srv = self.peer_container.get_service_by_name_and_ns(service_name, self.namespace)
        if not srv:
            self.syntax_error(f'Missing service referenced by the ingress {"default" if is_default else ""} backend',
                              service)
        service_port = srv.get_port_by_name(port_name) if port_name else srv.get_port_by_number(port_number)
        if not service_port:
            self.syntax_error(f'Missing port {port_name if port_name else port_number} in the service', service)

        rule_ports = PortSet()
        rule_ports.add_port(service_port.target_port)  # may be either a number or a named port
        return srv.target_pods, rule_ports

    def _make_tcp_like_properties(self, dest_ports, peers, paths_dfa=None, hosts_dfa=None):
        """
        get TcpLikeProperties with TCP allowed connections, corresponding to input properties cube.
        TcpLikeProperties should not contain named ports: substitute them with corresponding port numbers, per peer
        :param PortSet dest_ports: ports set for dest_ports dimension (possibly containing named ports)
        :param PeerSet peers: the set of (target) peers
        :param MinDFA paths_dfa: MinDFA obj for paths dimension
        :param MinDFA hosts_dfa: MinDFA obj for hosts dimension
        :return: TcpLikeProperties with TCP allowed connections, corresponding to input properties cube
        """
        assert peers
        base_peer_set = self.peer_container.peer_set.copy()
        base_peer_set.add(IpBlock.get_all_ips_block())
        if not dest_ports.named_ports:
            peers_interval = base_peer_set.get_peer_interval_of(peers)
            return TcpLikeProperties(source_ports=PortSet(True), dest_ports=dest_ports, methods=MethodSet(True),
                                     paths=paths_dfa, hosts=hosts_dfa, peers=peers_interval,
                                     base_peer_set=base_peer_set)
        assert not dest_ports.port_set
        assert len(dest_ports.named_ports) == 1
        port = list(dest_ports.named_ports)[0]
        tcp_properties = None
        for peer in peers:
            named_ports = peer.get_named_ports()
            real_port = named_ports.get(port)
            if not real_port:
                self.warning(f'Missing named port {port} in the pod {peer}. Ignoring the pod')
                continue
            if real_port[1] != 'TCP':
                self.warning(f'Illegal protocol {real_port[1]} in the named port {port} ingress target pod {peer}.'
                             f'Ignoring the pod')
                continue
            peer_in_set = PeerSet()
            peer_in_set.add(peer)
            ports = PortSet()
            ports.add_port(real_port[0])
            props = TcpLikeProperties(source_ports=PortSet(True), dest_ports=ports, methods=MethodSet(True),
                                      paths=paths_dfa, hosts=hosts_dfa,
                                      peers=base_peer_set.get_peer_interval_of(peer_in_set),
                                      base_peer_set=base_peer_set)
            if tcp_properties:
                tcp_properties |= props
            else:
                tcp_properties = props

        return tcp_properties

    def parse_ingress_path(self, path):
        """
        Parses ingress path resource.
        The assumption is that the default backend has been already parsed
        :param dict path: the path resource
        :return: a tuple (path_string, path_type, peers, ports)
        """
        self.check_fields_validity(path, 'ingress rule path',
                                   {'backend': [1, dict], 'path': [0, str], 'pathType': [1, str]},
                                   {'pathType': ['ImplementationSpecific', 'Exact', 'Prefix']})

        backend = path.get('backend')
        peers, ports = self.parse_backend(backend)
        if not peers:
            peers, ports = self.default_backend_peers, self.default_backend_ports
        path_string = path.get('path')
        path_type = path.get('pathType')
        # from https://docs.nginx.com/nginx-ingress-controller/configuration/ingress-resources/basic-configuration/
        # this is true only for ingress-nginx
        if path_type == 'ImplementationSpecific':
            path_type = 'Prefix'
        # from https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.23/#httpingresspath-v1-networking-k8s-io
        if not path_string:
            self.syntax_error('Missing path string in the rule path', path)

        # TODO: support use-regex, defined by:
        # metadata:
        #  annotations:
        #   nginx.ingress.kubernetes.io/use-regex: "true"
        # from https://kubernetes.github.io/ingress-nginx/user-guide/ingress-path-matching/#regular-expression-support
        # the following implementation is for nginx.ingress.kubernetes.io/use-regex == False
        self.validate_path_value(path_string, path)
        if path_type == 'Prefix':
            # https://kubernetes.io/docs/concepts/services-networking/ingress/#examples
            if path_string.endswith('/'):
                path_string = path_string[:-1]  # remove the trailing slash
        return path_string, path_type, peers, ports

    def segregate_longest_paths_and_make_dfa(self, parsed_paths):
        """
        Implement longest match semantics: for every path string, eliminate shorter subpaths to extend to longer ones
        :param parsed_paths: a list of tuples (path_string, path_type, peers, ports)
        :return: a list of tuples (path_string, path_dfa, path_type, peers, ports), where path_dfa elements obey
        the longest match semantics
        """
        # first, convert path strings to dfas
        parsed_paths_with_dfa = []
        allowed_chars = "[" + DimensionsManager().default_dfa_alphabet_chars + "]"
        for path_string, path_type, peers, ports in parsed_paths:
            if path_type == 'Exact':
                path_regex = path_string
            else:
                if path_string:
                    path_regex = path_string + '|' + path_string + '/' + allowed_chars + '+'
                else:
                    path_regex = '/' + allowed_chars + '*'
            parsed_paths_with_dfa.append((path_string, MinDFA.dfa_from_regex(path_regex), path_type, peers, ports))

        # next, avoid shorter sub-paths to extend to longer ones, using dfa operations
        res = []
        for i in range(0, len(parsed_paths)):
            path_string, path_dfa, path_type, peers, ports = parsed_paths_with_dfa[i]
            if path_type == 'Exact':  # we never eliminate 'Exact' paths
                res.append(parsed_paths_with_dfa[i])
                continue
            for j in range(0, len(parsed_paths)):
                if i == j:
                    continue
                path2_string, path2_dfa, path2_type, _, _ = parsed_paths_with_dfa[j]
                if path2_string.startswith(path_string):
                    # this includes the case when path_string (Prefix) == path2_string (Exact),
                    # thus giving the preference to path2_string (Exact)
                    path_dfa -= path2_dfa
            res.append((path_string, path_dfa, path_type, peers, ports))  # updates path_dfa

        return res

    def _make_default_connections(self, hosts_dfa, paths_dfa=None):
        """
        Creates default backend connections for given hosts and paths
        :param MinDFA hosts_dfa: the hosts for the default connections
        :param MinDFA paths_dfa: the paths for the default connections
        :return: TcpLikeProperties containing default connections or None (when no default backend exists)
        """
        default_conns = None
        if self.default_backend_peers:
            if paths_dfa:
                default_conns = self._make_tcp_like_properties(self.default_backend_ports, self.default_backend_peers,
                                                               paths_dfa, hosts_dfa)
            else:
                default_conns = self._make_tcp_like_properties(self.default_backend_ports, self.default_backend_peers,
                                                               hosts_dfa=hosts_dfa)
        return default_conns

    def _make_deny_rules(self, allowed_conns):
        """
        Make deny rules from the given connections
        :param TcpLikeProperties allowed_conns: the given allowed connections
        :return: the list of deny IngressPolicyRules
        """
        all_peers_and_ip_blocks = self.peer_container.peer_set | set(IpBlock.get_all_ips_block())
        all_conns = self._make_tcp_like_properties(PortSet(True), all_peers_and_ip_blocks)
        denied_conns = all_conns - allowed_conns
        res = self._make_rules_from_conns(denied_conns)
        # Add deny rule for all protocols but TCP , relevant for all peers and ip blocks
        non_tcp_conns = ConnectionSet.get_non_tcp_connections()
        res.append(IngressPolicyRule(all_peers_and_ip_blocks, non_tcp_conns))
        return res

    def _make_rules_from_conns(self, tcp_conns):
        """
        Make IngressPolicyRules from the given connections
        :param TcpLikeProperties tcp_conns: the given connections
        :return: the list of IngressPolicyRules
        """
        peers_to_conns = dict()
        res = []
        # extract peers dimension from cubes
        for cube in tcp_conns:
            ports = None
            paths = None
            hosts = None
            peer_set = None
            for i, dim in enumerate(tcp_conns.active_dimensions):
                if dim == "dst_ports":
                    ports = cube[i]
                elif dim == "paths":
                    paths = cube[i]
                elif dim == "hosts":
                    hosts = cube[i]
                elif dim == "peers":
                    peer_set = PeerSet(set(tcp_conns.base_peer_set.get_peer_list_by_indices(cube[i])))
                else:
                    assert False
            if not peer_set:
                peer_set = self.peer_container.peer_set.copy()
            port_set = PortSet()
            port_set.port_set = ports
            port_set.named_ports = tcp_conns.named_ports
            port_set.excluded_named_ports = tcp_conns.excluded_named_ports
            new_conns = self._get_connection_set_from_properties(port_set, paths_dfa=paths, hosts_dfa=hosts)
            if peers_to_conns.get(peer_set):
                peers_to_conns[peer_set] |= new_conns  # optimize conns for the same peers
            else:
                peers_to_conns[peer_set] = new_conns
        for peer_set, conns in peers_to_conns.items():
            res.append(IngressPolicyRule(peer_set, conns))
        return res

    def parse_rule(self, rule):
        """
        Parses a single ingress rule, producing a number of IngressPolicyRules (per path).
        :param dict rule: The rule resource
        :return: A tuple containing TcpLikeProperties including allowed connections for the given rule,
        and a dfa for hosts
        """
        if rule is None:
            self.syntax_error('Ingress rule cannot be null. ')

        allowed_elements = {'host': [0, str], 'http': [0, dict]}
        self.check_fields_validity(rule, 'ingress rule', allowed_elements)
        hosts_dfa = self.parse_regex_host_value(rule.get("host"), rule)
        paths_array = self.get_key_array_and_validate_not_empty(rule.get('http'), 'paths')
        allowed_conns = None
        if paths_array is not None:
            all_paths_dfa = None
            parsed_paths = []
            for path in paths_array:
                parsed_paths.append(self.parse_ingress_path(path))
            parsed_paths_with_dfa = self.segregate_longest_paths_and_make_dfa(parsed_paths)
            for (_, paths_dfa, _, peers, ports) in parsed_paths_with_dfa:
                # every path is converted to allowed connections
                conns = self._make_tcp_like_properties(ports, peers, paths_dfa, hosts_dfa)
                if not allowed_conns:
                    allowed_conns = conns
                else:
                    allowed_conns |= conns
                if not all_paths_dfa:
                    all_paths_dfa = paths_dfa
                else:
                    all_paths_dfa = all_paths_dfa | paths_dfa  # pick all captured paths
            # for this host, every path not captured by the above paths goes to the default backend or is denied
            paths_remainder_dfa = DimensionsManager().get_dimension_domain_by_name('paths') - all_paths_dfa
            default_conns = self._make_default_connections(hosts_dfa, paths_remainder_dfa)
        else:  # no paths --> everything for this host goes to the default backend or is denied
            default_conns = self._make_default_connections(hosts_dfa)
        if allowed_conns and default_conns:
            allowed_conns |= default_conns
        elif default_conns:
            allowed_conns = default_conns
        return allowed_conns, hosts_dfa

    def parse_policy(self):
        """
        Parses the input object to create  IngressPolicy object (with deny rules only)
        :return: IngressPolicy object with proper deny egress_rules, or None for wrong input object
        """
        if not isinstance(self.policy, dict):
            self.syntax_error('Top ds is not a map')
        if self.policy.get('kind') != 'Ingress':
            return None  # Not an Ingress object
        self.check_fields_validity(self.policy, 'Ingress', {'kind': 1, 'metadata': 1, 'spec': 1,
                                                            'apiVersion': 1, 'status': 0})
        if 'k8s' not in self.policy['apiVersion']:
            return None  # apiVersion is not properly set
        if 'name' not in self.policy['metadata']:
            self.syntax_error('Ingress has no name', self.policy)
        self.namespace = self.peer_container.get_namespace(self.policy['metadata'].get('namespace', 'default'))

        res_deny_policy = IngressPolicy(self.policy['metadata']['name'] + '/deny', self.namespace,
                                        IngressPolicy.ActionType.Deny)

        policy_spec = self.policy['spec']
        allowed_spec_keys = {'defaultBackend': [0, dict], 'ingressClassName': [0, str],
                             'rules': [0, list], 'TLS': [0, dict]}
        self.check_fields_validity(policy_spec, 'Ingress spec', allowed_spec_keys)

        self.default_backend_peers, self.default_backend_ports = self.parse_backend(policy_spec.get('defaultBackend'),
                                                                                    True)
        # TODO extend to other ingress controllers
        res_deny_policy.selected_peers = \
            self.peer_container.get_pods_with_service_name_containing_given_string('ingress-nginx')
        allowed_conns = None
        all_hosts_dfa = None
        for ingress_rule in policy_spec.get('rules', []):
            conns, hosts_dfa = self.parse_rule(ingress_rule)
            if not allowed_conns:
                allowed_conns = conns
            else:
                allowed_conns |= conns
            if hosts_dfa:
                if not all_hosts_dfa:
                    all_hosts_dfa = hosts_dfa
                else:
                    all_hosts_dfa = all_hosts_dfa | hosts_dfa
            else:
                all_hosts_dfa = DimensionsManager().get_dimension_domain_by_name('hosts')
        # every host not captured by the ingress rules goes to the default backend
        hosts_remainder_dfa = DimensionsManager().get_dimension_domain_by_name('hosts') - all_hosts_dfa
        default_conns = self._make_default_connections(hosts_remainder_dfa)
        if allowed_conns and default_conns:
            allowed_conns |= default_conns
        elif default_conns:
            allowed_conns = default_conns
        assert allowed_conns

        res_deny_policy.add_rules(self._make_deny_rules(allowed_conns))
        res_deny_policy.findings = self.warning_msgs
        return res_deny_policy
