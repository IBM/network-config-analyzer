#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import re

from nca.CoreDS.MinDFA import MinDFA
from nca.CoreDS.DimensionsManager import DimensionsManager
from nca.CoreDS.Peer import PeerSet
from nca.CoreDS.PortSet import PortSet
from nca.CoreDS.ConnectivityProperties import ConnectivityProperties
from nca.CoreDS.ProtocolSet import ProtocolSet
from nca.Resources.IngressPolicy import IngressPolicy
from nca.Resources.NetworkPolicy import NetworkPolicy
from .GenericIngressLikeYamlParser import GenericIngressLikeYamlParser


class IngressPolicyYamlParser(GenericIngressLikeYamlParser):
    """
    A parser for Ingress objects
    """

    def __init__(self, policy, peer_container, ingress_file_name=''):
        """
        :param dict policy: The ingress policy object as provided by the yaml parser
        :param PeerContainer peer_container: The ingress policy will be evaluated against this set of peers
        :param str ingress_file_name: The name of the ingress resource file
        """
        GenericIngressLikeYamlParser.__init__(self, peer_container, ingress_file_name)
        self.policy = policy
        self.namespace = None
        self.default_backend_peers = PeerSet()
        self.default_backend_ports = PortSet()
        # missing_k8s_ingress_peers is True if config has no identified ingress controller pod
        self.missing_k8s_ingress_peers = False

    def validate_path_value(self, path_value, path):
        if path_value[0] != '/':
            self.syntax_error(f'Illegal path {path_value} in the rule path', path)
        pattern = "[" + MinDFA.default_dfa_alphabet_chars + "]*"
        if not re.fullmatch(pattern, path_value):
            self.syntax_error(f'Illegal characters in path {path_value} in {path}')

    def parse_backend(self, backend, is_default=False):
        """
        Parses ingress backend and returns the set of pods and ports referenced by it.
        :param dict backend: the backend resource
        :param bool is_default: whether this is the default backend
        :return: a tuple PeerSet and PortSet and a bool flag, as following:
        the sets of pods and ports referenced by the backend and True,
        or None and all ports and True when the default backend is None ,
        or None and None and True when the non-default backend is None,
        or None and None and False when the backend is not None but backend service does not exist (for default and
        non-default backends)
        - for non-default backend when the flag is False then the backend service does not exist, and the path
        containing this backend should be ignored (i.e. don't override its peers and ports from the default_backend)
        :rtype: (PeerSet, PortSet, bool)
        """
        if backend is None:
            return (None, PortSet(True), True) if is_default else (None, None, True)
        allowed_elements = {'resource': [0, dict], 'service': [0, dict]}
        self.check_fields_validity(backend, 'backend', allowed_elements)
        resource = backend.get('resource')
        service = backend.get('service')
        if resource and service:
            self.syntax_error(f'Resource and service are not mutually exclusive'
                              f'in the ingress {"default" if is_default else ""} backend', backend)
        if resource:
            self.warning('Resource is not yet supported in an ingress backend. Ignoring', backend)
            return (None, PortSet(True), True) if is_default else (None, None, True)
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
            warning_msg = f'The service referenced by the ingress {"default" if is_default else ""} ' \
                          f'backend does not exist. '
            if is_default:
                warning_msg += 'The default backend will be ignored'
            else:
                warning_msg += 'The rule path containing this backend service will be ignored'
            self.warning(warning_msg, service)
            return None, None, False

        service_port = srv.get_port_by_name(port_name) if port_name else srv.get_port_by_number(port_number)
        if not service_port:
            self.syntax_error(f'Missing port {port_name if port_name else port_number} in the service', service)

        rule_ports = PortSet()
        rule_ports.add_port(service_port.target_port)  # may be either a number or a named port
        return srv.target_pods, rule_ports, True

    def parse_ingress_path(self, path):
        """
        Parses ingress path resource.
        The assumption is that the default backend has been already parsed
        :param dict path: the path resource
        :return: a tuple (path_string, path_type, peers, ports) or None if the path to be ignored
        """
        self.check_fields_validity(path, 'ingress rule path',
                                   {'backend': [1, dict], 'path': [0, str], 'pathType': [1, str]},
                                   {'pathType': ['ImplementationSpecific', 'Exact', 'Prefix']})

        backend = path.get('backend')
        peers, ports, override_default = self.parse_backend(backend)
        if not peers:
            if override_default:
                peers, ports = self.default_backend_peers, self.default_backend_ports
            else:  # backend service does not exist , ignoring this path
                return None
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

    @staticmethod
    def segregate_longest_paths_and_make_dfa(parsed_paths):
        """
        Implement the longest match semantics:for every path string, eliminate shorter subpaths to extend to longer ones
        :param parsed_paths: a list of tuples (path_string, path_type, peers, ports)
        :return: a list of tuples (path_string, path_dfa, path_type, peers, ports), where path_dfa elements obey
        the longest match semantics
        """
        # first, convert path strings to dfas
        parsed_paths_with_dfa = []
        for path_string, path_type, peers, ports in parsed_paths:
            if path_type == 'Exact':
                path_dfa = MinDFA.dfa_from_regex(path_string)
            else:  # Prefix type
                path_string = '/' if not path_string else path_string
                path_dfa = GenericIngressLikeYamlParser.get_path_prefix_dfa(path_string)
            parsed_paths_with_dfa.append((path_string, path_dfa, path_type, peers, ports))

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
        :return: ConnectivityProperties containing default connections or None (when no default backend exists)
        """
        default_conns = ConnectivityProperties.make_empty_props()
        if self.default_backend_peers:
            if paths_dfa:
                default_conns = \
                    ConnectivityProperties.make_conn_props(self.peer_container,
                                                           dst_ports=self.default_backend_ports,
                                                           dst_peers=self.default_backend_peers,
                                                           paths_dfa=paths_dfa, hosts_dfa=hosts_dfa)
            else:
                default_conns = \
                    ConnectivityProperties.make_conn_props(self.peer_container,
                                                           dst_ports=self.default_backend_ports,
                                                           dst_peers=self.default_backend_peers,
                                                           hosts_dfa=hosts_dfa)
        return default_conns

    def parse_rule(self, rule):
        """
        Parses a single ingress rule, producing a number of IngressPolicyRules (per path).
        :param dict rule: The rule resource
        :return: A tuple containing ConnectivityProperties including allowed connections for the given rule,
        and a dfa for hosts
        """
        if rule is None:
            self.syntax_error('Ingress rule cannot be null. ')

        allowed_elements = {'host': [0, str], 'http': [0, dict]}
        self.check_fields_validity(rule, 'ingress rule', allowed_elements)
        hosts_dfa = self.parse_regex_host_value(rule.get("host"), rule)
        paths_array = self.get_key_array_and_validate_not_empty(rule.get('http'), 'paths')
        allowed_conns = ConnectivityProperties.make_empty_props()
        default_conns = ConnectivityProperties.make_empty_props()
        if paths_array is not None:
            all_paths_dfa = None
            parsed_paths = []
            for path in paths_array:
                path_resources = self.parse_ingress_path(path)
                if path_resources is not None:
                    parsed_paths.append(path_resources)
            if parsed_paths:
                parsed_paths_with_dfa = self.segregate_longest_paths_and_make_dfa(parsed_paths)
                for (_, paths_dfa, _, peers, ports) in parsed_paths_with_dfa:
                    # every path is converted to allowed connections
                    conns = ConnectivityProperties.make_conn_props(self.peer_container, dst_ports=ports,
                                                                   dst_peers=peers, paths_dfa=paths_dfa,
                                                                   hosts_dfa=hosts_dfa)
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
        allowed_conns |= default_conns
        return allowed_conns, hosts_dfa

    def parse_policy(self):
        """
        Parses the input object to create  IngressPolicy object (with deny rules only)
        :return: IngressPolicy object with proper deny egress_rules, or None for wrong input object
        """
        policy_name, policy_ns = self.parse_generic_yaml_objects_fields(self.policy, ['Ingress'],
                                                                        ['networking.k8s.io/v1'], 'k8s', True)
        if policy_name is None:
            return None  # Not an Ingress object

        self.namespace = self.peer_container.get_namespace(policy_ns)
        res_policy = IngressPolicy(policy_name + '/allow', self.namespace, IngressPolicy.ActionType.Allow)
        res_policy.policy_kind = NetworkPolicy.PolicyType.Ingress

        policy_spec = self.policy['spec']
        allowed_spec_keys = {'defaultBackend': [0, dict], 'ingressClassName': [0, str],
                             'rules': [0, list], 'tls': [0, list]}
        self.check_fields_validity(policy_spec, 'Ingress spec', allowed_spec_keys)

        self.default_backend_peers, self.default_backend_ports, _ = self.parse_backend(policy_spec.get('defaultBackend'),
                                                                                       True)
        # TODO extend to other ingress controllers
        res_policy.selected_peers = \
            self.peer_container.get_pods_with_service_name_containing_given_string('ingress-nginx')
        if not res_policy.selected_peers:
            self.missing_k8s_ingress_peers = True
            self.warning("No ingress-nginx pods found, the Ingress policy will have no effect")
        allowed_conns = ConnectivityProperties.make_empty_props()
        all_hosts_dfa = None
        for ingress_rule in policy_spec.get('rules', []):
            conns, hosts_dfa = self.parse_rule(ingress_rule)
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
        allowed_conns |= default_conns
        # allowed_conns = none means that services referenced by this Ingress policy are not found,
        # then no connections rules to add (Ingress policy has no effect)
        if allowed_conns:
            res_policy.add_rules(self._make_allow_rules(allowed_conns))
            protocols = ProtocolSet()
            protocols.add_protocol('TCP')
            allowed_conns &= ConnectivityProperties.make_conn_props(self.peer_container, protocols=protocols,
                                                                    src_peers=res_policy.selected_peers)
            res_policy.add_optimized_egress_props(allowed_conns)
        res_policy.findings = self.warning_msgs
        return res_policy
