#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import re

from MinDFA import MinDFA
from DimensionsManager import DimensionsManager
from GenericYamlParser import GenericYamlParser
from IngressPolicy import IngressPolicy, IngressPolicyRule
from Peer import PeerSet
from PeerContainer import PeerContainer
from PortSet import PortSet


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
        self.namespace = peer_container.get_namespace('default')  # value to be replaced if ingress has ns defined
        self.default_backend_peers = PeerSet()
        self.default_backend_ports = PortSet()
        self.allowed_labels = set()

    def _validate_ingress_regex_pattern(self, regex_str, is_host):
        """
        validate input regex str is supported by ingress rule host or path.
        raise syntax error if invalid.
        :param str regex_str: the input regex str to validate
        :param bool is_host: whether this is host regex
        """
        if '*' in regex_str:
            if not is_host and not (regex_str.count('*') == 1 and regex_str.endswith('*')):
                self.syntax_error(f'Illegal str value pattern: {regex_str}')
            if is_host and not regex_str.startswith('*.'):
                self.syntax_error(f'Illegal str value pattern: {regex_str}')

    def _parse_str_value(self, str_val_input, dim_name, rule):
        """
        transform input regex/str to the format supported by greenery
        :param str str_val_input: the str/regex from input
        :param str dim_name: the name of the dimension of str_val_input value
        :param dict rule: the rule object being parsed
        :return: str: the result regex/str after conversion
        """
        if dim_name == 'hosts':
            allowed_chars = "[\\w]"
        else:
            allowed_chars = "[" + DimensionsManager().default_dfa_alphabet_chars + "]"
        allowed_chars_with_star_regex = "[*" + DimensionsManager().default_dfa_alphabet_chars + "]*"
        if not re.fullmatch(allowed_chars_with_star_regex, str_val_input):
            self.syntax_error(f'Illegal characters in {dim_name} {str_val_input} in {rule}')

        # convert str_val_input into regex format supported by greenery
        res = str_val_input.replace(".", "[.]")
        if '*' in res:
            self._validate_ingress_regex_pattern(res, dim_name == "hosts")
            res = res.replace("*", allowed_chars + '*')
        return res

    def parse_regex_dimension_values(self, dim_name, regex_value, rule):
        """
        for dimension of type MinDFA -> return a MinDFA or None for all values
        :param str dim_name: dimension name
        :param str regex_value: regex value
        :param dict rule: the parsed rule object
        :return: Union[MinDFA, None] object
        """
        dim_type = DimensionsManager().get_dimension_type_by_name(dim_name)
        assert dim_type == DimensionsManager.DimensionType.DFA

        if regex_value is None:
            return None  # to represent that all is allowed, and this dimension can be inactive in the generated cube
        regex = self._parse_str_value(regex_value, dim_name, rule)
        return MinDFA.dfa_from_regex(regex)

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
            self.syntax_error('Port name and port number are mutually exclusive' 
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

    def parse_ingress_path(self, path, hosts_dfa):
        """
        Parses ingress path resource.
        The assumption is that the default backend has been already parsed
        :param dict path: the path resource
        :param MinDFA hosts_dfa: the dfa of host for this rule
        :return: a tuple of IngressPolicyRule and paths_dfa for this path resource
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
        if path_string[0] != '/':
            self.syntax_error(f'Illegal path {path_string} in the rule path', path)
        path_regex = path_string
        if path_type == 'Prefix':
            # https://kubernetes.io/docs/concepts/services-networking/ingress/#examples
            if path_string.endswith('/'):
                path_string = path_string[:-1]  # remove the trailing slash
            if path_string:
                path_regex = path_string + ' | ' + path_string + '/*'
            else:
                path_regex = '/*'
        paths_dfa = self.parse_regex_dimension_values("paths", path_regex, path)
        connections = self._get_connection_set_from_properties(ports, paths_dfa=paths_dfa, hosts_dfa=hosts_dfa)
        return IngressPolicyRule(peers, connections), paths_dfa

    def _make_default_and_deny_rules(self, hosts_dfa, paths_dfa=None):
        """
        Creates a 'default' backend rule for given hosts and paths and a deny rule for the remaining ports
        :param MinDFA hosts_dfa: the hosts for the default rule
        :param MinDFA paths_dfa: the paths for the default rule
        :return: the list of created IngressPolicy rules
        """
        allow_rules = []
        deny_rules = []
        if self.default_backend_peers:
            other_ports = PortSet(True)
            other_ports -= self.default_backend_ports
            if paths_dfa:
                conns = self._get_connection_set_from_properties(self.default_backend_ports, paths_dfa=paths_dfa,
                                                                 hosts_dfa=hosts_dfa)
                denied_conns = self._get_connection_set_from_properties(other_ports, paths_dfa=paths_dfa,
                                                                        hosts_dfa=hosts_dfa)
            else:
                conns = self._get_connection_set_from_properties(self.default_backend_ports, hosts_dfa=hosts_dfa)
                denied_conns = self._get_connection_set_from_properties(other_ports, hosts_dfa=hosts_dfa)

            allow_rules.append(IngressPolicyRule(self.default_backend_peers, conns))
            deny_rules.append(IngressPolicyRule(self.peer_container.get_all_peers_group(), denied_conns))
        else:
            all_ports = PortSet(True)
            if paths_dfa:
                denied_conns = self._get_connection_set_from_properties(all_ports, paths_dfa=paths_dfa,
                                                                        hosts_dfa=hosts_dfa)
            else:
                denied_conns = self._get_connection_set_from_properties(all_ports, hosts_dfa=hosts_dfa)

            deny_rules.append(IngressPolicyRule(self.peer_container.get_all_peers_group(), denied_conns))
        return allow_rules, deny_rules

    def parse_rule(self, rule):
        """
        Parses a single ingress rule, producing a number of IngressPolicyRules (per path).
        :param dict rule: The rule resource
        :return: A tuple containing two lists of IngressPolicyRules (allow rules and deny rules)
                 with the proper PeerSet and ConnectionSet, and a dfa for hosts
        """
        if rule is None:
            self.syntax_error('Ingress rule cannot be null. ')

        allowed_elements = {'host': [0, str], 'http': [0, dict]}
        self.check_fields_validity(rule, 'ingress rule', allowed_elements)
        hosts_dfa = self.parse_regex_dimension_values("hosts", rule.get("host"), rule)
        paths_array = self.get_key_array_and_validate_not_empty(rule.get('http'), 'paths')
        ingress_allow_rules = []
        ingress_deny_rules = []
        if paths_array is not None:
            all_paths_dfa = None
            for path in paths_array:
                # TODO: implement path priority rules
                # every path is converted to IngressPolicyRule
                ingress_policy_rule, paths_dfa = self.parse_ingress_path(path, hosts_dfa)
                ingress_allow_rules.append(ingress_policy_rule)
                if not all_paths_dfa:
                    all_paths_dfa = paths_dfa
                else:
                    all_paths_dfa = all_paths_dfa | paths_dfa  # pick all captured paths
            # for this host, every path not captured by the above paths goes to the default backend or is denied
            paths_remainder_dfa = DimensionsManager().get_dimension_domain_by_name('paths') - all_paths_dfa
            allow_rules, deny_rules = self._make_default_and_deny_rules(hosts_dfa, paths_remainder_dfa)
            ingress_allow_rules += allow_rules
            ingress_deny_rules += deny_rules
        else:  # no paths --> everything for this host goes to the default backend or is denied
            allow_rules, deny_rules = self._make_default_and_deny_rules(hosts_dfa)
            ingress_allow_rules += allow_rules
            ingress_deny_rules += deny_rules
        return ingress_allow_rules, ingress_deny_rules, hosts_dfa

    def parse_policy(self):
        """
        Parses the input object to create two IngressPolicy objects (one for allow and one for deny)
        :return: a tuple of IngressPolicy objects with proper egress_rules or (None, None) for wrong input object
        """
        if not isinstance(self.policy, dict):
            self.syntax_error('Top ds is not a map')
        if self.policy.get('kind') != 'Ingress':
            return None, None  # Not an Ingress object
        self.check_fields_validity(self.policy, 'Ingress', {'kind': 1, 'metadata': 1, 'spec': 1,
                                                            'apiVersion': 1, 'status': 0})
        if 'k8s' not in self.policy['apiVersion']:
            return None, None  # apiVersion is not properly set
        if 'name' not in self.policy['metadata']:
            self.syntax_error('Ingress has no name', self.policy)
        if 'namespace' in self.policy['metadata']:
            self.namespace = self.peer_container.get_namespace(self.policy['metadata']['namespace'])

        res_allow_policy = IngressPolicy(self.policy['metadata']['name'] + '/allow', self.namespace,
                                         IngressPolicy.ActionType.Allow)
        res_deny_policy = IngressPolicy(self.policy['metadata']['name'] + '/deny', self.namespace,
                                        IngressPolicy.ActionType.Deny)

        policy_spec = self.policy['spec']
        allowed_spec_keys = {'defaultBackend': [0, dict], 'ingressClassName': [0, str],
                             'rules': [0, list], 'TLS': [0, dict]}
        self.check_fields_validity(policy_spec, 'istio authorization policy spec', allowed_spec_keys)

        self.default_backend_peers, self.default_backend_ports = self.parse_backend(policy_spec.get('defaultBackend'),
                                                                                    True)
        # TODO extend to other ingress controllers
        res_allow_policy.selected_peers = \
            self.peer_container.get_pods_with_service_name_containing_given_string('ingress-nginx')
        res_deny_policy.selected_peers = res_allow_policy.selected_peers
        all_hosts_dfa = None
        for ingress_rule in policy_spec.get('rules', []):
            allow_rules, deny_rules, hosts_dfa = self.parse_rule(ingress_rule)
            res_allow_policy.add_rules(allow_rules)
            res_deny_policy.add_rules(deny_rules)
            if not all_hosts_dfa:
                all_hosts_dfa = hosts_dfa
            else:
                all_hosts_dfa = all_hosts_dfa | hosts_dfa
        # every host not captured by the ingress rules goes to the default backend or is denied
        hosts_remainder_dfa = DimensionsManager().get_dimension_domain_by_name('hosts') - all_hosts_dfa
        allow_rules, deny_rules = self._make_default_and_deny_rules(hosts_remainder_dfa)
        res_allow_policy.add_rules(allow_rules)
        res_deny_policy.add_rules(deny_rules)
        res_allow_policy.findings = self.warning_msgs
        return res_allow_policy, res_deny_policy
