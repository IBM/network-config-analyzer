#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import re
from GenericYamlParser import IstioGenericYamlParser
from NetworkPolicy import NetworkPolicy
from IstioSidecar import IstioSidecar, IstioSidecarRule
from Peer import PeerSet


class IstioSidecarYamlParser(IstioGenericYamlParser):
    """
    A parser for Istio Sidecar objects
    """

    def _validate_and_partition_host_format(self, host):
        """
        Check the validity of <namespace>/<dnsName> host format
        :param str host : single host value
        :return: namespace and dnsName - the parts of the host value
        :rtype: (str, str)
        """
        if not host.count('/') == 1:
            self.syntax_error(f'Illegal host format "{host}". Host format must be namespace/dnsName', self)

        host_parts = list(filter(None, host.split('/')))
        if not len(host_parts) == 2:
            self.syntax_error(f'Illegal host format "{host}". Host must include both namespace and dnsName', self)

        return host_parts[0], host_parts[1]

    def _get_peers_from_host_namespace(self, namespace):
        """
        returns all the services' peers in the specified namespace/s
        The namespace can be set to *, ., or ~, representing any, the current, or no namespace, respectively
        :param str namespace: the namespace value
        :return: set of peers of services in the specified namespace value or empty PeerSet if no matching peers
        :rtype: PeerSet
        """
        # since hosts expose services, target_pods of relevant services are returned in this method
        supported_chars = ('*', '.', '~')
        if any(s in namespace for s in supported_chars) and not len(namespace) == 1:
            self.syntax_error(f'unsupported regex pattern for namespace "{namespace}"', self)
        if namespace == '*':
            # return self.peer_container.get_all_peers_group()
            return self.peer_container.get_all_services_target_pods()
        if namespace == '.':
            # return self.peer_container.get_namespace_pods(self.namespace)
            return self.peer_container.get_services_target_pods_in_namespace(self.namespace)
        if namespace == '~':
            return PeerSet()

        ns_obj = self.peer_container.get_namespace(namespace)
        # get_namespace prints a msg to stderr if the namespace is missing from the configuration
        return self.peer_container.get_services_target_pods_in_namespace(ns_obj)

    def _validate_dns_name_pattern(self, dns_name):
        """
        Check validity of dns_name containing as following:
        The dnsName should be specified using FQDN format,
        optionally including a wildcard character in the left-most component.
        Set the dnsName to * to select all services from the specified namespace
        :param str dns_name: a dnsName
        """
        alphabet_str = dns_name if not dns_name == '*' else None
        # assuming wildcard char may be only *
        if '*' in dns_name:
            if not ((dns_name.startswith('*.') and dns_name.count('*') == 1) or dns_name == '*'):
                self.syntax_error(f'Illegal host value pattern: "{dns_name}"', self)
            if dns_name.startswith('*.'):
                alphabet_str = dns_name.split('*')[1]

        # currently dnsName pattern supported is of "internal" services only (i.e. k8s service)
        # the dnsName in this case form looks like <service_name>.<domain>.svc.cluster.local
        # also FQDN is of the format [hostname].[domain].[tld]
        if alphabet_str:
            fqdn_regex = "^((?!-)[A-Za-z0-9-]+(?<!-).)+[A-Za-z0-9.]+"
            if alphabet_str.count('.') == 0 or not re.fullmatch(fqdn_regex, alphabet_str):
                self.syntax_error(f'Illegal host value pattern: "{dns_name}", '
                                  f'dnsName must be specified using FQDN format', self)

    def _get_peers_from_host_dns_name(self, dns_name):
        """
        Return the workload instances of the service in the given dns_name
        :param str dns_name: the service given in the host
        :rtype: PeerSet
        """
        # supported dns_name format is fqdn with internal k8s services pattern
        # <service_name>.<domain>.svc.cluster.local
        # the only relevant part of it is <service_name>
        service_name = dns_name.split('.')[0]
        return self.peer_container.get_pods_with_service_name_containing_given_string(service_name)

    def _parse_egress_rule(self, egress_rule):
        """
        Parse a single egress rule, producing a IstioSidecarRule
        :param dict egress_rule: The dict with the egress rule (IstioEgressListener) fields
        :return: A IstioSidecarRule with the proper PeerSet
        :rtype: IstioSidecarRule
        """
        # currently only hosts is considered in the rule parsing, other fields are not supported
        allowed_keys = {'port': [0, dict], 'bind': [0, str], 'captureMode': [0, str], 'hosts': [1, list]}
        self.check_fields_validity(egress_rule, 'Istio Egress Listener', allowed_keys)

        if egress_rule.get('port') or egress_rule.get('bind') or egress_rule.get('captureMode'):
            self.warning('Only hosts field will be considered in policy connections of the sidecar egress', egress_rule)

        hosts = egress_rule.get('hosts')
        if not hosts:
            self.syntax_error('One or more service hosts to be exposed by the listener are required', egress_rule)
        res_peers = PeerSet()
        for host in hosts:
            host_peers = PeerSet()
            # Services in the specified namespace matching dnsName will be exposed.
            namespace, dns_name = self._validate_and_partition_host_format(host)
            host_peers |= self._get_peers_from_host_namespace(namespace)
            self._validate_dns_name_pattern(dns_name)
            if host_peers:  # if there are services in the specified namespace
                if '*' not in dns_name:  # * means all services in namespace, all already in host_peers
                    host_peers &= self._get_peers_from_host_dns_name(dns_name)
            res_peers |= host_peers

        return IstioSidecarRule(res_peers)

    def _remove_peers_from_default_sidecar(self, sidecar_override_peers, override_global_only):
        """
        Checks if the current namespace or the istio root namespace has a default sidecar and removes
        the given peers from these default sidecars since they are overridden by more specific sidecars (curr sidecar)
        :param list sidecar_override_peers: list of peers to be removed from wider sidecars
        :param bool override_global_only: a flag indicates if to override only the global sidecar of the mesh
        """
        if not override_global_only:
            # override the current namespace's default (selector-less) sidecar
            if self.namespace.default_sidecar is not None:
                for peer in sidecar_override_peers:
                    self.namespace.default_sidecar.selected_peers.remove(peer)
                return

        root_namespace = self.peer_container.get_namespace(IstioSidecarYamlParser.istio_root_namespace)
        if root_namespace.default_sidecar is not None:
            for peer in sidecar_override_peers:
                root_namespace.default_sidecar.selected_peers.remove(peer)

    def parse_policy(self):
        """
        Parses the input object to create a IstioSidecar object
        :return: a IstioSidecar object with proper PeerSets
        :rtype: IstioSidecar
        """
        policy_name = self.parse_generic_istio_policy_fields('Sidecar', 'networking.istio.io/v1beta1')
        if policy_name is None:
            return None  # not relevant to build this policy

        res_policy = IstioSidecar(policy_name, self.namespace)
        res_policy.policy_kind = NetworkPolicy.PolicyType.IstioSidecar

        if 'spec' not in self.policy or self.policy['spec'] is None:
            self.warning('spec is missing or null in Sidecar ' + res_policy.full_name())
            return res_policy

        sidecar_spec = self.policy['spec']
        # currently, supported fields in spec are workloadSelector and egress
        allowed_spec_keys = {'workloadSelector': [0, dict], 'ingress': [0, list], 'egress': [0, list],
                             'outboundTrafficPolicy': [2, str]}
        self.check_fields_validity(sidecar_spec, 'Sidecar spec', allowed_spec_keys)
        res_policy.affects_egress = sidecar_spec.get('egress') is not None

        sidecar_with_selector = False
        workload_selector = sidecar_spec.get('workloadSelector')
        if workload_selector is None:
            if self.namespace.default_sidecar is not None:
                self.warning(f'Namespace "{self.namespace.name}" already has a Sidecar configuration '
                             f'without any workloadSelector. Sidecar:'
                             f' "{res_policy.full_name()}" will be ignored', sidecar_spec)
                return None  # this sidecar is ignored
            res_policy.selected_peers = self.peer_container.get_all_peers_group()
            self.namespace.default_sidecar = res_policy
        else:
            res_policy.selected_peers = self.parse_workload_selector(workload_selector, 'labels')
            sidecar_with_selector = True
        # if sidecar's namespace is the root namespace, then it applies to all cluster's namespaces
        if self.namespace.name != IstioGenericYamlParser.istio_root_namespace:
            res_policy.selected_peers &= self.peer_container.get_namespace_pods(self.namespace)

        # check if any wider (selector-less) sidecar should be overridden by this sidecar, or if any peers should not be
        # selected in this sidecar since another sidecar already selects them
        sidecar_override_peers = []
        override_global_only = False
        for peer in res_policy.selected_peers.copy():
            if peer.specified_in_sidecar:
                self.warning(f'Peer "{peer.full_name()}" already has a Sidecar configuration selecting it.'
                             f'Sidecar: "{res_policy.full_name()}" will be ignored for it', sidecar_spec)
                res_policy.selected_peers.remove(peer)
            elif sidecar_with_selector:
                peer.specified_in_sidecar = True
                sidecar_override_peers.append(peer)
        if not sidecar_with_selector and self.namespace.name != IstioGenericYamlParser.istio_root_namespace:
            # current is a default sidecar in curr namespace, may override global sidecar if exists
            override_global_only = True
            sidecar_override_peers = res_policy.selected_peers
        # calling this to remove relevant selected_peers from the default/global sidecar
        self._remove_peers_from_default_sidecar(sidecar_override_peers, override_global_only)

        if sidecar_spec.get('ingress') is not None:
            self.warning('Sidecar ingress is not supported yet.'
                         f'Although "{res_policy.full_name()}" contains ingress entry, '
                         f'it is not considered in policy connections', sidecar_spec)

        egress = sidecar_spec.get('egress', [])
        if egress is None:
            self.syntax_error('An empty configuration is provided', res_policy.name)  # behavior of live cluster
        for egress_rule in egress:
            res_policy.add_egress_rule(self._parse_egress_rule(egress_rule))

        res_policy.findings = self.warning_msgs
        res_policy.referenced_labels = self.referenced_labels

        return res_policy
