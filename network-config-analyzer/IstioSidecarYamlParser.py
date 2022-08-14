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
            self.syntax_error(f'Illegal host format {host}. Host format must be namespace/dnsName', self)

        host_parts = list(filter(None, host.split('/')))
        if not len(host_parts) == 2:
            self.syntax_error(f'Illegal host format {host}. Host must be consisted of both namespace and dnsName', self)

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
            self.syntax_error(f'unsupported regex pattern for namespace {namespace}', self)
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
            if not (dns_name.count('*') == 1 and (dns_name.startswith('*.') or dns_name == '*')):
                self.syntax_error(f'Illegal host value pattern: {dns_name}', self)
            if dns_name.startswith('*.'):
                alphabet_str = dns_name.split('*.')[1]

        # currently dnsName pattern supported is of "internal" services only (i.e. k8s service)
        # the dnsName in this case form looks like <service_name>.<domain>.svc.cluster.local
        # also FQDN is of the format [hostname].[domain].[tld]
        fqdn_regex = "^((?!-)[A-Za-z0-9-]+(?<!-)\\.)+[A-Za-z]+"
        if alphabet_str and not re.fullmatch(fqdn_regex, alphabet_str):
            self.syntax_error(f'Illegal host value pattern: {dns_name}, '
                              f'dnsName should be specified using FQDN format', self)

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
            self.warning('Only hosts field will be considered in policy connections of the sidecar egress', self)

        hosts = egress_rule.get('hosts')
        if not hosts:
            self.syntax_error('One or more service hosts to be exposed by the listener are required', self)
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

    def parse_policy(self):
        """
        Parses the input object to create a IstioSidecar object
        :return: a IstioSidecar object with proper PeerSets
        :rtype: IstioSidecar
        """
        if not isinstance(self.policy, dict):
            self.syntax_error('type of Top ds is not a map')
        if self.policy.get('kind') != 'Sidecar':
            return None  # Not a Sidecar object
        api_version = self.policy.get('apiVersion')
        if 'istio' not in api_version:
            return None  # apiVersion is not properly set
        valid_keys = {'kind': [1, str], 'apiVersion': [1, str], 'metadata': [1, dict], 'spec': [0, dict]}
        self.check_fields_validity(self.policy, 'Sidecar', valid_keys,
                                   {'apiVersion': ['networking.istio.io/v1beta1']})
        metadata = self.policy['metadata']
        allowed_metadata_keys = {'name': [1, str], 'namespace': [0, str]}
        self.check_fields_validity(metadata, 'metadata', allowed_metadata_keys)
        self.namespace = self.peer_container.get_namespace(metadata.get('namespace', 'default'))
        res_policy = IstioSidecar(metadata['name'], self.namespace)
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

        workload_selector = sidecar_spec.get('workloadSelector')
        if workload_selector is None:
            res_policy.selected_peers = self.peer_container.get_all_peers_group()
        else:
            res_policy.selected_peers = self.parse_workload_selector(workload_selector, 'labels')
        # if sidecar's namespace is the root namespace, then it applies to all cluster's namespaces
        if self.namespace.name != IstioGenericYamlParser.istio_root_namespace:
            res_policy.selected_peers &= self.peer_container.get_namespace_pods(self.namespace)

        if sidecar_spec.get('ingress') is not None:
            self.warning('Sidecar ingress is not supported yet.'
                         f'Although {res_policy.full_name()} contains ingress entry, '
                         f'it is not considered in policy connections')

        for egress_rule in sidecar_spec.get('egress', []):
            res_policy.add_egress_rule(self._parse_egress_rule(egress_rule))

        res_policy.findings = self.warning_msgs
        res_policy.referenced_labels = self.referenced_labels

        return res_policy
