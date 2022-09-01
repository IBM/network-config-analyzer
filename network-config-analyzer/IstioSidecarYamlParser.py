#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import re
from IstioGenericYamlParser import IstioGenericYamlParser
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
        if host.count('/') != 1:
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
            return self.peer_container.get_all_services_target_pods(), False
        if namespace == '.':
            # if the sidecar is global and ns is '.', then allow egress traffic only in the same namespace,
            # we return all matching peers in the mesh and later will compare namespaces to allow connections
            if str(self.namespace) == self.istio_root_namespace:
                return self.peer_container.get_all_services_target_pods(), True
            return self.peer_container.get_services_target_pods_in_namespace(self.namespace), False
        if namespace == '~':
            return PeerSet(), False

        ns_obj = self.peer_container.get_namespace(namespace)
        # get_namespace prints a msg to stderr if the namespace is missing from the configuration
        return self.peer_container.get_services_target_pods_in_namespace(ns_obj), False

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
        allowed_keys = {'port': [3, dict], 'bind': [3, str], 'captureMode': [3, str], 'hosts': [1, list]}
        self.check_fields_validity(egress_rule, 'Istio Egress Listener', allowed_keys)

        hosts = egress_rule.get('hosts')
        if not hosts:
            self.syntax_error('One or more service hosts to be exposed by the listener are required', egress_rule)
        res_peers = PeerSet()
        special_res_peers = PeerSet()
        for host in hosts:
            # Services in the specified namespace matching dnsName will be exposed.
            namespace, dns_name = self._validate_and_partition_host_format(host)
            host_peers, special_case_host = self._get_peers_from_host_namespace(namespace)
            self._validate_dns_name_pattern(dns_name)
            if host_peers:  # if there are services in the specified namespace
                if '*' not in dns_name:  # * means all services in namespace, all already in host_peers
                    host_peers &= self._get_peers_from_host_dns_name(dns_name)
            if special_case_host:
                special_res_peers |= host_peers
            else:
                res_peers |= host_peers

        return IstioSidecarRule(res_peers, special_res_peers)

    def _check_and_save_sidecar_if_top_priority(self, curr_sidecar):
        """
        check if current sidecar is top priority for its namespace or workloads.
        if the sidecar is selector less, and is the first default sidecar for current namespace, save it
        otherwise, save it for any peer if this is the first sidecar selecting it
        :param IstioSidecar curr_sidecar: the sidecar parsed in self
        a warning message will be printed if current sidecar is not the first for its relevant object,
        indicating that this sidecar will be ignored in the sidecar's connections
        """
        if curr_sidecar.default_sidecar:
            if self.namespace.prior_default_sidecar:  # this sidecar is not first one
                self.warning(f'Namespace "{str(self.namespace)}" already has a Sidecar configuration '
                             f'without any workloadSelector. '
                             f'Connections in sidecar: "{curr_sidecar.full_name()}" will be ignored')
                return
            self.namespace.prior_default_sidecar = curr_sidecar
            return

        for peer in curr_sidecar.selected_peers:
            if peer.prior_sidecar:  # this sidecar is not first one
                self.warning(f'Peer "{peer.full_name()}" already has a Sidecar configuration selecting it. Sidecar: '
                             f'"{curr_sidecar.full_name()}" will not be considered as connections for this workload')
                return
            peer.prior_sidecar = curr_sidecar

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
            self.syntax_error('spec is missing or null in Sidecar ' + res_policy.full_name())

        sidecar_spec = self.policy['spec']
        # currently, supported fields in spec are workloadSelector and egress
        allowed_spec_keys = {'workloadSelector': [0, dict], 'ingress': [3, list], 'egress': [0, list],
                             'outboundTrafficPolicy': [2, str]}
        self.check_fields_validity(sidecar_spec, 'Sidecar spec', allowed_spec_keys)
        res_policy.affects_egress = sidecar_spec.get('egress') is not None

        workload_selector = sidecar_spec.get('workloadSelector')
        res_policy.default_sidecar = workload_selector is None
        if str(self.namespace) == self.istio_root_namespace and workload_selector is not None:
            self.syntax_error('Global Sidecar configuration should not have any workloadSelector.')
        res_policy.selected_peers = self.update_policy_peers(workload_selector, 'labels')
        self._check_and_save_sidecar_if_top_priority(res_policy)

        for egress_rule in sidecar_spec.get('egress') or []:
            res_policy.add_egress_rule(self._parse_egress_rule(egress_rule))

        res_policy.findings = self.warning_msgs
        res_policy.referenced_labels = self.referenced_labels

        return res_policy
