#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import re

from nca.CoreDS.Peer import DNSEntry
from nca.Parsers.GenericYamlParser import GenericYamlParser
from nca.Resources.ServiceResource import IstioServiceEntry


class IstioServiceEntryYamlParser(GenericYamlParser):

    def __init__(self, service_entry_file):
        super().__init__(service_entry_file)

    @staticmethod
    def _parse_export_to(namespaces, curr_ns):
        """
        parses the list in exportTo field of the ServiceEntry if found, and returns the namespaces list which
        the ServiceEntry is exported to. If exportTo not found , by default, a service is exported to all namespaces.
        :param list[str] namespaces: the list of namespaces names given in exportTo field
        :param str curr_ns: the name of this serviceEntry's namespace name
        :return list of namespaces or ['*'] if exported to all namespaces
        :rtype: list[str]
        """
        if not namespaces:
            return ['*']

        ns_list = []
        for ns in namespaces:
            if ns == '*':
                return ['*']
            if ns == '.':
                ns_list.append(str(curr_ns))
            else:
                ns_list.append(ns)
        return ns_list

    def _legal_host_name(self, host_name):
        """
        returns if the host name is a DNS name with wildcard prefix.
        :param str host_name: host name to check
        return: an re-matching object if the host name matches the DNS pattern, None otherwise
        :rtype Union[str, None]
        """
        dns_pattern = "[*.\\w/\\-]*"
        return re.fullmatch(dns_pattern, host_name)

    @staticmethod
    def get_or_create_dns_entry_peer(peer_set, host_name):
        """
        checks if the given peer set contains a DNSEntry peer with the given host_dfa, if yes returns it, otherwise
        creates a new DNSEntry peer with the given host_dfa and host_name
        :param peer_set: set of peers
        :param str host_name: the host name
        :return DNSEntry
        """
        for peer in peer_set:
            if isinstance(peer, DNSEntry) and peer.name == host_name:
                return peer
        return DNSEntry(name=host_name)

    def _parse_host_and_get_dns_entry(self, host, rule_dict, peer_set):
        """
        parse a host in the hosts field of the ServiceEntry, get or create a DNSEntry peer based on the host
        :param str host : the host name/ url
        :param dict rule_dict: the spec dict that includes the host
        :param PeerSet peer_set: set of peers
        :return a DNSEntry peer to add to the ServiceEntry's target_peers if the host is legal
        :rtype Union[DNSEntry, None]
        """
        if host == '*':
            self.syntax_error(f'illegal host {host}', rule_dict)
        if self._legal_host_name(host):
            # check if a DNSEntry with same host already exists in the peer set, get it, otherwise create new one
            return self.get_or_create_dns_entry_peer(peer_set, host)
        return None

    def parse_service(self, service_entry_obj, peer_set):
        """
        Parses a service resource object and creates an IstioServiceEntry object
        :param dict service_entry_obj: the service object to parse
        :param PeerSet peer_set : set of the peers that already parsed by other input resources
        :return: IstioServiceEntry object or None
        """
        se_name, se_ns = self.parse_generic_yaml_objects_fields(service_entry_obj, ['ServiceEntry'],
                                                                ['networking.istio.io/v1beta1',
                                                                 'networking.istio.io/v1alpha3'], 'istio', True)
        if se_name is None:
            return None   # not a ServiceEntry object, nothing to build

        service_entry = IstioServiceEntry(se_name, se_ns)
        se_spec = service_entry_obj['spec']

        allowed_keys = {'hosts': [1, list], 'addresses': [3, list], 'ports': [1, list], 'location': [0, str],
                        'resolution': [0, str], 'endpoints': [2, list], 'workloadSelector': [2, dict],
                        'exportTo': [0, list], 'subjectAltNames': [3, list]}
        # Note: even though the resolution field appears as required in Istio ServiceEntry reference,
        # live cluster accepts service-entry yaml without this field (not required)

        specified_values = {'location': ['MESH_EXTERNAL', 'MESH_INTERNAL'],
                            'resolution': ['NONE', 'STATIC', 'DNS', 'DNS_ROUND_ROBIN']}

        self.check_fields_validity(se_spec, 'ServiceEntry', allowed_keys, specified_values)

        location = se_spec.get('location')
        if location and location != 'MESH_EXTERNAL':
            self.warning('ServiceEntry with internal services is not supported yet')

        resolution = se_spec.get('resolution')
        if resolution and resolution not in ['NONE', 'DNS', 'DNS_ROUND_ROBIN']:
            # STATIC is relevant only with IP addresses
            self.warning(f'{resolution} value is not supported yet for resolution')

        hosts = se_spec.get('hosts')
        if not hosts:
            self.syntax_error('ServiceEntry spec must have at least one host', se_spec)
        for host in hosts:
            service_entry.add_host(self._parse_host_and_get_dns_entry(host, se_spec, peer_set))

        ports = se_spec.get('ports')
        if not ports:
            self.syntax_error('ServiceEntry spec must have at least one port', se_spec)
        port_valid_keys = {'number': [1, int], 'protocol': [1, str], 'name': [1, str], 'targetPort': [0, int]}
        port_allowed_values = {'protocol': ['HTTP', 'HTTPS', 'GRPC', 'HTTP2', 'MONGO', 'TCP', 'TLS']}
        self._parse_and_add_service_resource_ports(ports, port_valid_keys, port_allowed_values, service_entry)

        service_entry.exported_to_namespaces = self._parse_export_to(se_spec.get('exportTo', []), se_ns)
        service_entry.update_hosts_namespaces_and_ports()

        return service_entry
