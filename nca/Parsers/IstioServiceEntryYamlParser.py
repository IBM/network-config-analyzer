#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
from nca.CoreDS.Peer import DNSEntry
from nca.Parsers.GenericYamlParser import GenericYamlParser
from nca.Resources.ServiceResource import IstioServiceEntry


class IstioServiceEntryYamlParser(GenericYamlParser):

    def __init__(self, service_entry_file):
        super().__init__(service_entry_file)

    def _parse_export_to(self, namespaces, curr_ns):
        if not namespaces:
            return [], True

        ns_list = []
        for ns in namespaces:
            if ns == '*':
                return [], True
            if ns == '.':
                ns_list.append(str(curr_ns))
            else:
                ns_list.append(ns)

        return ns_list, False

    def _parse_host_and_build_dns_entry(self, host, rule_dict):
        if host == '*':
            self.syntax_error(f'illegal host {host}', rule_dict)
        host_dfa = self.parse_regex_host_value(host, rule_dict)
        if host_dfa:
            # TODO: check if a DNSEntry with same host already exists, get it instead of creating new one
            return DNSEntry(host_dfa, host)
        return None

    def parse_service(self, service_entry_obj):
        se_name, se_ns = self.parse_generic_yaml_objects_fields(service_entry_obj, ['ServiceEntry'],
                                                                ['networking.istio.io/v1beta1',
                                                                 'networking.istio.io/v1alpha3'], 'istio', True)
        if se_name is None:
            return None   # not a ServiceEntry object, nothing to build

        service_entry = IstioServiceEntry(se_name, se_ns)
        se_spec = service_entry_obj['spec']

        allowed_keys = {'hosts': [1, list], 'addresses': [3, list], 'ports': [3, list], 'location': [0, str],
                        'resolution': [0, str], 'endpoints': [2, list], 'workloadSelector': [2, dict],
                        'exportTo': [0, str], 'subjectAltNames': [3, list]}
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
            service_entry.add_host(self._parse_host_and_build_dns_entry(host, se_spec))

        namespaces_list, all_ns_flag = self._parse_export_to(se_spec.get('exportTo', []), se_ns)
        service_entry.update_namespaces_fields(namespaces_list, all_ns_flag)
        service_entry.update_hosts_namespaces()

        return service_entry
