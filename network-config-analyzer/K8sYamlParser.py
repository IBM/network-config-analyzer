#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import re
import Peer
import yaml
from GenericYamlParser import GenericYamlParser
from PeerContainer import PeerContainer
from K8sNamespace import K8sNamespace
from K8sService import K8sService
from CmdlineRunner import CmdlineRunner
from GenericTreeScanner import TreeScannerFactory


class K8sYamlParser(GenericYamlParser):
    """
    A parser for k8s NetworkPolicy objects
    """

    def __init__(self, yaml_file_name=''):
        """
        :param str yaml_file_name: The name of the yaml file containing K8s resources/policies
        """
        GenericYamlParser.__init__(self, yaml_file_name)
        self.allowed_labels = set()

    def check_dns_subdomain_name(self, value, key_container):
        """
        checking validity of the resource name
        :param string value : The value assigned for the key
        :param dict key_container : where the key appears
        :return: None
        """
        if len(value) > 253:
            self.syntax_error(f'invalid subdomain name : "{value}", DNS subdomain name must '
                              f'be no more than 253 characters', key_container)
        pattern = r"[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*"
        if re.fullmatch(pattern, value) is None:
            self.syntax_error(f'invalid DNS subdomain name : "{value}", it must consist of lower case alphanumeric '
                              f'characters, "-" or ".", and must start and end with an alphanumeric character',
                              key_container)

    def check_dns_label_name(self, value, key_container):
        """
        checking validity of the label name
        :param string value : The value assigned for the key
        :param dict key_container : where the key appears
        :return: None
        """
        if len(value) > 63:
            self.syntax_error(f'invalid label: "{value}" ,DNS label name must be no more than 63 characters',
                              key_container)
        pattern = r"[a-z0-9]([-a-z0-9]*[a-z0-9])?"
        if re.fullmatch(pattern, value) is None:
            self.syntax_error(f'invalid DNS label : "{value}", it must consist of lower case alphanumeric characters '
                              f'or "-", and must start and end with an alphanumeric character', key_container)

    def check_label_key_syntax(self, key_label, key_container):
        """
        checking validity of the label's key
        :param string key_label: The key name
        :param dict key_container : The label selector's part where the key appears
        :return: None
        """
        if key_label.count('/') > 1:
            self.syntax_error(f'Invalid key "{key_label}", a valid label key may have two segments: '
                              f'an optional prefix and name, separated by a slash (/).', key_container)
        if key_label.count('/') == 1:
            prefix = key_label.split('/')[0]
            if not prefix:
                self.syntax_error(f'invalid key "{key_label}", prefix part must be non-empty', key_container)
            self.check_dns_subdomain_name(prefix, key_container)
            name = key_label.split('/')[1]
        else:
            name = key_label
        if not name:
            self.syntax_error(f'invalid key "{key_label}", name segment is required in label key', key_container)
        if len(name) > 63:
            self.syntax_error(f'invalid key "{key_label}", a label key name must be no more than 63 characters',
                              key_container)
        pattern = r"([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]"
        if re.fullmatch(pattern, key_label) is None:
            self.syntax_error(f'invalid key "{key_label}", a label key name part must consist of alphanumeric '
                              f'characters, "-", "_" or ".", and must start and end with an alphanumeric character',
                              key_container)

    def check_label_value_syntax(self, val, key, key_container):
        """
        checking validity of the label's value
        :param string val : the value to be checked
        :param string key: The key name which the value is assigned for
        :param dict key_container : The label selector's part where the key: val appear
        :return: None
        """
        if val is None:
            self.syntax_error(f'value label of "{key}" can not be null', key_container)
        if val:
            if len(val) > 63:
                self.syntax_error(f'invalid value in "{key}: {val}", a label value must be no more than 63 characters',
                                  key_container)
            pattern = r"(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?"
            if re.fullmatch(pattern, val) is None:
                self.syntax_error(f'invalid value in "{key}: {val}", value label must be an empty string or consist'
                                  f' of alphanumeric characters, "-", "_" or ".", and must start and end with an '
                                  f'alphanumeric character ', key_container)

    def parse_label_selector_requirement(self, peer_container, namespace, requirement, namespace_selector):
        """
        Parse a LabelSelectorRequirement element
        :param PeerContainer peer_container: The requirement will be evaluated against this set of peers
        :param K8sNamespace namespace: The namespace in which the peers will be looked for
        :param dict requirement: The element to parse
        :param bool namespace_selector: Whether or not this is in the context of namespaceSelector
        :return: A PeerSet containing the peers that satisfy the requirement
        :rtype: Peer.PeerSet
        """
        self.check_fields_validity(requirement, 'LabelSelectorRequirement', {'key': [1, str], 'operator': [1, str],
                                                                             'values': [0, list]},
                                   {'operator': ['In', 'NotIn', 'Exists', 'DoesNotExist']})
        key = requirement['key']
        operator = requirement['operator']
        self.check_label_key_syntax(key, requirement)
        if operator in ['In', 'NotIn']:
            values = requirement.get('values')
            if not values:
                self.syntax_error('A requirement with In/NotIn operator but without values', requirement)
            action = PeerContainer.FilterActionType.In if operator == 'In' else PeerContainer.FilterActionType.NotIn  
            if namespace_selector:
                return peer_container.get_namespace_pods_with_label(key, values, action)
            return peer_container.get_peers_with_label(key, values, action)

        if operator in ['Exists', 'DoesNotExist']:
            if 'values' in requirement and requirement['values']:
                self.syntax_error('A requirement with Exist/DoesNotExist operator must not have values', requirement)
            if namespace_selector:
                return peer_container.get_namespace_pods_with_key(key, operator == 'DoesNotExist')
            return peer_container.get_peers_with_key(namespace, key, operator == 'DoesNotExist')

        return None

    def parse_label_selector(self, peer_container, namespace, label_selector, namespace_selector=False):
        """
        Parse a LabelSelector element (can also come from a NamespaceSelector)
        :param PeerContainer peer_container: The label will be evaluated against this set of peers
        :param K8sNamespace namespace: The namespace in which the peers will be looked for
        :param dict label_selector: The element to parse
        :param bool namespace_selector: Whether or not this is a namespaceSelector
        :return: A PeerSet containing all the pods captured by this selection
        :rtype: Peer.PeerSet
        """
        if label_selector is None:
            return Peer.PeerSet()  # A None value means the selector selects nothing
        if not label_selector:  # empty
            return peer_container.get_all_peers_group()  # An empty value means the selector selects everything
        allowed_elements = {'matchLabels': [0, dict], 'matchExpressions': [0, list]}
        self.check_fields_validity(label_selector, 'pod/namespace selector', allowed_elements)

        res = peer_container.get_all_peers_group()
        match_labels = label_selector.get('matchLabels')
        if match_labels:
            keys_set = set()
            for key, val in match_labels.items():
                self.check_label_key_syntax(key, match_labels)
                self.check_label_value_syntax(val, key, match_labels)
                if namespace_selector:
                    res &= peer_container.get_namespace_pods_with_label(key, [val])
                else:
                    res &= peer_container.get_peers_with_label(key, [val])
                keys_set.add(key)
            self.allowed_labels.add(':'.join(keys_set))

        match_expressions = label_selector.get('matchExpressions')
        if match_expressions:
            keys_set = set()
            for requirement in match_expressions:
                res &= self.parse_label_selector_requirement(peer_container, namespace, requirement, namespace_selector)
                key = requirement['key']
                keys_set.add(key)
            self.allowed_labels.add(':'.join(keys_set))

        if not res:
            if namespace_selector:
                self.warning('A namespaceSelector selects no pods. Better use "namespaceSelector: Null"',
                             label_selector)
            else:
                self.warning('A podSelector selects no pods. Better use "podSelector: Null"', label_selector)
        elif namespace_selector and res == peer_container.get_all_peers_group():
            self.warning('A non-empty namespaceSelector selects all pods. Better use "namespaceSelector: {}"',
                         label_selector)

        return res

    def check_port_syntax(self, port, allow_named, field_name):
        if not allow_named and isinstance(port, str):
            self.syntax_error(f'type of port is not numerical in {field_name}', port)
        if not isinstance(port, str) and not isinstance(port, int):
            self.syntax_error(f'type of port is not numerical or named (string) in {field_name}', port)
        if isinstance(port, int):
            self.validate_value_in_domain(port, 'dst_ports', port, 'Port number')
        if isinstance(port, str):
            if len(port) > 15:
                self.syntax_error('port name  must be no more than 15 characters', port)
            if re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", port) is None:
                self.syntax_error('port name should contain only lowercase alphanumeric characters or "-", '
                                  'and start and end with alphanumeric characters', port)

    def parse_service(self, srv_object, peer_container):
        """
        Parses a service resource object and creates a K8sService object
        :param dict srv_object: the service object to parse
        :param PeerContainer peer_container: the peer container in which pods of the service are located
        :return: K8sService object
        """
        if srv_object.get('kind') != 'Service':
            return None  # Not a Service object
        api_version = srv_object.get('apiVersion')
        if api_version != 'v1':
            return None  # apiVersion is not properly set
        self.check_fields_validity(srv_object, 'Service', {'kind': [1, str], 'metadata': [1, dict],
                                                           'spec': [1, dict], 'apiVersion': [1, str],
                                                           'status': [0, dict]},
                                   {'apiVersion': ['v1']})
        metadata = srv_object['metadata']
        allowed_metadata_keys = {'name': [1, str], 'annotations': [0, dict], 'creationTimestamp': [0, str],
                                 'namespace': [0, str], 'resourceVersion': [0, str], 'uid': [0, str], 'labels': [0, dict]}
        self.check_fields_validity(metadata, 'metadata', allowed_metadata_keys)
        srv_name = metadata['name']
        self.check_dns_subdomain_name(srv_name, metadata)
        service = K8sService(srv_name)
        if srv_object['spec'] is None:
            self.warning('spec is missing or null in Service ' + srv_name)
            return service

        service_spec = srv_object['spec']
        allowed_spec_keys = {'selector': [0, dict], 'type': [0, str], 'ports': [0, list],
                             'clusterIP': [0, str], 'clusterIPs': [0, list], 'sessionAffinity': [0, str],
                             'ipFamilies': [0, list], 'ipFamilyPolicy': [0, str], 'externalTrafficPolicy': [0, str]}
        self.check_fields_validity(service_spec, 'spec', allowed_spec_keys,
                                   {'type': ['ClusterIP', 'NodePort', 'LoadBalancer', 'ExternalName']})
        service_type = service_spec.get('type', 'ClusterIP')
        if service_type == 'ClusterIP':
            service.set_type(K8sService.ServiceType.ClusterIP)
        elif service_type == 'NodePort':
            service.set_type(K8sService.ServiceType.NodePort)
        elif service_type == 'LoadBalancer':
            service.set_type(K8sService.ServiceType.LoadBalancer)
        else:
            service.set_type(K8sService.ServiceType.ExternalName)

        selector = service_spec.get('selector')
        if selector is not None:
            for key, val in selector.items():
                self.check_label_key_syntax(key, selector)
                self.check_label_value_syntax(val, key, selector)
                service.add_selector(key, val)
                service.target_pods |= peer_container.get_peers_with_label(key, [val])

        ports = service_spec.get('ports')
        if ports is not None:
            for port in ports:
                self.check_fields_validity(port, 'Service port',
                                           {'port': [1, int], 'protocol': [0, str], 'name': [0, str], 'targetPort': 0,
                                            'nodePort': [0, int]},
                                           {'protocol': ['TCP', 'UDP', 'SCTP']})
                port_id = port.get('port', 0)
                self.check_port_syntax(port_id, False, 'Service port')
                target_port = port.get('targetPort')
                if target_port is None:
                    target_port = port_id
                else:
                    self.check_port_syntax(target_port, True, 'Service targetPort')
                name = port.get('name', '')
                self.check_dns_label_name(name, srv_object)
                if not service.add_port(K8sService.ServicePort(port_id, target_port,
                                                               port.get('protocol', 'TCP'), name)):
                    self.warning(f'The port {name} is not unique in Service {srv_object}')
                else:
                    if isinstance(target_port, str):
                        # check if all pods include this named port, and remove those that don't
                        pods_to_remove = Peer.PeerSet()
                        for pod in service.target_pods:
                            pod_named_port = pod.named_ports.get(target_port)
                            if not pod_named_port:
                                self.warning(f'The named port {target_port} referenced in Service {srv_object} is not defined in the pod {pod}. Ignoring the pod')
                                pods_to_remove |= pod
                        service.target_pods -= pods_to_remove
        return service

    @staticmethod
    def load_services_from_live_cluster(peer_container):
        """
        Loads and parses service resources from live cluster
        :param PeerContainer peer_container: the peer container in which pods of the service are located
        :return: The list of parsed services in K8sService format
        """
        PeerContainer.locate_kube_config_file()
        yaml_file = CmdlineRunner.get_k8s_resources('service')
        srv_resources = yaml.load(yaml_file, Loader=yaml.SafeLoader)
        if not isinstance(srv_resources, dict):
            return []
        parser = K8sYamlParser('k8s')
        res = []
        for srv_code in srv_resources.get('items', []):
            res.append(parser.parse_service(srv_code, peer_container))
        return res

    @staticmethod
    def parse_service_resources(srv_resources_list, peer_container):
        """
        Parses the set of services in the container from one of the following resources:
         - git path of yaml file or a directory with yamls
         - local file (yaml or json) or a local directory containing yamls
         - query of the cluster
        :param list srv_resources_list: The service resource to be used.
            If set to 'k8s', will query cluster using kubectl
        :param PeerContainer peer_container: the peer container in which pods of the service are located
        :return: The list of parsed services in K8sService format
        """
        for srv_resources in srv_resources_list:
            # load from live cluster
            if srv_resources == 'k8s':
                return K8sYamlParser.load_services_from_live_cluster(peer_container)
            else:
                res = []
                resource_scanner = TreeScannerFactory.get_scanner(srv_resources)
                if resource_scanner is None:
                    continue
                yaml_files = resource_scanner.get_yamls()
                for yaml_file in yaml_files:
                    parser = K8sYamlParser(yaml_file)
                    for srv_code in yaml_file.data:
                        if isinstance(srv_code, dict) and srv_code.get('kind') in {'Service'}:
                            res.append(parser.parse_service(srv_code, peer_container))
                return res
