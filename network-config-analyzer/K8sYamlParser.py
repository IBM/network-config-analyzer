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
    A generic parser for k8s resources
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
