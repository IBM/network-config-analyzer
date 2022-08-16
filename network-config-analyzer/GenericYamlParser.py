#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from sys import stderr
from ruamel.yaml import comments
from enum import Enum
from DimensionsManager import DimensionsManager
from TcpLikeProperties import TcpLikeProperties
from MethodSet import MethodSet
from ConnectionSet import ConnectionSet
from PortSet import PortSet
from MinDFA import MinDFA


class GenericYamlParser:
    """
    A base class for yaml parsers, providing basic services
    """

    class FilterActionType(Enum):
        """
        Allowed actions for Calico's network policy rules
        """
        In = 0
        NotIn = 1
        Contain = 2
        StartWith = 3
        EndWith = 4

    def __init__(self, yaml_file_name=''):
        """
        :param str yaml_file_name: The name of the parsed file
        """
        self.yaml_file_name = yaml_file_name
        self.warning_msgs = []  # Collect all warning messages during parsing here

    def syntax_error(self, msg, obj=None):
        """
        Just raise a SyntaxError Exception, possibly with file-line-column context
        :param str msg: The message to print
        :param obj: optionally, a CommentedBase object with context
        :return: None
        """
        if isinstance(obj, comments.CommentedBase):
            raise SyntaxError(msg, (self.yaml_file_name, obj.lc.line, obj.lc.col, '')) from None
        raise SyntaxError(msg) from None

    def warning(self, msg, obj=None):
        """
        Print a warning message and store it for later use
        :param str msg: The message to print
        :param object obj: The object this message refers to
        :return: None
        """
        print_msg = 'Warning: ' + msg
        if isinstance(obj, comments.CommentedBase):
            print_msg = f'{self.yaml_file_name}:{obj.lc.line}:{obj.lc.col}: {print_msg}'

        print(print_msg, file=stderr)
        self.warning_msgs.append(msg)

    def check_metadata_validity(self, policy_metadata):
        """
        Checks the validity of metadata fields according to k8s ref. (used also with istio objects)
        :param dict policy_metadata: the dict to be checked
        :return: None
        :raises SyntaxError: if some keys are not allowed/missing
        """
        allowed_metadata_keys = {'name': [1, str], 'namespace': [0, str], 'annotations': 0, 'clusterName': 0,
                                 'creationTimestamp': 0, 'deletionGracePeriodSeconds': 0, 'deletionTimestamp': 0,
                                 'finalizers': 0, 'generateName': 0, 'generation': 0, 'labels': 0, 'managedFields': 0,
                                 'ownerReferences': 0, 'resourceVersion': 0, 'selfLink': 0, 'uid': 0}
        self.check_fields_validity(policy_metadata, 'metadata', allowed_metadata_keys)

    def check_fields_validity(self, dict_to_check, dict_name, allowed_keys, allowed_values=None):
        """
        Check that all keys in dict_to_check are legal (appear in allowed_keys)
        if value type is specified for a key, it checks valid type of values too
        and that all non-optional keys exist.
        For keys that get specific known values only, it checks that the existing value of the key in the given dict
        is in the allowed_values.
        Allowed values contains all the possible values of a key in the correct type (value and type check).
        :param dict dict_to_check: The dictionary for which the keys should be checked
        :param str dict_name: A name for the dictionary (providing context in error messages)
        :param dict allowed_keys: Map from allowed keys to usage code
         (0-optional, 1-must have, 2-not yet supported, 3-ignored even if specified) and type (type is optional) -
         if type is specified, allowed_keys maps string to array.
        :param dict allowed_values: Map from a key name to its allowed values (optional)
        :return: None
        :raises SyntaxError: if some keys are not allowed/missing
        """

        for key, key_info in allowed_keys.items():
            if isinstance(key_info, list):
                code = key_info[0]
                value_type = key_info[1]
            else:
                code = key_info
                value_type = None
            if code == 1 and key not in dict_to_check:
                self.syntax_error(f'{dict_name} must have {key} entry', dict_to_check)
            if key in dict_to_check:
                if code == 2:
                    self.syntax_error(f'{key} is not yet supported inside {dict_name}', dict_to_check)
                if code == 3:
                    self.warning(f'over-approximation analysis: {key} is not yet supported inside {dict_name},'
                                 'ignoring this key', dict_to_check)
                value = dict_to_check.get(key)
                if code == 1 and value is None:
                    self.syntax_error(f'mandatory {key} value can not be null in {dict_name}', dict_to_check)
                if value_type is not None:
                    if value is not None and not isinstance(value, value_type):
                        self.syntax_error(f'type of {key} is not {value_type} in {dict_name}',
                                          dict_to_check)
                if allowed_values and key in allowed_values:
                    if value and value not in allowed_values[key]:
                        self.syntax_error(f'{key} has invalid value in {dict_name}')

        map_keys = set(dict_to_check.keys())
        allowed_entries = set(allowed_keys.keys())
        bad_policy_keys = map_keys.difference(allowed_entries)
        if bad_policy_keys:
            self.syntax_error(f'{bad_policy_keys.pop()} is not a valid entry in the specification of {dict_name}',
                              dict_to_check)

    def validate_existing_key_is_not_null(self, dict_elem, key):
        """
        check that if key exists in dict_elem, its value is not null
        :param dict_elem: dict  the element to check
        :param key: string  the key to validate
        :return:
        """
        if key in dict_elem and dict_elem.get(key) is None:
            self.syntax_error(f'Key: \'{key}\' cannot be null ')

    def validate_array_not_empty(self, array_elem, elem_name):
        """
        chack that array_elem is a non-empty array
        :param array_elem: list  the element to check
        :param elem_name:  string  the name of the element to check
        :return:
        """
        if not isinstance(array_elem, list):
            self.syntax_error(f'Key: \'{elem_name}\' should be an array ')
        if not array_elem:
            self.syntax_error(f'Key: \'{elem_name}\' cannot be empty ')

    def get_key_array_and_validate_not_empty(self, dict_elem, key):
        """
        check that for a given key in dict_elem, if it exists - its value is a non-empty array
        :param dict_elem:  dict element to check
        :param key: string   the key to check
        :return:
        """
        key_array = dict_elem.get(key)
        if key_array is not None:
            self.validate_array_not_empty(key_array, key)
            return key_array
        return None

    def validate_dict_elem_has_non_empty_array_value(self, dict_elem, dict_key_str):
        """
        assuming that dict values are of type arrays, checking that at least one of the arrays is not empty,
        and that dict_elem is not empty
        :param dict_elem: dict element to check
        :param dict_key_str: string  the name of the key to which the dict is mapped
        """
        arr_length_set = set(len(v) for v in dict_elem.values())
        if arr_length_set == {0} or not arr_length_set:
            self.syntax_error(f"{dict_key_str} cannot be empty ")

    def validate_value_in_domain(self, value, dim_name, array, value_name):
        """
        check that a given parsed value is valid by the defined domain of its associated dimension
        :param value: the value to validate
        :param dim_name:  the dimension name (which defines the domain)
        :param array: the element where this value is parsed from
        :param value_name: the name of the value (to be shown in error message)
        :return: None
        :raises SyntaxError: if the value is not within the defined domain for the relevant dimension
        """
        is_valid, err_message = DimensionsManager().validate_value_by_domain(value, dim_name, value_name)
        if not is_valid:
            self.syntax_error(err_message, array)

    @staticmethod
    def _get_connection_set_from_properties(dest_ports, method_set=MethodSet(True), paths_dfa=None, hosts_dfa=None):
        """
        get ConnectionSet with TCP allowed connections, corresponding to input properties cube
        :param PortSet dest_ports: ports set for dset_ports dimension
        :param MethodSet method_set: methods set for methods dimension
        :param MinDFA paths_dfa: MinDFA obj for paths dimension
        :param MinDFA hosts_dfa: MinDFA obj for hosts dimension
        :return: ConnectionSet with TCP allowed connections , corresponding to input properties cube
        """
        tcp_properties = TcpLikeProperties(source_ports=PortSet(True), dest_ports=dest_ports, methods=method_set,
                                           paths=paths_dfa, hosts=hosts_dfa)
        res = ConnectionSet()
        res.add_connections('TCP', tcp_properties)
        return res


from PeerContainer import PeerContainer  # noqa: E402


class IstioGenericYamlParser(GenericYamlParser):
    """
    A class for istio yaml parser , common methods for istio policies parsers
    """
    # TODO: istio_root_namespace should be configurable from istio configuration, currently using default value for it
    # If namespace is set to istio root namespace, the policy object applies to all namespaces in a mesh

    istio_root_namespace = 'istio-config'

    def __init__(self, policy, peer_container, file_name=''):
        """
        :param dict policy: The istio policy object as provided by the yaml parser
        :param PeerContainer peer_container: The policy will be evaluated against this set of peers
        :param str file_name: The name of the file in which the istio policy object resides
        """
        GenericYamlParser.__init__(self, file_name)
        self.policy = policy
        self.peer_container = peer_container
        self.namespace = None
        self.referenced_labels = set()

    def parse_workload_selector(self, workload_selector, element_key):
        """
        Parse a LabelSelector element
        :param dict workload_selector: The element to parse
        :param str element_key: the key label of the allowed element of the label-selector
        :return: A PeerSet containing all the pods captured by this selection
        :rtype: Peer.PeerSet
        """
        if not workload_selector:  # selector :{}
            return self.peer_container.get_all_peers_group()  # An empty value means the selector selects everything

        allowed_elements = {element_key: [1, dict]}
        self.check_fields_validity(workload_selector, 'Istio policy WorkloadSelector', allowed_elements)

        match_labels = workload_selector.get(element_key)
        if not match_labels:
            self.syntax_error('One or more labels that indicate a specific set '
                              'of pods are required.', workload_selector)

        res = self.peer_container.get_all_peers_group()
        for key, val in match_labels.items():
            res &= self.peer_container.get_peers_with_label(key, [val])
        self.referenced_labels.add(':'.join(match_labels.keys()))

        if not res:
            self.warning('A workload selector selects no pods.', workload_selector)

        return res

    def parse_generic_istio_policy_fields(self, policy_kind, istio_version):
        """
        Parse the common fields in istio policies, e.g kind, apiVersion and metadata
        :param str policy_kind : the kind of current policy
        :param str istio_version : the apiVersion of the istio object
        :return: the name of the current object or None if it is not relevant object
        :rtype: str
        """
        if not isinstance(self.policy, dict):
            self.syntax_error('type of Top ds is not a map')
        if self.policy.get('kind') != policy_kind:
            return None  # Not the relevant object
        api_version = self.policy.get('apiVersion')
        if 'istio' not in api_version:
            return None  # apiVersion is not properly set
        valid_keys = {'kind': [1, str], 'apiVersion': [1, str], 'metadata': [1, dict], 'spec': [0, dict]}
        self.check_fields_validity(self.policy, policy_kind, valid_keys,
                                   {'apiVersion': [istio_version]})
        metadata = self.policy['metadata']
        self.check_metadata_validity(metadata)
        self.namespace = self.peer_container.get_namespace(metadata.get('namespace', 'default'))
        return metadata['name']
