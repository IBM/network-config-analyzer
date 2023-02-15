#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from sys import stderr
from enum import Enum
from nca.CoreDS.DimensionsManager import DimensionsManager
from nca.CoreDS.TcpLikeProperties import TcpLikeProperties
from nca.CoreDS.MethodSet import MethodSet
from nca.CoreDS.ConnectionSet import ConnectionSet
from nca.CoreDS.PortSet import PortSet
from nca.CoreDS.Peer import IpBlock
from nca.Utils.NcaLogger import NcaLogger
from nca.FileScanners.GenericTreeScanner import ObjectWithLocation


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
        self.has_ipv6_addresses = False

    def set_file_name(self, yaml_file_name):
        """
        Set the resource file name, to be used for error/warning messages
        :param yaml_file_name: The file name to set
        """
        self.yaml_file_name = yaml_file_name

    def syntax_error(self, msg, obj=None):
        """
        Just raise a SyntaxError Exception, possibly with file-line-column context
        :param str msg: The message to print
        :param obj: optionally, a CommentedBase object with context
        :return: None
        """
        if isinstance(obj, ObjectWithLocation):
            raise SyntaxError(msg, (self.yaml_file_name, obj.line_number, obj.column_number, '')) from None
        raise SyntaxError(msg) from None

    def warning(self, msg, obj=None):
        """
        Print a warning message and store it for later use
        :param str msg: The message to print
        :param object obj: The object this message refers to
        :return: None
        """
        print_msg = 'Warning: ' + msg
        if isinstance(obj, ObjectWithLocation):
            print_msg = f'{self.yaml_file_name}:{obj.line_number}:{obj.column_number}: {print_msg}'

        NcaLogger().log_message(print_msg, file=stderr)
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

    def parse_generic_yaml_objects_fields(self, yaml_object, object_kind, object_version, layer_keywords, spec_required=False):
        """
        Parse and check validity of the common fields in network yaml objects as policies and services.
        e.g. kind, apiVersion, metadata and spec
        :param dict yaml_object: the source dict of the network yaml object to be parsed
        :param list[str] object_kind : the possible kind value(s) of current object
        :param list[str] object_version : the expected apiVersion(s) of the yaml object
        :param Union[str, list[str]] layer_keywords: the keyword(s) describing networkLayer that the object belongs to
        :param bool spec_required: indicates if spec field is mandatory for the parsed object
        :return: the name and namespace.name of the current object
        or None if the object does not match the expected kind and apiVersion requirements
        :rtype: Union[(str, str), (None, None)]
        """
        if not isinstance(yaml_object, dict):
            self.syntax_error('type of Top ds is not a map')
        kind = yaml_object.get('kind')
        if kind not in object_kind:
            return None, None  # Not the relevant object
        api_version = yaml_object.get('apiVersion')
        print(f'api_version field is {api_version}')
        version_keywords = [layer_keywords] if not isinstance(layer_keywords, list) else layer_keywords
        if not any(keyword in api_version for keyword in version_keywords):
            return None, None  # apiVersion is not properly set
        valid_keys = {'kind': [1, str], 'apiVersion': [1, str], 'metadata': [1, dict], 'spec': [spec_required, dict]}
        if 'k8s' in layer_keywords:
            valid_keys.update({'status': [0, dict]})
        self.check_fields_validity(yaml_object, kind, valid_keys,
                                   {'apiVersion': object_version})
        metadata = yaml_object['metadata']
        self.check_metadata_validity(metadata)
        ns_name = metadata.get('namespace', 'default') if layer_keywords != 'calico' else metadata.get('namespace')
        return metadata['name'], ns_name

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

    def check_and_update_has_ipv6_addresses(self, peers):
        """
        checks if the peer list has ipv6 addresses
        updates self.has_ipv6_addresses=true if at least on peer is an IPblock with IPv6 addresses
        :param PeerSet peers: list of peers
        """
        for peer in peers:
            if isinstance(peer, IpBlock):
                if not peer.is_ipv4_block():
                    self.has_ipv6_addresses = True
                    return  # if at least one peer is ipv6 block , this policy has_ipv6, no need to continue
