#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from ClusterInfo import ClusterInfo
from ConnectionSet import ConnectionSet
from K8sNamespace import K8sNamespace
from NetworkConfig import NetworkConfig
from Peer import ClusterEP, IpBlock, Pod


class LabelExpr:
    """
    a class for representing a label expression
    e.g. key = K, values = {v1, v2} => the label expression is: "K in (v1,v2)"
    """

    def __init__(self, key, values, map_simple_keys_to_all_values, all_values):
        """
        Create a LabelExpr object
        :param key: a label key of type string (can be a "complex" key with ":")
        :param values: set of label values of type set[string]
        :param map_simple_keys_to_all_values: dict that maps all simple keys from key to their
               sets of all possible values
        """
        self.key = key
        self.values = values
        self.map_simple_keys_to_all_values = map_simple_keys_to_all_values
        self.all_values = all_values

    @staticmethod
    def get_invalid_value_expr_str(k):
        """
        :param k:  a key label
        :return: a string representing that a pod doesn't have this key label: !has(k)
        """
        return ' and '.join(f'!has({key})' for key in sorted(k.split(':')))

    @staticmethod
    def get_all_valid_values_expr_str(k):
        """
        :param k:  a key label
        :return: a string representing that a pod has this key label: has(k)
        """
        return ' and '.join(f'has({key})' for key in sorted(k.split(':')))

    @staticmethod
    def get_valid_values_expr_str(k, values, complement_values, ns_has_pods_without_label_k):
        """
        :param k: a simple key label
        :param values: a set of simple values per given key (all are valid, not all values are covered)
        :param complement_values: the set of complement values
        :param ns_has_pods_without_label_k: bool flag, indicating if there exist pod w/o label k (in relevant ns)
        :return: string in one of the following formats:
                "k in (v1,v2...)"                   [used if values list is shorter than complement values]
                "k not in (v1,v2,...)"              [used if complement values list is shorter than values list &
                                                     all pods have label k]
                "has(k) and k not in (v1,v2,...)"  [used if complement values list is shorter than values list &
                                                     not all pods have label k]
        """
        if not values:
            return ''
        shorter_values_list = values
        containment_str = 'in'
        prefix_expr = ''
        if complement_values and len(complement_values) < len(values):
            shorter_values_list = complement_values
            containment_str = 'not in'
            if ns_has_pods_without_label_k:
                prefix_expr = f'has({k}) and '
        vals_str = ','.join(v for v in sorted(list(shorter_values_list)))
        if len(shorter_values_list) == 1:
            equality_operator = '=' if containment_str == 'in' else '!='
            label_containment_expr = f'{k}{equality_operator}{vals_str}'
        else:
            label_containment_expr = f'{k} {containment_str} ({vals_str})'
        return f'({prefix_expr}{label_containment_expr})' if prefix_expr else label_containment_expr

    def get_values_expr_str_per_simple_key(self, k, values):
        """
        Given a key and its set of values, return a representing string.
        values may include invalid_val, which is represented by "!has(key)"
        If all valid values are included, the expr is generalized to "has(key)"
        :param k: a simple key label (without ":" of and labels)
        :param values:  a set of simple values per given key
        :return: a string representing this expr
        """
        expr_str_list = []
        ns_has_pods_without_label_k = False
        if ClusterInfo.invalid_val in values:
            expr_str_list.append(self.get_invalid_value_expr_str(k))
        valid_values = values - {ClusterInfo.invalid_val}
        all_valid_values = self.map_simple_keys_to_all_values[k] - {ClusterInfo.invalid_val}
        if ClusterInfo.invalid_val in self.map_simple_keys_to_all_values[k]:
            ns_has_pods_without_label_k = True
        if valid_values:
            if valid_values == all_valid_values and len(all_valid_values) > 1:
                expr_str_list.append(self.get_all_valid_values_expr_str(k))
            else:
                complement_values = all_valid_values - valid_values
                expr_str_list.append(
                    self.get_valid_values_expr_str(k, valid_values, complement_values, ns_has_pods_without_label_k))
        res_expr_str = " or ".join(e for e in sorted(expr_str_list))
        return '{' + res_expr_str + '}' if len(expr_str_list) > 1 else res_expr_str

    def __str__(self):
        """
        :return: string representing the label expression
        """
        # reasoning of original key (possibly composed key)
        all_valid_values = set(v for v in self.all_values if ClusterInfo.invalid_val not in v)
        if self.values == all_valid_values and len(all_valid_values) > 1:
            # returns an expression of all valid values (e.g. has(app) and has(tier) )
            return self.get_all_valid_values_expr_str(self.key)

        # reasoning of simple keys separately
        key_labels = self.key.split(':')
        values_list_per_all_keys = [val.split(':') for val in self.values]
        expr_str_list = []
        for index, key in enumerate(key_labels):
            values_set_per_key = set(v[index] for v in values_list_per_all_keys)
            expr_str = self.get_values_expr_str_per_simple_key(key, values_set_per_key)
            expr_str_list.append(expr_str)

        if len(expr_str_list) == 1:
            return expr_str_list[0].replace('{', '').replace('}', '')
        return ' and '.join(e for e in sorted(expr_str_list))

    def __eq__(self, other):
        return self.key == other.key and self.values == other.values

    def __hash__(self):
        return hash(str(self))


class FWRuleElement:
    """
    This is the base class for all fw-rule elements (for either src or dst)
    Every fw-rule element (src,dst) has a ns-level info
    """

    def __init__(self, ns_info):
        """
        Create a FWRuleElement object
        :param ns_info: set of namespaces, of type: set[K8sNamespace]
        """
        self.ns_info = ns_info

    def get_elem_yaml_obj(self):
        """
        :return: list[string] for the field src_pods or dst_pods in representation for yaml object
        """
        # for an element of type FWRuleElement, the level of granularity is entire ns
        # thus, returning  "*" for representation of all pods in the ns
        return ['*']

    def get_pod_str(self):
        """
        :return: string for the field src_pods or dst_pods in representation for txt rule format
        """
        return '[*]'

    def get_ns_str(self):
        """
        :return: string  for the field src_ns or dst_ns in representation for txt rule format
        """
        return '[' + ','.join(str(ns) for ns in sorted(list([str(ns) for ns in self.ns_info]))) + ']'

    def __str__(self):
        """
        :return: string of the represented element
        """
        return f'ns: {self.get_ns_str()}, pods: {self.get_pod_str()}'

    def get_elem_str(self, is_src):
        """
        :param is_src: bool flag to indicate if element is src (True) or dst (False)
        :return: string of the represented element with src or dst description of fields
        """
        ns_prefix = 'src_ns: ' if is_src else 'dst_ns: '
        pods_prefix = ' src_pods: ' if is_src else ' dst_pods: '
        suffix = ' ' if is_src else ''
        return ns_prefix + self.get_ns_str() + pods_prefix + self.get_pod_str() + suffix

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        return self.ns_info == other.ns_info

    def is_system_ns(self):
        """
        :return: True if this element has one namespace and it ends with "system"
        """
        return len(self.ns_info) == 1 and str(list(self.ns_info)[0]).endswith("-system")

    def get_pods_set(self, cluster_info):
        """
        :param cluster_info: an object of type ClusterInfo, with relevant cluster topology info
        :return: a set of pods in the cluster represented by this element
        """
        res = set()
        for ns in self.ns_info:
            res |= cluster_info.ns_dict[ns]
        return res

    @staticmethod
    def create_fw_elements_from_base_element(base_elem):
        """
        create a list of fw-rule-elements from base-element
        :param base_elem: of type ClusterEP/IpBlock/K8sNamespace
        :return: list fw-rule-elements of type:  list[PodElement]/list[IPBlockElement]/list[FWRuleElement]
        """
        if isinstance(base_elem, ClusterEP):
            return [PodElement(base_elem)]
        elif isinstance(base_elem, IpBlock):
            return [IPBlockElement(ip) for ip in base_elem.split()]
        elif isinstance(base_elem, K8sNamespace):
            return [FWRuleElement({base_elem})]
        # unknown base-elem type
        return None


class PodElement(FWRuleElement):
    """
    This is the class for single pod element in fw-rule
    """

    def __init__(self, element, output_as_deployment=True):
        """
        Create a PodElement object
        :param element: the element of type Pod
        """
        super().__init__({element.namespace})
        self.element = element
        self.output_as_deployment = output_as_deployment

    def get_elem_yaml_obj(self):
        """
        :return: list[string] for the field src_pods or dst_pods in representation for yaml object
        """
        return [str(self._get_pod_name())]

    def get_pod_str(self):
        """
        :return: string for the field src_pods or dst_pods in representation for txt rule format
        """
        return f'[{self._get_pod_name()}]'

    def _get_pod_name(self):
        """
        return pod name :using elem.owner_name for Pod elem (if exists), and elem.name for HostEP
        :return: string representing pod element name
        """
        if self.output_as_deployment and isinstance(self.element, Pod) and self.element.owner_name:
            return self.element.owner_name
        return self.element.name

    def __str__(self):
        """
        :return: string of the represented element
        """
        return f'ns: {self.get_ns_str()}, pods: {self.get_pod_str()}'

    def get_elem_str(self, is_src):
        """
        :param is_src: bool flag to indicate if element is src (True) or dst (False)
        :return: string of the represented element with src or dst description of fields
        """
        ns_prefix = 'src_ns: ' if is_src else 'dst_ns: '
        pods_prefix = ' src_pods: ' if is_src else ' dst_pods: '
        suffix = ' ' if is_src else ''
        return ns_prefix + self.get_ns_str() + pods_prefix + self.get_pod_str() + suffix

    def __hash__(self):
        return hash(str(self))

    # TODO: should compare to other types as well, and make the comparison based on actual pods set?
    def __eq__(self, other):
        return isinstance(other, PodElement) and self.element == other.element and super().__eq__(other)

    def get_pods_set(self, cluster_info):
        """
        :param cluster_info: an object of type ClusterInfo, with relevant cluster topology info
        :return: a set of pods in the cluster represented by this element
        """
        return {self.element}


class PodLabelsElement(FWRuleElement):
    """
    This is the class for pods label-expr element in fw rule
    """

    # TODO: is it possible to have such element with len(ns_info)>1? if not, should add support for such merge?
    def __init__(self, element, ns_info):
        """
        Create an object of type PodLabelsElement
        :param element: an element of type LabelExpr
        :param ns_info: namespace set of type set[K8sNamespace]
        """
        super().__init__(ns_info)
        self.element = element

    def get_elem_yaml_obj(self):
        """
        :return: list[string] for the field src_pods or dst_pods in representation for yaml object
        """
        return [str(self.element)]

    def get_pod_str(self):
        """
        :return: string for the field src_pods or dst_pods in representation for txt rule format
        """
        return f'[{self.element}]'

    def __str__(self):
        """
        :return: string of the represented element
        """
        return f'ns: {self.get_ns_str()}, pods: {self.get_pod_str()}'

    def get_elem_str(self, is_src):
        """
        :param is_src: bool flag to indicate if element is src (True) or dst (False)
        :return: string of the represented element with src or dst description of fields
        """
        ns_prefix = 'src_ns: ' if is_src else 'dst_ns: '
        pods_prefix = ' src_pods: ' if is_src else ' dst_pods: '
        suffix = ' ' if is_src else ''
        return ns_prefix + self.get_ns_str() + pods_prefix + self.get_pod_str() + suffix

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        return isinstance(other, PodLabelsElement) and self.element == other.element and super().__eq__(other)

    def get_pods_set(self, cluster_info):
        """
        :param cluster_info: an object of type ClusterInfo, with relevant cluster topology info
        :return: a set of pods in the cluster represented by this element
        """
        res = set()
        ns_pods = super().get_pods_set(cluster_info)
        key = self.element.key
        values = self.element.values
        for v in values:
            pods_with_label_val_in_ns = cluster_info.pods_labels_map[(key, v)] & ns_pods
            res |= pods_with_label_val_in_ns
        return res


# TODO: should it be a sub-type of FWRuleElement?
class IPBlockElement(FWRuleElement):
    """
    Class for ip-block element in a fw-rule
    """

    def __init__(self, element):
        """
        Create an object of IPBlockElement
        :param element: an element of type IpBlock
        """
        super().__init__(set())  # no ns for ip-block
        self.element = element

    def get_ns_str(self):
        return ''

    def get_pod_str(self):
        """
        :return: string for the field src_pods or dst_pods in representation for txt rule format
        """
        return ''

    def get_elem_yaml_obj(self):
        """
        :return: list of strings of ip-blocks represented by this element
        """
        return self.element.get_cidr_list()

    def __str__(self):
        """
        :return: string of the represented element
        """
        return self.element.get_ip_range_or_cidr_str()

    def get_elem_str(self, is_src):
        """
        :param is_src: bool flag to indicate if element is src (True) or dst (False)
        :return: string of the represented element with src or dst description of fields
        """
        prefix = 'src: ' if is_src else 'dst: '
        suffix = ' ' if is_src else ''
        return prefix + str(self) + suffix

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        return isinstance(other, IPBlockElement) and self.element == other.element and super().__eq__(other)

    def get_pods_set(self, cluster_info):
        """
        :param cluster_info: an object of type ClusterInfo, with relevant cluster topology info
        :return: a set of pods in the cluster represented by this element
        """
        # an ip block element does not represent any pods
        return set()


class FWRule:
    """
    Class for holding a fw-rule: src, dst, connection-set
    """

    rule_csv_header = ['query', 'src_ns', 'src_pods', 'dst_ns', 'dst_pods', 'connection']
    supported_formats = {'txt', 'yaml', 'csv', 'md'}

    def __init__(self, src, dst, conn):
        """
        Create an object of FWRule
        :param src: src element of type FWRuleElement
        :param dst: dst element of type FWRuleElement
        :param conn: allowed connections of type ConnectionSet
        """
        self.src = src
        self.dst = dst
        self.conn = conn

    # TODO: also re-format the rule if ns is a combination of both 'system' and non 'system'
    def should_rule_be_filtered_out(self):
        """
        filter out rules of "-system" ns with an ip-block, or from such ns to itself
        :return: True if rule should be filtered out due to  "-system" namespace
        """
        if self.src.is_system_ns() and isinstance(self.dst, IPBlockElement):
            return True
        elif self.dst.is_system_ns() and isinstance(self.src, IPBlockElement):
            return True
        elif self.src.is_system_ns() and self.dst.is_system_ns():
            return True
        return False

    def __str__(self):
        """
        :return: a string representation of the fw-rule
        """
        src_str = self.src.get_elem_str(True)
        dst_str = self.dst.get_elem_str(False)
        conn_str = str(self.conn)
        return src_str + dst_str + ' conn: ' + conn_str

    def get_rule_str(self, use_complement_simplification):
        """
        :param bool use_complement_simplification: flag for complement simplification in connection set rep
        :return: a string representation of the fw-rule, for output in txt format
        """
        src_str = self.src.get_elem_str(True)
        dst_str = self.dst.get_elem_str(False)
        conn_str = self.conn.get_simplified_connections_representation(True, use_complement_simplification)
        return src_str + dst_str + ' conn: ' + conn_str + '\n'

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        return self.src == other.src and self.dst == other.dst and self.conn == other.conn

    def __lt__(self, other):
        return str(self) < str(other)

    def get_rule_component_str(self, component, use_complement_simplification):
        """
        This function is used to produce a csv row for a fw-rule
        :param str component: a fw-rule required component  from components in rule_csv_header
        :param bool use_complement_simplification: flag for complement simplification in connection set rep
        :return: string of the required rule component
        """
        if component == 'src_ns':
            return self.src.get_ns_str()
        elif component == 'src_pods':
            return str(self.src) if isinstance(self.src, IPBlockElement) else self.src.get_pod_str()
        elif component == 'dst_ns':
            return self.dst.get_ns_str()
        elif component == 'dst_pods':
            return str(self.dst) if isinstance(self.dst, IPBlockElement) else self.dst.get_pod_str()
        elif component == 'connection':
            return self.conn.get_simplified_connections_representation(True, use_complement_simplification)
        return ''

    def get_rule_csv_row(self, use_complement_simplification):
        """
        :param bool use_complement_simplification: flag for complement simplification in connection set rep
        :return: a list of strings, representing the csv row for this fw-rule
        """
        row = []
        for component in FWRule.rule_csv_header:
            row.append(self.get_rule_component_str(component, use_complement_simplification))
        return row

    def get_rule_yaml_obj(self, use_complement_simplification):
        """
        :param bool use_complement_simplification: flag for complement simplification in connection set rep
        :return:  a dict with content representing the fw-rule, for output in yaml format
        """
        src_ns_list = sorted([str(ns) for ns in self.src.ns_info])
        dst_ns_list = sorted([str(ns) for ns in self.dst.ns_info])
        src_pods_list = self.src.get_elem_yaml_obj() if not isinstance(self.src, IPBlockElement) else None
        dst_pods_list = self.dst.get_elem_yaml_obj() if not isinstance(self.dst, IPBlockElement) else None
        src_ip_block_list = sorted(self.src.get_elem_yaml_obj()) if isinstance(self.src, IPBlockElement) else None
        dst_ip_block_list = sorted(self.dst.get_elem_yaml_obj()) if isinstance(self.dst, IPBlockElement) else None
        conn_list = self.conn.get_simplified_connections_representation(False, use_complement_simplification)

        rule_obj = {}
        if src_ip_block_list is None and dst_ip_block_list is None:
            rule_obj = {'src_ns': src_ns_list,
                        'src_pods': src_pods_list,
                        'dst_ns': dst_ns_list,
                        'dst_pods': dst_pods_list,
                        'connection': conn_list}
        elif src_ip_block_list is not None:
            rule_obj = {'src_ip_block': src_ip_block_list,
                        'dst_ns': dst_ns_list,
                        'dst_pods': dst_pods_list,
                        'connection': conn_list}

        elif dst_ip_block_list is not None:
            rule_obj = {'src_ns': src_ns_list,
                        'src_pods': src_pods_list,
                        'dst_ip_block': dst_ip_block_list,
                        'connection': conn_list}
        return rule_obj

    def get_rule_in_req_format(self, req_format, config_type):
        """
        get fw-rule representation according to required format :
        yaml: dict object
        csv: list of strings
        txt: string
        :param str req_format: a string of the required format, should be in supported_formats
        :param NetworkConfig.ConfigType config_type: the network configuration type
        :return: Union[str,dict,list] the fw-rule representation according to required format
        """
        use_complement_simplification = self.use_connection_set_complement_simplification(config_type)
        if req_format == 'yaml':
            return self.get_rule_yaml_obj(use_complement_simplification)
        if req_format in ['csv', 'md']:
            return self.get_rule_csv_row(use_complement_simplification)
        if req_format == 'txt':
            return self.get_rule_str(use_complement_simplification)
        return None

    @staticmethod
    def use_connection_set_complement_simplification(config_type):
        # currently disabling this for Istio config, since complement with regex may be time consuming computation
        return config_type != NetworkConfig.ConfigType.Istio

    @staticmethod
    def create_fw_rules_from_base_elements(src, dst, connections):
        """
        create fw-rules from single pair of base elements (src,dst) and a given connection set
        :param ConnectionSet connections: the allowed connections from src to dst
        :param src: a base-element  of type: ClusterEP/K8sNamespace/ IpBlock
        :param dst: a base-element  of type: ClusterEP/K8sNamespace/IpBlock
        :return: list with created fw-rules
        :rtype list[FWRule]
        """
        src_elem = FWRuleElement.create_fw_elements_from_base_element(src)
        dst_elem = FWRuleElement.create_fw_elements_from_base_element(dst)
        if src_elem is None or dst_elem is None:
            return []
        return [FWRule(src, dst, connections) for src in src_elem for dst in dst_elem]
