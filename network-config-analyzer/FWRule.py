import ipaddress

from ClusterInfo import ClusterInfo


class LabelExpr:
    """
    a class for representing a label expression
    e.g. key = K, values = {v1, v2} => the label expression is: "K in (v1,v2)"
    """

    def __init__(self, key, values, all_valid_values):
        """
        Create a LabelExpr object
        :param key: a label key of type string
        :param values: set of label values of type set[string]
        :param all_valid_values: set of all valid values for this label key
        """
        self.key = key
        self.values = values
        self.all_valid_values = all_valid_values

    @staticmethod
    def get_invalid_value_expr_str(k):
        """
       :param k:  a simple key label
       :return: a string representing that a pod doesn't have this key label: !has(k)
       """
        return f'!has({k})'

    @staticmethod
    def get_all_valid_values_expr_str(k):
        """
        :param k:  a simple key label
        :return: a string representing that a pod has this key label: has(k)
        """
        return f'has({k})'

    @staticmethod
    def get_valid_values_expr_str(k, values):
        """
        :param k: a simple key label
        :param values: a set of simple values per given key (all are valid, not all values are covered)
        :return: a string of the format "k in (v1,v2..)"
        """
        if not values:
            return ''
        vals_str = ','.join(v for v in sorted(list(values)))
        return f'{k} in ({vals_str})'

    def get_values_expr_str(self, k, values):
        """
        Given a key and its set of values, return a representing string.
        values may include invalid_val, which is represented by "!has(key)"
        If all valid values are included, the expr is generalized to "has(key)"
        :param k: a simple key label (without ":" of and labels)
        :param values:  a set of simple values per given key
        :return: a string representing this expr
        """
        expr_str_list = []
        if ClusterInfo.invalid_val in values:
            expr_str_list.append(self.get_invalid_value_expr_str(k))
        valid_values = values - {ClusterInfo.invalid_val}
        if valid_values:
            if valid_values == self.all_valid_values:
                expr_str_list.append(self.get_all_valid_values_expr_str(k))
            else:
                expr_str_list.append(self.get_valid_values_expr_str(k, valid_values))
        return " or ".join(e for e in sorted(expr_str_list))

    def __str__(self):
        """
        :return: string representing the label expression
        """
        key_labels = self.key.split(':')
        values_list_per_all_keys = [val.split(':') for val in self.values]
        expr_str_list = []
        for index, key in enumerate(key_labels):
            values_set_per_key = set(v[index] for v in values_list_per_all_keys)
            expr_str = self.get_values_expr_str(key, values_set_per_key)
            expr_str_list.append(expr_str)
        expr_str_list = ["{" + e + "}" for e in expr_str_list] if len(expr_str_list) > 1 else expr_str_list
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


class PodElement(FWRuleElement):
    """
    This is the class for single pod element in fw-rule
    """

    def __init__(self, element):
        """
        Create a PodElement object
        :param element: the element of type Pod
        """
        super().__init__({element.namespace})
        self.element = element

    def get_elem_yaml_obj(self):
        """
        :return: list[string] for the field src_pods or dst_pods in representation for yaml object
        """
        return [str(self.element.owner_name)]

    def get_pod_str(self):
        """
        :return: string for the field src_pods or dst_pods in representation for txt rule format
        """
        return f'[{self.element.owner_name}]'

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

    def get_pod_str(self):
        """
        :return: string for the field src_pods or dst_pods in representation for txt rule format
        """
        return ''

    def get_elem_yaml_obj(self):
        """
        :return: list of strings of ip-blocks represented by this element
        """
        cidr_list = []
        for interval in self.element.interval_set:
            startip = ipaddress.IPv4Address(interval.start)
            endip = ipaddress.IPv4Address(interval.end)
            cidr = [ipaddr for ipaddr in ipaddress.summarize_address_range(startip, endip)]
            cidr_list.append(str(cidr[0]))
        return cidr_list

    def __str__(self):
        """
        :return: string of the represented element
        """
        # return 'ip block: ' + str(self.element)
        cidr_list = self.get_elem_yaml_obj()
        return 'ip block: ' + ','.join(str(cidr) for cidr in cidr_list)

    def get_elem_str(self, is_src):
        """
        :param is_src: bool flag to indicate if element is src (True) or dst (False)
        :return: string of the represented element with src or dst description of fields
        """
        prefix = 'src ' if is_src else 'dst '
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
        conn_str = str(self.conn)  # self.conn.get_connections_str()
        return src_str + dst_str + ' conn: ' + conn_str

    def get_rule_str(self, is_k8s_config):
        """
        :param is_k8s_config: bool flag indicating if network policy is k8s or not
        :return: a string representation of the fw-rule, for output in txt format
        """
        src_str = self.src.get_elem_str(True)
        dst_str = self.dst.get_elem_str(False)
        conn_str = self.conn.get_connections_str(is_k8s_config)  # str(self.conn)
        return src_str + dst_str + ' conn: ' + conn_str

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        return self.src == other.src and self.dst == other.dst and self.conn == other.conn

    def __lt__(self, other):
        return str(self) < str(other)

    def get_rule_yaml_obj(self, is_k8s_config):
        """
        :param is_k8s_config: bool flag indicating if network policy is k8s or not
        :return:  a dict with content representing the fw-rule, for output in yaml format
        """
        src_ns_list = sorted([str(ns) for ns in self.src.ns_info])
        dst_ns_list = sorted([str(ns) for ns in self.dst.ns_info])
        src_pods_list = self.src.get_elem_yaml_obj() if not isinstance(self.src, IPBlockElement) else None
        dst_pods_list = self.dst.get_elem_yaml_obj() if not isinstance(self.dst, IPBlockElement) else None
        src_ip_block_list = sorted(self.src.get_elem_yaml_obj()) if isinstance(self.src, IPBlockElement) else None
        dst_ip_block_list = sorted(self.dst.get_elem_yaml_obj()) if isinstance(self.dst, IPBlockElement) else None
        conn_list = self.conn.get_connections_list(is_k8s_config)

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

    '''
    def is_rule_trivial(self):
       return isinstance(self.src, PodElement) and isinstance(self.dst, PodElement) and self.src == self.dst
    '''
