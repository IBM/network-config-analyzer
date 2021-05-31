import ipaddress

from Peer import Pod, IpBlock
from ConnectionSet import ConnectionSet


class LabelExpr:
    """
    class for representing label expressions
    """

    def __init__(self, key: str, values):
        self.key = key
        self.values = values

    def __str__(self):
        # TODO: handle the string for 'NO_LABEL_VALUE' : app in NO_LABEL_VALUE => !app
        values_set = set(self.values)
        values_str = '(' + ','.join(v for v in sorted(list(values_set))) + ')'
        if ':' not in self.key:
            return self.key + ' in ' + values_str
        else:
            key_labels = self.key.split(':')
            res = ''
            values_str_map = dict()
            # for key in key_labels:
            for index in range(0, len(key_labels)):
                key = key_labels[index]
                split_vals = [val.split(':') for val in self.values]
                val_set = [v[index] for v in split_vals]
                values_str = '(' + ','.join(v for v in sorted(list(val_set))) + ')'
                values_str_map[key] = key + ' in ' + values_str
            for key in sorted(key_labels):
                res += values_str_map[key] + ','
        return res

    def __eq__(self, other):
        return self.key == other.key and set(self.values) == set(other.values)

    def __hash__(self):
        return hash(str(self))


class FWRuleElement:
    """
    This is the base class for all fw-rule elements
    Every fw-rule element (src,dst) has a ns-level info
    """

    def __init__(self, ns_info):  # ns_info is of type set[K8sNamespace]
        self.ns_info = ns_info

    def get_pods_yaml_obj(self):
        return ['*']

    def get_pod_str(self):
        return '[*]'

    def get_ns_str(self):
        return '[' + ','.join(str(ns) for ns in sorted(list([str(ns) for ns in self.ns_info]))) + ']'

    def __str__(self):
        return 'ns: ' + self.get_ns_str() + ', pods: ' + self.get_pod_str()

    def get_elem_str(self, is_src):
        ns_prefix = 'src_ns: ' if is_src else 'dst_ns: '
        pods_prefix = ' src_pods: ' if is_src else ' dst_pods: '
        suffix = ' ' if is_src else ''
        return ns_prefix + self.get_ns_str() + pods_prefix + self.get_pod_str() + suffix

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        return set(self.ns_info) == set(other.ns_info)

    def is_system_ns(self):
        return len(self.ns_info) == 1 and str(list(self.ns_info)[0]).endswith("-system")

    # return set of pods represented by this elem
    def get_pods_set(self, cluster_info):
        res = []
        for ns in self.ns_info:
            res.extend(cluster_info.ns_dict[ns])
        return set(res)


class PodElement(FWRuleElement):
    """
    This is the class for single pod element in fw rule
    """

    def __init__(self, element: Pod):
        super().__init__([element.namespace])
        self.element = element

    def get_pods_yaml_obj(self):
        return [str(self.element)]

    def get_pod_str(self):
        # return '[' + str(self.element) + ']'
        return '[' + str(self.element.owner_name) + ']'

    def __str__(self):
        return 'ns: ' + self.get_ns_str() + ', pods: ' + self.get_pod_str()

    def get_elem_str(self, is_src):
        ns_prefix = 'src_ns: ' if is_src else 'dst_ns: '
        pods_prefix = ' src_pods: ' if is_src else ' dst_pods: '
        suffix = ' ' if is_src else ''
        return ns_prefix + self.get_ns_str() + pods_prefix + self.get_pod_str() + suffix

    def __hash__(self):
        return hash(str(self))

    # TODO: should compare to other types as well, and make the comparison based on actual pods set?
    def __eq__(self, other):
        return isinstance(other, PodElement) and self.element == other.element and set(self.ns_info) == set(
            other.ns_info)

    # return set of pods represented by this elem
    def get_pods_set(self, cluster_info):
        return {self.element}


class PodLabelsElement(FWRuleElement):
    """
    This is the class for pods-labels expr element in fw rule
    """

    # TODO: is it possible to have such element with len(ns_info)>1? if not, should add support for such merge?
    def __init__(self, element: LabelExpr, ns_info):  # ns_info: set[K8sNamespace]
        super().__init__(ns_info)
        self.element = element

    def get_pods_yaml_obj(self):
        return [str(self.element)]

    def get_pod_str(self):
        return '[' + str(self.element) + ']'

    def __str__(self):
        return 'ns: ' + self.get_ns_str() + ', pods: ' + self.get_pod_str()

    def get_elem_str(self, is_src):
        ns_prefix = 'src_ns: ' if is_src else 'dst_ns: '
        pods_prefix = ' src_pods: ' if is_src else ' dst_pods: '
        suffix = ' ' if is_src else ''
        return ns_prefix + self.get_ns_str() + pods_prefix + self.get_pod_str() + suffix

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        return isinstance(other, PodLabelsElement) and self.element == other.element and set(self.ns_info) == set(
            other.ns_info)

    # return set of pods represented by this elem
    def get_pods_set(self, cluster_info):
        res = []
        ns_pods = set(super().get_pods_set(cluster_info))
        key = self.element.key
        values = self.element.values
        for v in values:
            pods_with_label_val = cluster_info.pods_labels_map[(key, v)]
            pods_with_label_val_in_ns = set(pods_with_label_val).intersection(ns_pods)
            res.extend(pods_with_label_val_in_ns)
        return set(res)


# TODO: should it be a sub-type of FWRuleElement?
class IPBlockElement(FWRuleElement):
    """
    Class for ip-block element in a fw-rule
    """

    def __init__(self, element: IpBlock):
        super().__init__(set())  # no ns for ip-block
        self.element = element

    def get_pod_str(self):
        return ''

    def get_ip_cidr_list(self):
        cidr_list = []
        for interval in self.element.interval_set:
            startip = ipaddress.IPv4Address(interval.start)
            endip = ipaddress.IPv4Address(interval.end)
            cidr = [ipaddr for ipaddr in ipaddress.summarize_address_range(startip, endip)]
            cidr_list.append(str(cidr[0]))
        return cidr_list

    def __str__(self):
        # return 'ip block: ' + str(self.element)
        cidr_list = self.get_ip_cidr_list()
        return 'ip block: ' + ','.join(str(cidr) for cidr in cidr_list)

    def get_elem_str(self, is_src):
        prefix = 'src ' if is_src else 'dst '
        suffix = ' ' if is_src else ''
        return prefix + str(self) + suffix

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        return isinstance(other, IPBlockElement) and self.element == other.element

    def get_pods_set(self, cluster_info):
        return set()


class FWRule:
    """
    Class for holding a fw-rule: src, dst, connection-set
    """

    def __init__(self, src: FWRuleElement, dst: FWRuleElement, conn: ConnectionSet):
        self.src = src
        self.dst = dst
        self.conn = conn

    def is_rule_trivial(self):
        return isinstance(self.src, PodElement) and isinstance(self.dst, PodElement) and self.src == self.dst

    # filter out rules of "-system" ns with an ip-block, or from such ns to itself
    # TODO: also re-format the rule if ns is a combination of both 'system' and non 'system'
    def should_rule_be_filtered_out(self):
        if self.src.is_system_ns() and isinstance(self.dst, IPBlockElement):
            return True
        elif self.dst.is_system_ns() and isinstance(self.src, IPBlockElement):
            return True
        elif self.src.is_system_ns() and self.dst.is_system_ns():
            return True
        return False

    def __str__(self):
        src_str = self.src.get_elem_str(True)
        dst_str = self.dst.get_elem_str(False)
        conn_str = self.conn.get_connections_str()  # str(self.conn)
        return src_str + dst_str + ' conn: ' + conn_str

    def __hash__(self):
        return hash(str(self))
