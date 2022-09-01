#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from sys import stderr
from Peer import PeerSet, Pod, IpBlock
from K8sNamespace import K8sNamespace
from K8sService import K8sService
from GenericYamlParser import GenericYamlParser


class PeerContainer:
    """
    This class holds a representation of the network topology: peers , namespaces and services
    It contains all the topology objects and used to get their info, e.g to filter the eps by labels and by namespaces
    """

    def __init__(self, peer_set, namespaces, services_list, representative_peers):
        """
        create a PeerContainer object
        :param PeerSet peer_set: the parsed peers from input resources
        :param dict namespaces: the parsed namespaces from input resources
        :param list services_list: the parsed services list from input resources, based on it ,
        the services dict is created after populating target pods
        :param dict representative_peers: the parsed representative peers
        """
        self.peer_set = peer_set
        self.representative_peers = representative_peers
        self.namespaces = namespaces  # mapping from namespace name to the actual K8sNamespace object
        self.services = {}  # mapping from service name to the actual K8sService object
        self._set_services_and_populate_target_pods(services_list)

    def __eq__(self, other):
        if isinstance(other, PeerContainer):
            return self.peer_set == other.peer_set and self.namespaces == other.namespaces \
                and self.services == other.services
        return False

    def delete_all_namespaces(self):
        if self.get_num_peers() > 0:  # Only delete namespaces if no peers are present
            return False
        self.namespaces.clear()
        return True

    def get_namespaces(self):
        return self.namespaces

    def get_namespace(self, namespace, warn_if_missing=True):
        """
         Get a K8sNamespace object for a given namespace name. If namespace is missing, then add it to the
         container's namespaces. Sources for new namespaces may be networkpolicies or config queries
        :param str namespace: The name of the required namespace
        :param bool warn_if_missing: indicates if missing namespace is istio_root_ns which is handled as special case
        :return: A relevant K8sNamespace
        :rtype: K8sNamespace
        """
        if namespace not in self.namespaces:
            if warn_if_missing:
                print('Namespace', namespace, 'is missing from the network configuration', file=stderr)
            k8s_ns = K8sNamespace(namespace)
            self.namespaces[namespace] = k8s_ns
        return self.namespaces[namespace]

    def delete_all_peers(self):
        self.peer_set.clear()
        self.representative_peers.clear()
        return True

    def get_num_peers(self):
        return len(self.peer_set)

    def clear_pods_extra_labels(self):
        for peer in self.peer_set:
            peer.clear_extra_labels()

    def get_peers_with_label(self, key, values, action=GenericYamlParser.FilterActionType.In, namespace=None):
        """
        Return all peers that have a specific key-value label (in a specific namespace)
        :param str key: The relevant key
        :param list[str] values: A list of possible values to match
        :param FilterActionType action: how to filter the values
        :param K8sNamespace namespace: If not None, only consider peers in this namespace
        :return PeerSet: All peers that (do not) have the key-value as their label
        """
        res = PeerSet()
        for peer in self.peer_set:
            # Note: It seems as if the semantics of NotIn is "either key does not exist, or its value is not in values"
            # Reference: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/
            if namespace is not None and peer.namespace != namespace:
                continue
            if action == GenericYamlParser.FilterActionType.In:
                if peer.labels.get(key) in values or peer.extra_labels.get(key) in values:
                    res.add(peer)
            elif action == GenericYamlParser.FilterActionType.NotIn:
                if peer.labels.get(key) not in values and peer.extra_labels.get(key) not in values:
                    res.add(peer)
            elif action == GenericYamlParser.FilterActionType.Contain:
                if values[0] in peer.labels.get(key, '') or values[0] in peer.extra_labels.get(key, ''):
                    res.add(peer)
            elif action == GenericYamlParser.FilterActionType.StartWith:
                if peer.labels.get(key, '').startswith(values[0]) or peer.extra_labels.get(key, '').startswith(
                        values[0]):
                    res.add(peer)
            elif action == GenericYamlParser.FilterActionType.EndWith:
                if peer.labels.get(key, '').endswith(values[0]) or peer.extra_labels.get(key, '').endswith(values[0]):
                    res.add(peer)
        return res

    def get_peers_with_key(self, namespace, key, does_not_exist):
        """
        Return all peers (possibly in a given namespace) that have a specific key in their labels
        :param K8sNamespace namespace: If not none - only include peers in this namespace
        :param str key: The relevant key
        :param bool does_not_exist: Whether to only include peers that do not have this key
        :return PeerSet: All peers that (do not) have the key
        """
        res = PeerSet()
        for peer in self.peer_set:
            if namespace is not None and peer.namespace != namespace:
                continue
            if (key in peer.labels or key in peer.extra_labels) ^ does_not_exist:
                res.add(peer)
        return res

    def get_namespace_pods_with_label(self, key, values, action=GenericYamlParser.FilterActionType.In):
        """
        Return all pods in namespace with a given key-value label
        :param str key: The relevant key
        :param list[str] values: possible values for the key
        :param FilterActionType action: how to filter the values
        :return PeerSet: All pods in namespaces that have (or not) the given key-value label
        """
        res = PeerSet()
        for peer in self.peer_set:
            if peer.namespace is None:
                continue
            # Note: It seems as if the semantics of NotIn is "either key does not exist, or its value is not in values"
            # Reference: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/
            if action == GenericYamlParser.FilterActionType.In:
                if peer.namespace.labels.get(key, '') in values:
                    res.add(peer)
            elif action == GenericYamlParser.FilterActionType.NotIn:
                if peer.namespace.labels.get(key, '') not in values:
                    res.add(peer)
            elif action == GenericYamlParser.FilterActionType.Contain:
                if values[0] in peer.namespace.labels.get(key, ''):
                    res.add(peer)
            elif action == GenericYamlParser.FilterActionType.StartWith:
                if peer.namespace.labels.get(key, '').startswith(values[0]):
                    res.add(peer)
            elif action == GenericYamlParser.FilterActionType.EndWith:
                if peer.namespace.labels.get(key, '').endswith(values[0]):
                    res.add(peer)
        return res

    def get_namespace_pods_with_key(self, key, does_not_exist):
        """
        Return all pods in namespaces that have a given key
        :param str key: The relevant key
        :param bool does_not_exist: whether to check for the inexistence of this key
        :return PeerSet: All pods in namespace with (or without) the given key
        """
        res = PeerSet()
        for peer in self.peer_set:
            if peer.namespace is None:
                continue
            if (key in peer.namespace.labels) ^ does_not_exist:
                res.add(peer)
        return res

    def get_namespace_pods(self, namespace):
        """
        Return all pods that are in a given namespace
        :param K8sNamespace namespace: The target namespace
        :return PeerSet: All pods in the namespace
        """
        if namespace is None:
            return self.get_all_peers_group()
        res = PeerSet()
        for peer in self.peer_set:
            if peer.namespace == namespace:
                res.add(peer)
        return res

    def get_pods_with_service_name_containing_given_string(self, name_substring):
        """
        Returns all pods that belong to services whose name contains the given substring
        :param str name_substring: the service name substring
        :return: PeerSet
        """
        res = PeerSet()
        for key, val in self.services.items():
            if name_substring in key:
                res |= val.target_pods
        return res

    def get_all_services_target_pods(self, update_compare_ns_flag=False):
        """
        Returns all pods that belong to services
        :rtype: PeerSet
        """
        res = PeerSet()
        for service in self.services.values():
            res |= service.target_pods
        return res

    def get_services_target_pods_in_namespace(self, namespace):
        """
        Returns all pods that belong to services in the given namespace
        :param K8sNamespace namespace:   namespace object
        :rtype: PeerSet
        """
        res = PeerSet()
        for service in self.services.values():
            if service.namespace == namespace:
                res |= service.target_pods
        return res

    def get_pods_with_service_account_name(self, sa_name, namespace_str):
        """
        Return all pods that are with a service account name in a given namespace
        :param sa_name: string  the service account name
        :param namespace_str:  string  the namespace str
        :rtype PeerSet
        """
        res = PeerSet()
        for peer in self.peer_set:
            if isinstance(peer, Pod) and peer.service_account_name == sa_name and peer.namespace.name == namespace_str:
                res.add(peer)
        return res

    def get_profile_pods(self, profile_name, first_profile_only):
        """
        Return all the pods that have a specific profile assigned
        :param str profile_name: The name of the target profile
        :param bool first_profile_only: whether to only consider the first profile of each pod
        :return PeerSet: The set of pods with the given profile
        """
        res = PeerSet()
        for peer in self.peer_set:
            if peer.has_profiles():
                if first_profile_only:
                    if peer.get_first_profile_name() == profile_name:
                        res.add(peer)
                else:
                    if profile_name in peer.profiles:
                        res.add(peer)
        return res

    def get_all_peers_group(self, add_external_ips=False, include_globals=True):
        """
        Return all peers known in the system
        :param bool add_external_ips: Whether to also add the full range of ips
        :param bool include_globals: Whether to include global peers
        :return PeerSet: The required set of peers
        """
        res = PeerSet()
        for peer in self.peer_set:
            if include_globals or not peer.is_global_peer():
                res.add(peer)
        if add_external_ips:
            res.add(IpBlock.get_all_ips_block())
        return res

    def get_all_global_peers(self):
        """
        Return all global peers known in the system
        :return PeerSet: The required set of peers
        """
        res = PeerSet()
        for peer in self.peer_set:
            if peer.is_global_peer():
                res.add(peer)
        return res

    def get_all_namespaces_str_list(self):
        return list(self.namespaces.keys())

    def get_service_by_name_and_ns(self, name, ns):
        """
        Returns a service with a given name and a given namespace
        :param name: the service name
        :param ns: the service namespace
        :return: The K8sService object
        """
        full_name = K8sService.service_full_name(name, ns)
        return self.services.get(full_name)

    def _set_services_and_populate_target_pods(self, service_list):
        """
        Populates services from the given service list,
        and for every service computes and populates its target pods.
        :param list service_list: list of service in K8sService format
        :return: None
        """
        for srv in service_list:
            # populate target ports
            if srv.selector:
                srv.target_pods = self.peer_set
            for key, val in srv.selector.items():
                srv.namespace = self.get_namespace(srv.namespace_name)
                srv.target_pods &= self.get_peers_with_label(key, [val], GenericYamlParser.FilterActionType.In,
                                                             srv.namespace)
            # remove target_pods that don't contain named ports referenced by target_ports
            for port in srv.ports.values():
                if not isinstance(port.target_port, str):
                    continue
                # check if all pods include this named port, and remove those that don't
                pods_to_remove = PeerSet()
                for pod in srv.target_pods:
                    pod_named_port = pod.named_ports.get(port.target_port)
                    if not pod_named_port:
                        print(f'Warning: The named port {port.target_port} referenced in Service {srv.name}'
                              f' is not defined in the pod {pod}. Ignoring the pod')
                        pods_to_remove.add(pod)
                    elif pod_named_port[1] != port.protocol:
                        print(f'Warning: The protocol {port.protocol} in the named port {port.target_port} '
                              f'referenced in Service {srv.name} does not match the protocol {pod_named_port[1]} '
                              f'defined in the pod {pod}. Ignoring the pod')
                        pods_to_remove.add(pod)
                srv.target_pods -= pods_to_remove
            if not srv.target_pods:
                print(f'Warning: The service {srv.name} does not reference any pod')
            self.services[srv.full_name()] = srv
