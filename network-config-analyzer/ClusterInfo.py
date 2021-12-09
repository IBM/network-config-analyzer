#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import itertools
from collections import defaultdict
from Peer import IpBlock


class ClusterInfo:
    """
        This is a class for holding cluster info, to be used for computation of fw-rules
        class members:
        * all_peers: the set of topology all peers (Pod and IpBlock), of type: PeerSet
        * ns_dict: a map from ns (K8sNamespace) to its set of pods (set[Pod])
        * pods_labels_map: a map from label-value pairs: (label, value),  to their set of pods (set[Pod])
        * allowed_labels: a set of label keys (set[str]) that appear in one of the policy yaml files.
                          using this set to determine which label can be used for grouping pods in fw-rules computation
    """

    invalid_val = '#NO_LABEL_VALUE'

    def __init__(self, all_peers, allowed_labels, config_type):
        """
        Create a ClusterInfo object
        :param all_peers: PeerSet with the topology all peers (pods and ip blocks)
        :param allowed_labels: the set of allowed labels to be used in generated fw-rules, extracted from policy yamls
        :param config_type:  of type NetworkConfig.ConfigType: for relevant protocols inference
        """
        self.all_peers = all_peers
        self.allowed_labels = allowed_labels
        self.ns_dict = defaultdict(set)  # map from ns to set of pods
        self.pods_labels_map = defaultdict(set)  # map from (label,value) pairs to set of pods
        self.all_label_values_per_ns = defaultdict(set)  # map from (label_key,ns) to set of all valid values
        self.config_type = config_type

        all_pods = set()
        for peer in self.all_peers:
            if isinstance(peer, IpBlock):
                continue
            all_pods.add(peer)
            self.ns_dict[peer.namespace].add(peer)
            for (k, v) in peer.labels.items():
                self.pods_labels_map[(k, v)].add(peer)
                self.all_label_values_per_ns[(k, peer.namespace)].add(v)

        # update pods_labels_map with (key,"NO_LABEL_VALUE") for any key in allowed_labels
        self.add_update_pods_labels_map_with_invalid_val(all_pods)

        # update pods_labels_map with 'and' labels from allowed labels e.g: if 'app:role' is in allowed labels,
        # and pod_x has : app=frontend, role=dev, then: adding to pods_labels_map the entry: ('app:role',
        # 'frontend:dev') with pod_x contained in its mapped set. this way we can group a set of pods with common
        # labels values for a combination of multiple labels, in a fw-rule
        self.add_update_pods_labels_map_with_required_conjunction_labels()

    def add_update_pods_labels_map_with_invalid_val(self, all_pods):
        """
        Updating the pods_labels_map with (key,"NO_LABEL_VALUE") for the set of pods without this label
        :param all_pods: A set of all pods in the cluster
        :return: None
        """
        allowed_labels_flattened = self._get_allowed_labels_flattened()
        all_keys = set(key for (key, val) in self.pods_labels_map.keys())
        all_keys = all_keys.intersection(allowed_labels_flattened)
        for key in all_keys:
            # get a list of pod sets per each label value
            pod_sets_with_key_val = [self.pods_labels_map[(k, v)] for (k, v) in self.pods_labels_map.keys() if
                                     k == key]
            # get a union of all pods with any value for current label key
            pod_sets_with_key_val_union = set.union(*pod_sets_with_key_val)
            # get a set of namespaces for which at least one pod in the ns has any value for current label key
            ns_context_options = set(pod.namespace for pod in pod_sets_with_key_val_union)
            # get the set of pods that do not have current label key
            pods_without_key_set = all_pods - pod_sets_with_key_val_union
            # get the set of pods that do not have current label key, only for namespaces where at least one pod in
            # the ns has any value for current label key
            pods_without_key_set_ns_restricted = set(pod for pod in pods_without_key_set if
                                                     pod.namespace in ns_context_options)
            # add the pair (key, invalid_val) for pods_labels_map with pods from pods_without_key_set_ns_restricted
            self.pods_labels_map[(key, ClusterInfo.invalid_val)] = pods_without_key_set_ns_restricted
            self._update_all_label_values_per_ns(key, ClusterInfo.invalid_val, pods_without_key_set_ns_restricted)

    def add_update_pods_labels_map_with_required_conjunction_labels(self):
        """
        Updating the pods_labels_map with 'and' labels from allowed labels, to allow grouping of 'and' between labels
        :return: None
        """
        required_conjunction_labels = [k for k in self.allowed_labels if ':' in k]
        for key in required_conjunction_labels:
            key_labels = key.split(':')
            key_labels_values = [self.get_values_set_for_key(k) for k in key_labels]
            cartesian_product_values = list(itertools.product(*key_labels_values))
            # for each elem check how many pods exist
            for elem in cartesian_product_values:
                flattened_elem_value = ':'.join(v for v in elem)
                pod_sets_per_combined_value = []
                elem_list = list(elem)
                for index, current_key in enumerate(key_labels):
                    val_per_key = elem_list[index]
                    pod_sets_per_combined_value.append(set(self.pods_labels_map[(current_key, val_per_key)]))
                final_pod_set = set.intersection(*pod_sets_per_combined_value)
                # add to pods_labels_map the combined value for the 'and' label, when pods exist
                if final_pod_set:
                    self.pods_labels_map[(key, flattened_elem_value)] = final_pod_set
                    self._update_all_label_values_per_ns(key, flattened_elem_value, final_pod_set)

    def _update_all_label_values_per_ns(self, key, value, pods_set):
        """
        When updating pods_labels_map (with invalid value or with "combined labels"),
        should also update all_label_values_per_ns:
        Given an update to pods_labels_map with (key,value) mapped to pods_set,
        we should add 'value' to the sets mapped to the pairs (key, ns) , for each possible ns
        according to pods_set namespaces.
        :param key:  a label key of type string
        :param value:  a label value key of type string
        :param pods_set: A set of pods, of type set(Pods)
        :return: None
        """
        actual_ns_set_for_added_pair = set(pod.namespace for pod in pods_set)
        for ns in actual_ns_set_for_added_pair:
            self.all_label_values_per_ns[(key, ns)].add(value)
        return

    def get_values_set_for_key(self, key):
        """
        Get the set of all possible values per label key in the cluster
        :param key: a label key of type string
        :return: A set of values, of type set(string)
        """
        values = set(v for (k, v) in self.pods_labels_map.keys() if k == key)
        return values

    def get_all_values_set_for_key_per_namespace(self, key, ns_set):
        """
        Get the set of all possible values per label key in the cluster for a specific set of namespaces
        :param key: a label key of type string
        :param ns_set: a set of namespaces of type set[K8sNamespace]
        :return:  A set of values, of type set(string)
        """
        all_labels_values_per_ns = [self.all_label_values_per_ns[(key, ns)] for ns in ns_set]
        return set.union(*all_labels_values_per_ns)

    def _get_allowed_labels_flattened(self):
        """
        Given the set of allowed labels, convert the 'and' labels into their components separately
        :return: A set of allowed labels after this conversion.
        """
        res = set()
        for key in self.allowed_labels:
            if ':' in key:
                key_labels = set(key.split(':'))
                res |= key_labels
            else:
                res.add(key)
        return res

    def get_map_of_simple_keys_to_all_values(self, key, ns_set):
        """
        Given a key (which can possibly be complex with ":") and a set of namespaces, compute a mapping
        from each simple key in key to its set of all possible values only from namespaces in ns_set
        :param key:  a label key of type string
        :param ns_set: a set of namespaces of type set[K8sNamespace]
        :return: map_simple_key_to_all_values of type dict
        """
        map_simple_keys_to_all_values = dict()
        simple_keys_list = key.split(':')
        for simple_key in simple_keys_list:
            map_simple_keys_to_all_values[simple_key] = self.get_all_values_set_for_key_per_namespace(simple_key, ns_set)
        return map_simple_keys_to_all_values
