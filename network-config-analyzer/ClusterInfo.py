import itertools
from collections import defaultdict
from Peer import IpBlock


class ClusterInfo:
    """
        This is a class for holding cluster info, to be used for computation of fw-rules
        ns_dict: a map from ns to its set of pods
        pods_labels_map: a map from pods-labels (label, value) to its set of pods
        allowed_labels: the set of label keys that appear in the policy yaml file, which can be used for grouping in
        fw-rules computation
    """

    def __init__(self, all_peers, allowed_labels, config):
        self.config = config
        self.all_peers = all_peers
        self.ns_dict = defaultdict(list)  # map from ns to set of pods
        self.ns_labels_map = defaultdict(list)  # map from ns_labels to set of pods
        self.pods_labels_map = defaultdict(set)  # map from pods_labels to set of pods
        self.allowed_labels = allowed_labels

        all_pods = set()
        for peer in self.all_peers:
            if isinstance(peer, IpBlock):
                continue
            all_pods.add(peer)
            self.ns_dict[peer.namespace].append(peer)
            for ns_label in peer.namespace.labels.items():
                self.ns_labels_map[ns_label].append(peer)
            for pod_labels in peer.labels.items():
                self.pods_labels_map[pod_labels].add(peer)

        self.add_update_pods_labels_map_with_invalid_val(all_pods)
        self.add_update_pods_labels_map_with_required_conjunction_labels()
        return

    def add_update_pods_labels_map_with_invalid_val(self, all_pods):
        """
        Updating the pods_labels_map with (key,"NO_LABEL_VALUE") for the set of pods without this label
        :param all_pods: A set of all pods in the cluster
        :return: None
        """
        allowed_labels_flattened = self._get_allowed_labels_flattened()
        all_keys = set([key for (key, val) in self.pods_labels_map.keys()])
        all_keys = all_keys.intersection(allowed_labels_flattened)
        invalid_val = 'NO_LABEL_VALUE'
        for key in all_keys:
            # get a list of pod sets per each label value
            pod_sets_with_key_val = [self.pods_labels_map[(k, v)] for (k, v) in self.pods_labels_map.keys() if
                                     k == key]
            # get a union of all pods with any value for current label key
            pod_sets_with_key_val_union = set.union(*pod_sets_with_key_val)
            # get a set of namespaces for which at least one pod in the ns has any value for current label key
            ns_context_options = set([pod.namespace for pod in pod_sets_with_key_val_union])
            # get the set of pods that do not have current label key
            pods_without_key_set = all_pods - pod_sets_with_key_val_union
            # get the set of pods that do not have current label key, only for namespaces where at least one pod in the ns has any value for current label key
            pods_without_key_set_ns_restricted = [pod for pod in pods_without_key_set if
                                                  pod.namespace in ns_context_options]
            # add the pair (key, invalid_val) for pods_labels_map with pods from pods_without_key_set_ns_restricted
            self.pods_labels_map[(key, invalid_val)] = set(pods_without_key_set_ns_restricted)
        return

    def add_update_pods_labels_map_with_required_conjunction_labels(self):
        """
        Updating the pods_labels_map with 'and' labels from allowed labels, to allow grouping of 'and' between labels
        :return: None
        """
        required_conjunction_labels = [k for k in self.allowed_labels if k.startswith('_AND_')]
        for key in required_conjunction_labels:
            key_labels = (key.split('_AND_')[1]).split(':')
            key_labels_values = [self.get_values_set_for_key(k) for k in key_labels]
            cartesian_product_values = list(itertools.product(*key_labels_values))
            # for each elem check how many pods exist
            for elem in cartesian_product_values:
                flattened_elem_value = '_AND_' + ':'.join(v for v in elem)
                pod_sets_per_combined_value = []
                for index in range(0, len(key_labels)):
                    current_key = key_labels[index]
                    val_per_key = list(elem)[index]
                    pod_sets_per_combined_value.append(set(self.pods_labels_map[(current_key, val_per_key)]))
                final_pod_set = set.intersection(*pod_sets_per_combined_value)
                # add to pods_labels_map the combined value for the 'and' label, when pods exist
                if len(final_pod_set) > 0:
                    self.pods_labels_map[(key, flattened_elem_value)] = final_pod_set
        return

    def get_values_set_for_key(self, key):
        """
        Get the set of all possible values per label key in the cluster
        :param key: a label key of type string
        :return: A set of values, of type set(string)
        """
        values = set([v for (k, v) in self.pods_labels_map.keys() if k == key])
        return values

    def _get_allowed_labels_flattened(self):
        """
        Given the set of allowed labels, convert the _AND_ labels into their components separately
        :return: A set of allowed labels after this conversion.
        """
        res = set()
        for key in self.allowed_labels:
            if key.startswith('_AND_'):
                key_labels = (key.split('_AND_')[1]).split(':')
                res.update(key_labels)
            else:
                res.add(key)
        return res

