import itertools
from collections import defaultdict
from Peer import IpBlock


class ClusterInfo:
    def __init__(self, all_peers, allowed_labels):
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

    # extend pod-labels-map with (key,"NO_LABEL_VALUE") for the set of pods without this label
    def add_update_pods_labels_map_with_invalid_val(self, all_pods):
        allowed_labels_flattened = self.get_allowed_labels_flattened()
        all_keys = set([key for (key, val) in self.pods_labels_map.keys()])
        all_keys = all_keys.intersection(allowed_labels_flattened)
        invalid_val = 'NO_LABEL_VALUE'
        for key in all_keys:
            pod_sets_with_key_val = [self.pods_labels_map[(k, v)] for (k, v) in self.pods_labels_map.keys() if
                                     k == key]
            pod_sets_with_key_val_union = set.union(*pod_sets_with_key_val)
            ns_context_options = set([pod.namespace for pod in pod_sets_with_key_val_union])
            pods_without_key_set = all_pods - pod_sets_with_key_val_union
            pods_without_key_set_ns_restricted = [pod for pod in pods_without_key_set if
                                                  pod.namespace in ns_context_options]
            self.pods_labels_map[(key, invalid_val)] = set(pods_without_key_set_ns_restricted)
        return

    # add to pods_labels_map the 'and' labels from allowed labels, to allow grouping of 'and' between labels
    def add_update_pods_labels_map_with_required_conjunction_labels(self):
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
        values = set([v for (k, v) in self.pods_labels_map.keys() if k == key])
        return values

    def get_allowed_labels_flattened(self):
        res = set()
        for key in self.allowed_labels:
            if key.startswith('_AND_'):
                key_labels = (key.split('_AND_')[1]).split(':')
                res.update(key_labels)
            else:
                res.add(key)
        return res
