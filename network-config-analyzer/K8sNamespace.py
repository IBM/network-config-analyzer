#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

class K8sNamespace:
    """
    Represents a K8s Namespace, storing its name and labels
    """
    def __init__(self, name):
        self.name = name if name else 'default'
        # Namespace labels are stored in a dict as key-value pairs
        # Every namespace gets a fixed-key label with its name.
        # See https://kubernetes.io/docs/concepts/services-networking/network-policies/#targeting-a-namespace-by-its-name
        self.labels = {'kubernetes.io/metadata.name': name}
        self.ordered_default_sidecars = []  # list saves the names of the default sidecars
        # of the current namespace in their injection order

    def __eq__(self, other):
        if isinstance(other, K8sNamespace):
            return self.name == other.name
        return False

    def __hash__(self):
        return hash(self.name)

    def __str__(self):
        return self.name

    def set_label(self, key, value):
        """
        Add/update a namespace label
        :param str key: The label key
        :param str value: The label value
        :return: None
        """
        self.labels[key] = value
