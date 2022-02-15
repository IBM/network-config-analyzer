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
        self.labels = {}  # Storing the namespace labels in a dict as key-value pairs

    def __eq__(self, other):
        if isinstance(other, K8sNamespace):
            return self.name == other.name
        return NotImplemented

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
