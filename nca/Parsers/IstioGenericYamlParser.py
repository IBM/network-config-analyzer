#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from nca.Resources.IstioTrafficResources import istio_root_namespace
from .GenericYamlParser import GenericYamlParser


class IstioGenericYamlParser(GenericYamlParser):
    """
    A class for istio yaml parser , common methods for istio policies parsers
    """

    def __init__(self, policy, peer_container, file_name=''):
        """
        :param dict policy: The istio policy object as provided by the yaml parser
        :param PeerContainer peer_container: The policy will be evaluated against this set of peers
        :param str file_name: The name of the file in which the istio policy object resides
        """
        GenericYamlParser.__init__(self, file_name)
        self.policy = policy
        self.peer_container = peer_container
        self.namespace = None
        self.referenced_labels = set()

    def _parse_workload_selector(self, workload_selector, element_key):
        """
        Parse a LabelSelector element
        :param dict workload_selector: The element to parse
        :param str element_key: the key label of the allowed element of the label-selector
        :return: A PeerSet containing all the pods captured by this selection
        :rtype: Peer.PeerSet
        """
        if not workload_selector:  # selector :{}
            return self.peer_container.get_all_peers_group()  # An empty value means the selector selects everything

        allowed_elements = {element_key: [1, dict]}
        self.check_fields_validity(workload_selector, 'Istio policy WorkloadSelector', allowed_elements)

        match_labels = workload_selector.get(element_key)
        if not match_labels:
            self.syntax_error('One or more labels that indicate a specific set '
                              'of pods are required.', workload_selector)

        res = self.peer_container.get_all_peers_group()
        for key, val in match_labels.items():
            res &= self.peer_container.get_peers_with_label(key, [val])
        self.referenced_labels.add(':'.join(match_labels.keys()))

        if not res:
            self.warning('A workload selector selects no pods.', workload_selector)

        return res

    def update_policy_peers(self, workload_selector, dict_key):
        """
        calculates the peers selected by current policy object
        :param dict workload_selector: the workload selector of the policy object yaml
        :param str dict_key: the key used in the selector for labels
        :return the list of peers selected by the policy object
        :rtype: Peer.PeerSet
        """
        if workload_selector is None:
            # istio selected peers may only be clusterEP
            selected_peers = self.peer_container.get_all_peers_group(add_external_ips=False, include_globals=False,
                                                                     include_dns_entries=False)
        else:
            selected_peers = self._parse_workload_selector(workload_selector, dict_key)
        # if policy's namespace is the root namespace, then it applies to all cluster's namespaces
        if self.namespace.name != istio_root_namespace:
            selected_peers &= self.peer_container.get_namespace_pods(self.namespace)

        return selected_peers
