#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from enum import Enum
from NetworkConfig import NetworkConfig
from PoliciesFinder import PoliciesFinder
from TopologyObjectsFinder import PodsFinder, NamespacesFinder, ServicesFinder
from GenericTreeScanner import TreeScannerFactory
from PeerContainer import PeerContainer


class ResourceType(Enum):
    Unknown = 0
    Pods = 1
    Namespaces = 2
    Policies = 3


class ResourcesHandler:
    """
    This class is responsible to build the network config based on input resources from nca cmd line/ scheme runner.
    In case of scheme file with global resources, it is responsible to build and handle it too
    """
    def __init__(self):
        self.global_peer_container = None
        self.global_pods_finder = None
        self.global_ns_finder = None

    def get_network_config(self, np_list, ns_list, pod_list, resource_list, config_name='global', k8s_np_flag=False):
        """
        First tries to build a peer_container using the input resources (NetworkConfigs's resources)
        If fails, it uses the global peer container otherwise build it from the k8s live cluster peers.
        Then parse the input resources for policies and builds the network config accordingly.
        :param Union[list[str], None] np_list: networkPolicies entries
        :param Union[list[str], None] ns_list: namespaces entries
        :param Union[list[str], None] pod_list: pods and services entries
        :param Union[list[str], None] resource_list: entries to read pods/namespaces/policies from
        if the specific list is None
        :param str config_name: name of the config
        :param bool k8s_np_flag: get policies from k8s live cluster if they are not found in the input resources
        :rtype NetworkConfig
        """

        # build peer container
        resources_parser = ResourcesParser()
        success, res_type = resources_parser.parse_lists_for_topology(ns_list, pod_list, resource_list)
        if success or res_type:
            if res_type == ResourceType.Pods:  # found only pods in the specific config, use the global namespaces
                # or load from k8s live cluster
                if self.global_ns_finder:
                    resources_parser.ns_finder = self.global_ns_finder
                else:
                    resources_parser.load_resources_from_k8s_live_cluster([ResourceType.Namespaces])
            elif res_type == ResourceType.Namespaces:
                # found only namespaces in the specific config, use the global pods or load from k8s live cluster
                if self.global_pods_finder:
                    resources_parser.pods_finder = self.global_pods_finder
                else:
                    resources_parser.load_resources_from_k8s_live_cluster([ResourceType.Pods])
            peer_container = resources_parser.build_peer_container(config_name)
        elif self.global_peer_container:  # no specific peer container, use the global one
            peer_container = self.global_peer_container
        else:  # the specific networkConfig has no topology input resources (not private, neither global)
            print('loading topology objects from k8s live cluster')
            resources_parser.load_resources_from_k8s_live_cluster([ResourceType.Namespaces, ResourceType.Pods])
            peer_container = resources_parser.build_peer_container(config_name)

        # parse for policies
        resources_parser.parse_lists_for_policies(np_list, resource_list, peer_container, k8s_np_flag)

        if config_name == 'global':
            if np_list and np_list != ['']:
                config_name = np_list[0]
            elif resource_list:
                config_name = resource_list[0]
        # build and return the networkConfig
        return NetworkConfig(name=config_name, peer_container=peer_container,
                             policies_container=resources_parser.policies_finder.policies_container,
                             config_type=resources_parser.policies_finder.type)

    def set_global_peer_container(self, global_ns_list, global_pod_list, global_resource_list):
        """
        builds the global peer container based on global input resources,
        it also saves the global pods and namespaces finder, to use in case specific configs missing one of them
        :param Union[list[str], None] global_ns_list: global namespaces entries
        :param Union[list[str], None] global_pod_list: global pods entries
        :param Union[list[str], None] global_resource_list: list of global entries of namespaces/pods to handle
        in case specific list is None
        """
        resources_parser = ResourcesParser()
        success, res_type = resources_parser.parse_lists_for_topology(global_ns_list, global_pod_list,
                                                                      global_resource_list)
        if success:
            self.global_peer_container = resources_parser.build_peer_container()
            self.global_pods_finder = resources_parser.pods_finder
            self.global_ns_finder = resources_parser.ns_finder
        elif res_type == ResourceType.Pods:
            # in case the global resources has only pods (can not build global peerContainer)
            self.global_pods_finder = resources_parser.pods_finder
        elif res_type == ResourceType.Namespaces:
            # in case the global resources has only namespaces (can not build global peerContainer)
            self.global_ns_finder = resources_parser.ns_finder


class ResourcesParser:
    """
    This class parses the input resources for topology (pods, namespaces, services) and policies.
    """
    def __init__(self):
        self.policies_finder = PoliciesFinder()
        self.pods_finder = PodsFinder()
        self.ns_finder = NamespacesFinder()
        self.services_finder = ServicesFinder()

    @staticmethod
    def _determine_topology_resource(topology_list, resource_list, res_type):
        res_name = 'namespaces' if res_type == ResourceType.Namespaces else 'pods and services'
        if topology_list:
            topology_resource = topology_list
            if resource_list:
                print(f'Warning: {res_name} provided with resource list key will be ignored, since its specific key overrides resource_list')
        else:
            topology_resource = resource_list

        return topology_resource

    def parse_lists_for_topology(self, ns_list, pod_list, resource_list):
        """
        Chooses to parse the namespaces from the ns_list if exists in the input resources.
        the pods and services: from pod_list if exist in the input resources
        if the specified lists do not exist, try to parse from the resources list (if exists)
        :param Union[list[str], None] ns_list: namespaces entry
        :param Union[list[str], None] pod_list: pods entry
        :param Union[list[str], None] resource_list: resources entry
        :rtype (bool, ResourceType)
        returns if succeeds or fails to find any topology objects as following:
        True, 0 : if succeeds to find both namespaces and peers
        False, ResourceType.Pods: if succeeds to find only pods
        False, ResourceType.Namespaces: if succeeds to find only namespaces
        False, 0: if fails to find both namespaces and pods
        """
        ns_resource = self._determine_topology_resource(ns_list, resource_list, ResourceType.Namespaces)
        pod_resource = self._determine_topology_resource(pod_list, resource_list, ResourceType.Pods)

        if pod_resource is None and ns_resource is None:  # no resources to parse
            return False, 0

        if pod_resource == resource_list and pod_resource == ns_resource:  # both may exist in resourceList
            self._parse_resources_path(resource_list,
                                       [ResourceType.Namespaces, ResourceType.Pods])
        else:  # we always want to parse for namespaces first (if exists)
            if ns_resource:
                self._parse_resources_path(ns_resource, [ResourceType.Namespaces])
            if pod_resource:
                self._parse_resources_path(pod_resource, [ResourceType.Pods])

        if len(self.pods_finder.peer_set) > 0 and len(self.ns_finder.namespaces) > 0:
            return True, 0
        elif len(self.pods_finder.peer_set) == 0 and len(self.ns_finder.namespaces) > 0:
            return False, ResourceType.Namespaces
        elif len(self.pods_finder.peer_set) > 0 and len(self.ns_finder.namespaces) == 0:
            return False, ResourceType.Pods
        else:
            return False, 0

    def parse_lists_for_policies(self, np_list, resource_list, peer_container, k8s_np_flag):
        """
        parses policies from np_list resource if exists, otherwise parses the resource_list for policies
        :param np_list: list of entries of networkPolicies
        :param resource_list: list of entries
        :param peer_container: the existing PeerContainer
        :param bool k8s_np_flag: get policies from k8s live cluster if they are not found in the input resources
        """
        self.policies_finder.set_peer_container(peer_container)
        if np_list and np_list != ['']:
            self._parse_resources_path(np_list, [ResourceType.Policies])
            if resource_list:
                print('Warning: policies will be taken from the provided networkPolicy list key. '
                      'input resources provided with resource list key will be ignored when finding network policies')
        elif resource_list:
            self._parse_resources_path(resource_list, [ResourceType.Policies])
            # if np list is not given and there are no policies in the resource list but k8s_np_flag is True
            # then load policies from live cluster
            if k8s_np_flag and self.policies_finder.has_empty_containers():
                self.policies_finder.load_policies_from_k8s_cluster()

    def _parse_resources_path(self, resource_list, resource_flags):
        """
        parsing the resources path / live cluster using the Finder classes
        :param list resource_list: list of input resources paths
        :param list resource_flags: resource types to search in the given resource_list
        list possibilities are: [ResourceType.Policies], [ResourceType.Namespaces], [ResourceType.Pods] and
        [ResourceType.Namespaces, ResourceType.Pods]
        """
        for resource_item in resource_list:
            if resource_item == 'k8s':
                self.load_resources_from_k8s_live_cluster(resource_flags)
            elif resource_item == 'calico':
                self._handle_calico_inputs(resource_flags)
            elif resource_item == 'istio':
                self._handle_istio_inputs(resource_flags)
            else:
                resource_scanner = TreeScannerFactory.get_scanner(resource_item)
                if resource_scanner is None:
                    continue
                yaml_files = resource_scanner.get_yamls()
                if not yaml_files:
                    continue
                for yaml_file in yaml_files:
                    for res_code in yaml_file.data:
                        if ResourceType.Namespaces in resource_flags:
                            self.ns_finder.parse_yaml_code_for_ns(res_code)
                        if ResourceType.Pods in resource_flags:
                            self.pods_finder.namespaces_finder = self.ns_finder
                            self.pods_finder.add_eps_from_yaml(res_code)
                            self.services_finder.namespaces_finder = self.ns_finder
                            self.services_finder.parse_yaml_code_for_service(res_code, yaml_file)
                        if ResourceType.Policies in resource_flags:
                            self.policies_finder.parse_yaml_code_for_policy(res_code, yaml_file.path)

        self.policies_finder.parse_policies_in_parse_queue()

    def load_resources_from_k8s_live_cluster(self, resource_flags):
        if ResourceType.Namespaces in resource_flags:
            self.ns_finder.load_ns_from_live_cluster()
        if ResourceType.Pods in resource_flags:
            self.pods_finder.namespaces_finder = self.ns_finder
            self.pods_finder.load_peer_from_k8s_live_cluster()
            self.services_finder.namespaces_finder = self.ns_finder
            self.services_finder.load_services_from_live_cluster()
        if ResourceType.Policies in resource_flags:
            self.policies_finder.load_policies_from_k8s_cluster()

    def _handle_calico_inputs(self, resource_flags):
        if ResourceType.Namespaces in resource_flags:
            self.ns_finder.load_ns_from_live_cluster()
        if ResourceType.Pods in resource_flags:
            self.pods_finder.load_peer_from_calico_resource()
        if ResourceType.Policies in resource_flags:
            self.policies_finder.load_policies_from_calico_cluster()

    def _handle_istio_inputs(self, resource_flags):
        if ResourceType.Pods in resource_flags or ResourceType.Namespaces in resource_flags:
            self.load_resources_from_k8s_live_cluster(resource_flags)
        if ResourceType.Policies in resource_flags:
            self.policies_finder.load_istio_policies_from_k8s_cluster()

    def build_peer_container(self, config_name='global'):
        print(f'{config_name}: cluster has {len(self.pods_finder.peer_set)} unique endpoints, '
              f'{len(self.ns_finder.namespaces)} namespaces')

        return PeerContainer(self.pods_finder.peer_set, self.ns_finder.namespaces, self.services_finder.services_list,
                             self.pods_finder.representative_peers)
