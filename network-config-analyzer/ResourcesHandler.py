#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import copy
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

    def set_global_peer_container(self, global_ns_list, global_pod_list, global_resource_list):
        """
        builds the global peer container based on global input resources,
        it also saves the global pods and namespaces finder, to use in case specific configs missing one of them
        :param Union[list[str], None] global_ns_list: global namespaces entries
        :param Union[list[str], None] global_pod_list: global pods entries
        :param Union[list[str], None] global_resource_list: list of global entries of namespaces/pods to handle
        in case specific list is None
        """
        global_resources_parser = ResourcesParser()
        self._set_config_peer_container(global_ns_list, global_pod_list, global_resource_list,
                                        'global', True, global_resources_parser)

    def get_network_config(self, np_list, ns_list, pod_list, resource_list, config_name='global', save_flag=False):
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
        :param bool save_flag: used in cmdline queries with two configs, if save flag is True
         will save the peer container as global to use it for base config's peer resources in case are missing
        :rtype NetworkConfig
        """
        resources_parser = ResourcesParser()
        # build peer container
        peer_container = \
            self._set_config_peer_container(ns_list, pod_list, resource_list, config_name, save_flag, resources_parser)

        # parse for policies
        cfg = resources_parser.parse_lists_for_policies(np_list, resource_list, peer_container)

        if cfg and config_name == 'global':
            config_name = cfg

        # build and return the networkConfig
        return NetworkConfig(name=config_name, peer_container=peer_container,
                             policies_container=resources_parser.policies_finder.policies_container,
                             config_type=resources_parser.policies_finder.type)

    def _set_config_peer_container(self, ns_list, pod_list, resource_list, config_name, save_flag, resources_parser):
        success, res_type = resources_parser.parse_lists_for_topology(ns_list, pod_list, resource_list)
        if success or res_type:
            if res_type:
                self._fill_empty_finder(res_type, resources_parser)
            peer_container = resources_parser.build_peer_container(config_name)
        elif self.global_peer_container:  # no specific peer container, use the global one if exists
            peer_container = copy.deepcopy(self.global_peer_container)
        else:  # the specific networkConfig has no topology input resources (not private, neither global)
            print('loading topology objects from k8s live cluster')
            resources_parser.load_resources_from_k8s_live_cluster([ResourceType.Namespaces, ResourceType.Pods])
            peer_container = resources_parser.build_peer_container(config_name)

        if save_flag:  # if called from scheme with global topology or cmdline with 2 configs query
            self.global_peer_container = peer_container
            self.global_ns_finder = resources_parser.ns_finder
            self.global_pods_finder = resources_parser.pods_finder

        return peer_container

    def _fill_empty_finder(self, res_type, resources_parser):
        """
        :param ResourceType res_type: the topology resource type that was found from input resources
        :param ResourcesParser resources_parser: the current resources_parser object
        This function is called when one topology resource type is missing (the one different from input res_type).
        It updates resources_parser with relevant topology finder, either from global config or from live cluster:

        If res_type is ResourceType.Pods , then resources parser found only pods in the specific config,
        use the global namespaces or load from k8s live cluster to build a peer container
        If res_type is ResourceType.Namespaces, then resources parser found only namespaces in the specific config,
        use the global pods or load from k8s live cluster
        """
        global_ns_exist = True if self.global_ns_finder else False
        global_pod_exist = True if self.global_pods_finder else False
        if res_type == ResourceType.Pods and global_ns_exist:
            resources_parser.ns_finder = self.global_ns_finder
        elif res_type == ResourceType.Namespaces and global_pod_exist:
            resources_parser.pods_finder = self.global_pods_finder
        else:
            load_type = ResourceType.Namespaces if res_type == ResourceType.Pods else ResourceType.Pods
            resources_parser.load_resources_from_k8s_live_cluster([load_type])


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
        specific_resource_flag = True
        res_name = 'namespaces' if res_type == ResourceType.Namespaces else 'pods and services'
        if topology_list:
            topology_resource = topology_list
            if resource_list:
                print(f'Warning: {res_name} provided with resource list key will be ignored, since its specific key '
                      f'overrides resource_list')
        else:
            topology_resource = resource_list
            specific_resource_flag = False

        return topology_resource, specific_resource_flag

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
        ns_resource, specific_ns = self._determine_topology_resource(ns_list, resource_list, ResourceType.Namespaces)
        pod_resource, specific_pods = self._determine_topology_resource(pod_list, resource_list, ResourceType.Pods)

        if pod_resource is None and ns_resource is None:  # no resources to parse
            return False, 0

        if pod_resource == resource_list and ns_resource == resource_list:  # both may exist in resourceList
            self._parse_resources_path(resource_list,
                                       [ResourceType.Namespaces, ResourceType.Pods])
        else:  # we always want to parse for namespaces first (if exists)
            if ns_resource:
                self._parse_resources_path(ns_resource, [ResourceType.Namespaces])
            if pod_resource:
                self._parse_resources_path(pod_resource, [ResourceType.Pods])

        # calculating the return value:
        if (self.pods_finder.peer_set and self.ns_finder.namespaces) or \
                (specific_pods and specific_ns):
            # input resources include both pods and namespaces or include only pods- so their namespaces are taken
            # or both pods and namespaces from specific switches (a specific switch may point to an empty file)
            return True, 0
        if specific_pods and self.ns_finder.namespaces:
            # pod_list point to empty file, namespaces found in the input resources
            return True, 0
        if not self.pods_finder.peer_set and self.ns_finder.namespaces:
            # no specific pod_list and resource_list doesn't include pods -> get pods from global
            return False, ResourceType.Namespaces
        if not self.ns_finder.namespaces and specific_pods:
            # there is a pod_list (empty from pods) but no namespaces in the resources-> get namespaces from global
            return False, ResourceType.Pods
        return False, 0

    def parse_lists_for_policies(self, np_list, resource_list, peer_container):
        """
        parses policies from np_list resource if exists,
        otherwise parses the resource_list for policies,
        if no policies are found in the resource_list or if both np_list and resource_list does not exist
        loads policies from k8s live cluster
        :param np_list: list of entries of networkPolicies
        :param resource_list: list of entries
        :param peer_container: the existing PeerContainer
        :rtype str
        returns the config name - 'k8s' if policies are loaded from live cluster,
        otherwise the name of the first policy in the input list
        """
        live_cluster_flag = False
        config_name = None
        self.policies_finder.set_peer_container(peer_container)
        if np_list is not None:
            self._parse_resources_path(np_list, [ResourceType.Policies])
            if np_list:
                config_name = np_list[0]
            if resource_list:
                print('Warning: policies will be taken from the provided networkPolicy list key. '
                      'input resources provided with resource list key will be ignored when finding network policies')
        elif resource_list:
            self._parse_resources_path(resource_list, [ResourceType.Policies])
            config_name = resource_list[0]
            # if np list is not given and there are no policies in the resource list
            # then load policies from live cluster
            if self.policies_finder.has_empty_containers():
                live_cluster_flag = True
        else:
            live_cluster_flag = True

        if live_cluster_flag:
            config_name = 'k8s'
            print('loading policies from k8s live cluster')
            self._parse_resources_path(['k8s'], [ResourceType.Policies])

        return config_name

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
                rt_load = True if ResourceType.Policies in resource_flags else False
                resource_scanner = TreeScannerFactory.get_scanner(resource_item, rt_load=rt_load)
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
