#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from NetworkConfig import NetworkConfig
from PoliciesFinder import PoliciesFinder
from TopologyObjectsFinder import PodsFinder, NameSpacesFinder, ServicesFinder
from GenericTreeScanner import TreeScannerFactory
from PeerContainer import PeerContainer


class ResourcesHandler:
    """
    This class is responsible to build the network config based on input resources from nca cmd line/ scheme runner.
    In case of scheme file with global resources, it is responsible to build and handle it too
    """
    def __init__(self):
        self.global_peer_container = None

    def get_network_config(self, np_list, ns_list, pod_list, resource_list, config_name='global'):
        """
        first tries to build a peer_container using the input resources (NetworkConfigs's resources)
        if fails, it uses the global peer container otherwise build it from the k8s live cluster peers.
        then parse the input resources for policies
        and builds the network config accordingly
        :param Union[list[str], None] np_list: networkPolicies entries
        :param list ns_list: entries to take namespaces from or None
        :param list pod_list: entries to take pods and services from or None
        :param list resource_list: entries to take pods/namespaces/policies from if the specific list is None or None
        :param str config_name: name of the config or None
        :rtype NetworkConfig
        """

        # build peer container
        resources_parser = ResourcesParser()
        if resources_parser.parse_lists_for_topology(ns_list, pod_list, resource_list, config_name):
            peer_container = resources_parser.build_peer_container()
        elif self.global_peer_container:
            peer_container = self.global_peer_container
        else:
            print('loading topology objects from k8s live cluster')
            resources_parser.load_resources_from_k8s_live_cluster(ns_flag=True, pod_flag=True)
            peer_container = resources_parser.build_peer_container()

        # parse for policies
        resources_parser.parse_lists_for_policies(np_list, resource_list, peer_container)

        if config_name == 'global':
            config_name = np_list[0] or resource_list[0]
        # build and return the networkConfig
        network_config = NetworkConfig(name=config_name, peer_container=peer_container,
                                       policies_container=resources_parser.policies_finder.policies_container,
                                       config_type=resources_parser.policies_finder.type)
        return network_config

    def set_global_peer_container(self, global_ns_list, global_pod_list, global_resource_list):
        """
        builds the global peer container based on global input resources
        :param global_ns_list: list of entries to take namespaces from or None
        :param global_pod_list: list of entries to take pods from or None
        :param global_resource_list: list of entries of namespaces/pods in case specific list is None or None
        """
        resources_parser = ResourcesParser()
        if resources_parser.parse_lists_for_topology(global_ns_list, global_pod_list, global_resource_list):
            self.global_peer_container = resources_parser.build_peer_container()


class ResourcesParser:
    """
    This class parses the input resources for topology (pods, namespaces, services) and policies.
    """
    def __init__(self):
        self.policies_finder = PoliciesFinder()
        self.pods_finder = PodsFinder()
        self.ns_finder = NameSpacesFinder()
        self.services_finder = ServicesFinder()

    def parse_lists_for_topology(self, ns_list, pod_list, resource_list, config_name='global'):
        """
        Chooses to parse the namespaces from the ns_list if exists in the input resources.
        the pods and services: from pod_list if exist in the input resources
        if the specified lists do not exist, parses them from the resources list
        """
        if ns_list:
            ns_resource = ns_list
            if resource_list:
                print('Warning: namespaces will be taken from the provided namespace list key.'
                      'input resources provided with resource list key will be ignored when finding namespaces')
        else:
            ns_resource = resource_list

        if pod_list:
            pod_resource = pod_list
            if resource_list:
                print('Warning: pods and services will be taken from the provided pod list key. '
                      'input resources provided with resource list key will be ignored when finding pods and services')
        else:
            pod_resource = resource_list

        if pod_resource is None or ns_resource is None:
            return False  # can not build peer container

        if pod_resource == resource_list and pod_resource == ns_resource:  # both in resourceList
            print(f'Finding topology objects in {resource_list}')
            self._parse_resources_path(resource_list, np_flag=False, ns_flag=True, pod_flag=True)
        else:  # we always want to parse for ns first
            self._parse_resources_path(ns_resource, ns_flag=True)
            self._parse_resources_path(pod_resource, pod_flag=True)

        if len(self.pods_finder.peer_set) == 0 or len(self.ns_finder.namespaces) == 0:
            return False  # can not build peer container

        print(f'{config_name}: cluster has {len(self.pods_finder.peer_set)} unique endpoints, '
              f'{len(self.ns_finder.namespaces)} namespaces')
        return True

    def parse_lists_for_policies(self, np_list, resource_list, peer_container):
        """
        parses policies from np_list resource if exists, otherwise parses the resource_list for policies
        :param np_list: list of entries of networkPolicies
        :param resource_list: list of entries
        :param peer_container: the existing PeerContainer
        """
        self.policies_finder.set_peer_container(peer_container)
        if np_list and np_list != ['']:
            self._parse_resources_path(np_list, np_flag=True)
            if resource_list:
                print('Warning: policies will be taken from the provided networkPolicy list key. '
                      'input resources provided with resource list key will be ignored when finding network policies')
        elif resource_list:
            print(f'Finding policies in {resource_list}')
            self._parse_resources_path(resource_list, np_flag=True)

    def _parse_resources_path(self, resource_list, np_flag=False, ns_flag=False, pod_flag=False):
        """
        parsing the resources path / live cluster using the Finder classes
        """
        for resource_item in resource_list:
            if resource_item == 'k8s':
                self.load_resources_from_k8s_live_cluster(np_flag, ns_flag, pod_flag)
            elif resource_item == 'calico' and pod_flag:
                self.pods_finder.load_peer_from_calico_resource()
            elif resource_item == 'calico' and np_flag:
                self.policies_finder.load_policies_from_calico_cluster()
            elif resource_item == 'istio' and np_flag:
                self.policies_finder.load_istio_policies_from_k8s_cluster()
            else:
                resource_scanner = TreeScannerFactory.get_scanner(resource_item)
                if resource_scanner is None:
                    continue
                yaml_files = resource_scanner.get_yamls()
                if not yaml_files:
                    continue
                for yaml_file in yaml_files:
                    for res_code in yaml_file.data:
                        if ns_flag:
                            self.ns_finder.parse_yaml_code_for_ns(res_code)
                        if pod_flag:
                            self.pods_finder.namespaces_finder = self.ns_finder
                            self.pods_finder.add_eps_from_list(res_code)
                            self.services_finder.namespaces_finder = self.ns_finder
                            self.services_finder.parse_yaml_code_for_service(res_code, yaml_file)
                        if np_flag:
                            self.policies_finder.parse_yaml_code_for_policy(res_code, yaml_file.path)

        self.policies_finder.parse_policies_in_parse_queue()

    def load_resources_from_k8s_live_cluster(self, np_flag=False, ns_flag=False, pod_flag=False):
        if ns_flag:
            self.ns_finder.load_ns_from_live_cluster()
        if pod_flag:
            self.pods_finder.namespaces_finder = self.ns_finder
            self.pods_finder.load_peer_from_k8s_live_cluster()
            self.services_finder.namespaces_finder = self.ns_finder
            self.services_finder.load_services_from_live_cluster()
        if np_flag:
            self.policies_finder.load_policies_from_k8s_cluster()

    def build_peer_container(self):
        return PeerContainer(self.pods_finder.peer_set, self.ns_finder.namespaces, self.services_finder.services_list,
                             self.pods_finder.representative_peers)
