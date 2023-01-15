#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
import copy
import os
from enum import Enum
from sys import stderr
from ruamel.yaml import error
from nca.FileScanners.GenericTreeScanner import TreeScannerFactory
from nca.Utils.CmdlineRunner import CmdlineRunner
from .NetworkConfig import NetworkConfig
from .PoliciesFinder import PoliciesFinder
from .TopologyObjectsFinder import PodsFinder, NamespacesFinder, ServicesFinder
from .PeerContainer import PeerContainer
from nca.Utils.NcaLogger import NcaLogger


class ResourceType(Enum):
    Unknown = 0
    Pods = 1
    Namespaces = 2
    Policies = 3


class LiveSimPaths:
    """
    Hold the location of the LiveSim yaml files
    """
    DnsCfgPath = 'LiveSim/dns_pods.yaml'
    IngressControllerCfgPath = 'LiveSim/ingress_controller.yaml'
    IstioGwCfgPath = 'LiveSim/istio_gateway.yaml'


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
        it also saves the global pods and namespaces finder, to use in case specific configs missing one of them.
        Note: if there are no input resources at all, loads them from k8s live cluster
        :param Union[list[str], None] global_ns_list: global namespaces entries
        :param Union[list[str], None] global_pod_list: global pods entries
        :param Union[list[str], None] global_resource_list: list of global entries of namespaces/pods to handle
        in case specific list is None
        """
        global_resources_parser = ResourcesParser()
        self._set_config_peer_container(global_ns_list, global_pod_list, global_resource_list,
                                        'global', True, global_resources_parser)

    @staticmethod
    def analyze_livesim(policy_finder):
        """
        Analyze the pre-parsing of the topology and finds what needs
        to be added.
        :param PolicyFinder policy_finder: Contains the policies found in pre-parsing
        :return: [strings]: configuration_addons: the paths of the yamls to be added.
        """
        configuration_addons = []
        path = os.path.dirname(__file__)
        # find kube-dns reference
        if 'kube-system' in policy_finder.missing_pods_with_labels.values() or \
                policy_finder.missing_pods_with_labels.get('k8s-app') == 'kube-dns':
            configuration_addons.append(os.path.join(path, LiveSimPaths.DnsCfgPath))
            NcaLogger().log_message('Found missing elements - adding complementary kube-dns elements', level='I')

        # find ingress controller pods
        if policy_finder.missing_k8s_ingress_peers:
            configuration_addons.append(os.path.join(path, LiveSimPaths.IngressControllerCfgPath))
            NcaLogger().log_message('Found missing elements - adding complementary ingress controller elements', level='I')

        # find Istio ingress gateway
        if policy_finder.missing_istio_gw_peers:
            configuration_addons.append(os.path.join(path, LiveSimPaths.IstioGwCfgPath))
            NcaLogger().log_message('Found missing elements - adding complementary Istio ingress gateway elements', level='I')

        return configuration_addons

    def parse_elements(self, ns_list, pod_list, resource_list, config_name, save_flag, np_list):
        """
        Parse the elements and build peer container.
        :param Union[list[str], None] ns_list: namespaces entries
        :param Union[list[str], None] pod_list: pods and services entries
        :param Union[list[str], None] resource_list: entries to read pods/namespaces/policies from
        if the specific list is None
        :param str config_name: name of the config
        :param bool save_flag: used in cmdline queries with two configs, if save flag is True
         will save the peer container as global to use it for base config's peer resources in case are missing
        :param Union[list[str], None] np_list: networkPolicies entries
        :return:  PeerContainer, ResourcesParser, str
        """
        resources_parser = ResourcesParser()
        # build peer container
        peer_container = \
            self._set_config_peer_container(ns_list, pod_list, resource_list, config_name, save_flag, resources_parser)

        # parse for policies
        cfg = resources_parser.parse_lists_for_policies(np_list, resource_list, peer_container)

        return peer_container, resources_parser, cfg

    def get_network_config(self, np_list, ns_list, pod_list, resource_list, config_name='global', save_flag=False):
        """
        First tries to build a peer_container using the input resources (NetworkConfigs's resources)
        If fails, it uses the global peer container.
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
        NcaLogger().mute()
        peer_container, resources_parser, cfg = self.parse_elements(ns_list,
                                                                    pod_list,
                                                                    resource_list,
                                                                    config_name,
                                                                    save_flag,
                                                                    np_list
                                                                    )
        NcaLogger().unmute()
        # check if LiveSim can add anything.
        livesim_addons = self.analyze_livesim(resources_parser.policies_finder)
        if livesim_addons:
            NcaLogger().flush_messages(silent=True)
            if ns_list:
                ns_list += livesim_addons

            if pod_list:
                pod_list += livesim_addons

            if resource_list:
                resource_list += livesim_addons

            peer_container, resources_parser, cfg = self.parse_elements(ns_list,
                                                                        pod_list,
                                                                        resource_list,
                                                                        config_name,
                                                                        save_flag,
                                                                        np_list
                                                                        )
        else:
            NcaLogger().flush_messages()

        if cfg and config_name == 'global':
            config_name = cfg

        # build and return the networkConfig
        return NetworkConfig(name=config_name, peer_container=peer_container,
                             policies_container=resources_parser.policies_finder.policies_container)

    def _set_config_peer_container(self, ns_list, pod_list, resource_list, config_name, save_flag, resources_parser):
        success, res_type = resources_parser.parse_lists_for_topology(ns_list, pod_list, resource_list)
        if success or res_type:
            if res_type:
                self._fill_empty_finder(res_type, resources_parser)
            peer_container = resources_parser.build_peer_container(config_name)
        elif self.global_peer_container:  # no specific peer container, use the global one if exists
            # deepcopy is required since PoliciesFinder may change peer_container
            peer_container = copy.deepcopy(self.global_peer_container)
        else:  # the specific networkConfig has no topology input resources (not private, neither global)
            # this case is reachable when:
            # 1. no input paths are provided at all, then try to load from live cluster silently
            # if communication fails then build an empty peer container
            # 2. paths are provided only using resourceList flag, but no topology objects found;
            # in this case we will not load topology from live cluster - keeping peer container empty
            if resource_list is None:  # getting here means ns_list and pod_list are None too
                resources_parser.try_to_load_topology_from_live_cluster([ResourceType.Namespaces, ResourceType.Pods],
                                                                        config_name)
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
        It updates resources_parser with relevant topology finder, from the global peer container:

        If res_type is ResourceType.Pods , then resources parser found only pods in the specific config,
        use the global namespaces for its namespace list
        If res_type is ResourceType.Namespaces, then resources parser found only namespaces in the specific config,
        use the global pods to fill its peer set
        """
        global_ns_exist = True if self.global_ns_finder else False
        global_pod_exist = True if self.global_pods_finder else False
        if res_type == ResourceType.Pods and global_ns_exist:
            resources_parser.ns_finder = self.global_ns_finder
        elif res_type == ResourceType.Namespaces and global_pod_exist:
            resources_parser.pods_finder = self.global_pods_finder


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
            # input resources include both pods and namespaces or include only pods - so their namespaces are taken
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
        Note: if both np_list and resource_list does not exist loads policies from k8s live cluster
        :param np_list: list of entries of networkPolicies
        :param resource_list: list of entries
        :param peer_container: the existing PeerContainer
        :rtype str
        returns the config name - 'k8s' if policies are loaded from live cluster,
        otherwise the name of the first policy in the input list
        """
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
        else:  # running without any input flags - try to load from k8s live cluster silently
            self.try_to_load_topology_from_live_cluster([ResourceType.Policies])

        return config_name

    def _parse_resources_path(self, resource_list, resource_flags):
        """
        parsing the resources paths / live cluster using the Finder classes
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
                    try:
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

                    except error.MarkedYAMLError as prs_err:
                        print(
                            f'{prs_err.problem_mark.name}:{prs_err.problem_mark.line}:{prs_err.problem_mark.column}:',
                            'Parse Error:', prs_err.problem, file=stderr)
                    except UnicodeDecodeError as decode_err:
                        print(f'Parse Error: Failed to decode {yaml_file.path}. error:\n{decode_err.reason}')

        self.policies_finder.parse_policies_in_parse_queue()

    def load_resources_from_k8s_live_cluster(self, resource_flags, run_silently=False):
        """
        attempt to load the resources in resource_flags from k8s live cluster
        :param list resource_flags: resource types to load from k8s live cluster
        :param bool run_silently: indicates if this attempt should run silently, i.e. ignore errors if fails to
        communicate.
        """
        # Setting a flag in the CmdlineRunner to indicate if we are trying to load resources silently
        # from the live cluster (e.g. global resources are missing)
        CmdlineRunner.ignore_live_cluster_err = run_silently

        if ResourceType.Namespaces in resource_flags:
            self.ns_finder.load_ns_from_live_cluster()
        if ResourceType.Pods in resource_flags:
            self.pods_finder.namespaces_finder = self.ns_finder
            self.pods_finder.load_peer_from_k8s_live_cluster()
            self.services_finder.namespaces_finder = self.ns_finder
            self.services_finder.load_services_from_live_cluster()
        if ResourceType.Policies in resource_flags:
            self.policies_finder.load_policies_from_k8s_cluster()

    def try_to_load_topology_from_live_cluster(self, resources_flags, config_name='global'):
        """
        an attempt to load resources from k8s live cluster silently.
        in this case, communication with a k8s live cluster is not a must.
        so the attempt occurs silently, if succeed to connect and load resources then a relevant message will be printed
        otherwise, a warning message of not found resources will be printed
        :param  list resources_flags: resource types to load from k8s live cluster
        :param str config_name: configuration name
        """
        try:
            self.load_resources_from_k8s_live_cluster(resources_flags, run_silently=True)
            if ResourceType.Policies in resources_flags:
                success = self.policies_finder.policies_container.policies
            else:
                success = self.ns_finder.namespaces or self.pods_finder.peer_set
        except FileNotFoundError:  # in case that kube-config file is not found
            success = False  # ignore the exception since this is a silent try

        resource_names = ' and '.join(str(resource).split('.')[1].lower() for resource in resources_flags)
        if success:  # we got resources from live cluster
            print(f'{config_name}: loading {resource_names} from k8s live cluster')
        else:
            print(f'Warning: {config_name} - {resource_names} were not found')

    def _handle_calico_inputs(self, resource_flags):
        if ResourceType.Namespaces in resource_flags:
            self.ns_finder.load_ns_from_live_cluster()
        if ResourceType.Pods in resource_flags:
            self.pods_finder.namespaces_finder = self.ns_finder
            self.pods_finder.load_peer_from_calico_resource()
        if ResourceType.Policies in resource_flags:
            self.policies_finder.load_policies_from_calico_cluster()

    def _handle_istio_inputs(self, resource_flags):
        if ResourceType.Pods in resource_flags or ResourceType.Namespaces in resource_flags:
            self.load_resources_from_k8s_live_cluster(resource_flags)
        if ResourceType.Policies in resource_flags:
            self.policies_finder.load_istio_policies_from_k8s_cluster()

    def build_peer_container(self, config_name='global'):
        NcaLogger().log_message(f'{config_name}: cluster has {len(self.pods_finder.peer_set)} unique endpoints, '
                                f'{len(self.ns_finder.namespaces)} namespaces')

        return PeerContainer(self.pods_finder.peer_set, self.ns_finder.namespaces, self.services_finder.services_list,
                             self.pods_finder.representative_peers)
