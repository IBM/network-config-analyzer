#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import Peer
import yaml
from PeerContainer import PeerContainer
from K8sService import K8sService
from CmdlineRunner import CmdlineRunner
from GenericTreeScanner import TreeScannerFactory
from K8sYamlParser import K8sYamlParser


class K8sServiceYamlParser(K8sYamlParser):
    """
    A parser for k8s service resources
    """

    def __init__(self, service_file_name=''):
        """
        :param str service_file_name: The name of the yaml file containing K8s service resources
        """
        K8sYamlParser.__init__(self, service_file_name)

    def parse_service(self, srv_object, peer_container):
        """
        Parses a service resource object and creates a K8sService object
        :param dict srv_object: the service object to parse
        :param PeerContainer peer_container: the peer container in which pods of the service are located
        :return: K8sService object or None
        """
        if srv_object.get('kind') != 'Service':
            return None  # Not a Service object
        api_version = srv_object.get('apiVersion')
        if api_version != 'v1':
            return None  # apiVersion is not properly set
        metadata = srv_object.get('metadata')
        if not metadata:
            return None
        srv_name = metadata.get('name')
        if not srv_name:
            return None
        srv_namespace = metadata.get('namespace')
        service_spec = srv_object.get('spec')
        if not service_spec:
            self.warning(f'Spec is missing or null in Service {srv_name}. Ignoring the service')
            return None
        service = K8sService(srv_name, srv_namespace)
        service_type = service_spec.get('type', 'ClusterIP')
        if service_type == 'ExternalName':
            service.set_type(K8sService.ServiceType.ExternalName)
        elif service_type == 'NodePort':
            service.set_type(K8sService.ServiceType.NodePort)
        elif service_type == 'LoadBalancer':
            service.set_type(K8sService.ServiceType.LoadBalancer)
        else:
            service.set_type(K8sService.ServiceType.ClusterIP)  # the default type

        selector = service_spec.get('selector')
        if selector:
            for key, val in selector.items():
                self.check_label_key_syntax(key, selector)
                self.check_label_value_syntax(val, key, selector)
                service.add_selector(key, val)
                service.target_pods |= peer_container.get_peers_with_label(key, [val], PeerContainer.FilterActionType.In,
                                                                           service.namespace)

        ports = service_spec.get('ports')
        if ports is not None:
            for port in ports:
                port_id = port.get('port')
                if not port_id:
                    continue
                target_port = port.get('targetPort')
                if not target_port:
                    target_port = port_id
                name = port.get('name', '')
                if not service.add_port(K8sService.ServicePort(port_id, target_port,
                                                               port.get('protocol', 'TCP'), name)):
                    self.warning(f'The port {name} is not unique in Service {service.name}. Ignoring the port')
                else:
                    if isinstance(target_port, str):
                        # check if all pods include this named port, and remove those that don't
                        pods_to_remove = Peer.PeerSet()
                        for pod in service.target_pods:
                            pod_named_port = pod.named_ports.get(target_port)
                            if not pod_named_port:
                                self.warning(f'The named port {target_port} referenced in Service {service.name}' 
                                             f' is not defined in the pod {pod}. Ignoring the pod')
                                pods_to_remove.add(pod)
                        service.target_pods -= pods_to_remove
        return service

    @staticmethod
    def load_services_from_live_cluster(peer_container):
        """
        Loads and parses service resources from live cluster
        :param PeerContainer peer_container: the peer container in which pods of the service are located
        :return: The list of parsed services in K8sService format
        """
        PeerContainer.locate_kube_config_file()
        yaml_file = CmdlineRunner.get_k8s_resources('service')
        srv_resources = yaml.load(yaml_file, Loader=yaml.SafeLoader)
        if not isinstance(srv_resources, dict):
            return []
        parser = K8sServiceYamlParser('k8s')
        res = []
        for srv_code in srv_resources.get('items', []):
            service = parser.parse_service(srv_code, peer_container)
            if service:
                res.append(service)
        return res

    @staticmethod
    def parse_service_resources(srv_resources_list, peer_container):
        """
        Parses the set of services in the container from one of the following resources:
         - git path of yaml file or a directory with yamls
         - local file (yaml or json) or a local directory containing yamls
         - query of the cluster
        :param list srv_resources_list: The service resource to be used.
            If set to 'k8s', will query cluster using kubectl
        :param PeerContainer peer_container: the peer container in which pods of the service are located
        :return: The list of parsed services in K8sService format
        """
        for srv_resources in srv_resources_list:
            # load from live cluster
            if srv_resources == 'k8s':
                return K8sServiceYamlParser.load_services_from_live_cluster(peer_container)
            else:
                res = []
                resource_scanner = TreeScannerFactory.get_scanner(srv_resources)
                if resource_scanner is None:
                    continue
                yaml_files = resource_scanner.get_yamls()
                for yaml_file in yaml_files:
                    parser = K8sServiceYamlParser(yaml_file)
                    for srv_code in yaml_file.data:
                        if not isinstance(srv_code, dict):
                            continue
                        kind = srv_code.get('kind')
                        if kind in {'List'}:
                            for srv_item in srv_code.get('items', []):
                                if isinstance(srv_item, dict) and srv_item.get('kind') in {'Service'}:
                                    service = parser.parse_service(srv_item, peer_container)
                                    if service:
                                        res.append(service)
                        elif kind in {'Service'}:
                            service = parser.parse_service(srv_code, peer_container)
                            if service:
                                res.append(service)
                return res
