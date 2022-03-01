#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

import yaml
from K8sService import K8sService
from CmdlineRunner import CmdlineRunner
from GenericTreeScanner import TreeScannerFactory
from GenericYamlParser import GenericYamlParser


class K8sServiceYamlParser(GenericYamlParser):
    """
    A parser for k8s service resources
    """

    def __init__(self, service_file_name=''):
        """
        :param str service_file_name: The name of the yaml file containing K8s service resources
        """
        GenericYamlParser.__init__(self, service_file_name)

    def parse_service(self, srv_object):
        """
        Parses a service resource object and creates a K8sService object
        :param dict srv_object: the service object to parse
        :return: K8sService object or None
        """
        if srv_object.get('kind') != 'Service' or srv_object.get('apiVersion') != 'v1':
            return None  # Not a v1 Service object
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
                service.add_selector(key, val)

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
        return service

    @staticmethod
    def load_services_from_live_cluster():
        """
        Loads and parses service resources from live cluster
        :return: The list of parsed services in K8sService format
        """
        yaml_file = CmdlineRunner.get_k8s_resources('service')
        srv_resources = yaml.load(yaml_file, Loader=yaml.SafeLoader)
        if not isinstance(srv_resources, dict):
            return []
        parser = K8sServiceYamlParser('k8s')
        res = []
        for srv_code in srv_resources.get('items', []):
            service = parser.parse_service(srv_code)
            if service:
                res.append(service)
        return res

    @staticmethod
    def parse_service_resources(srv_resources_list):
        """
        Parses the set of services in the container from one of the following resources:
         - git path of yaml file or a directory with yamls
         - local file (yaml or json) or a local directory containing yamls
         - query of the cluster
        :param list srv_resources_list: The service resource to be used.
            If set to 'k8s', will query cluster using kubectl
        :return: The list of parsed services in K8sService format
        """
        res = []
        for srv_resources in srv_resources_list:
            # load from live cluster
            if srv_resources == 'k8s':
                res.extend(K8sServiceYamlParser.load_services_from_live_cluster())
            else:
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
                                    service = parser.parse_service(srv_item)
                                    if service:
                                        res.append(service)
                        elif kind in {'Service'}:
                            service = parser.parse_service(srv_code)
                            if service:
                                res.append(service)
        return res
