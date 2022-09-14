#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from nca.Resources.K8sService import K8sService
from .GenericYamlParser import GenericYamlParser


class K8sServiceYamlParser(GenericYamlParser):
    """
    A parser for k8s service resources
    """

    def __init__(self, service_file_name=''):
        """
        :param str service_file_name: The name of the yaml file containing K8s service resources
        """
        GenericYamlParser.__init__(self, service_file_name)

    def parse_service(self, srv_object):  # noqa: C901
        """
        Parses a service resource object and creates a K8sService object
        :param dict srv_object: the service object to parse
        :return: K8sService object or None
        """
        srv_name, srv_ns = self.parse_generic_yaml_objects_fields(srv_object, ['Service'], ['v1'], ['v1', 'k8s'])
        if srv_name is None:
            return None  # Not a k8s Service object

        service = K8sService(srv_name, srv_ns)
        service_spec = srv_object.get('spec')
        if not service_spec:
            self.warning(f'Spec is missing or null in Service {srv_name}. Ignoring the service')
            return None
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
