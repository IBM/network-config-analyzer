#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
from abc import abstractmethod
from enum import Enum
from nca.CoreDS.Peer import PeerSet


class ServiceResource:
    """
    A class that represents service resources
    """
    def __init__(self, name, namespace_name):
        self.name = name
        self.namespace_name = namespace_name
        # The following self.namespace is a K8sNamespace (to be retrieved from namespace_name by the ServicesFinder)
        self.namespace = None
        self.target_pods = PeerSet()

    def __hash__(self):
        return hash(self.name)

    def __str__(self):
        return self.name

    @staticmethod
    def service_full_name(name, ns):
        return ns.name + '/' + name

    def full_name(self):
        return self.service_full_name(self.name, self.namespace)

    @abstractmethod
    def is_service_exported_to_namespace(self, namespace):
        raise NotImplementedError


class K8sService(ServiceResource):
    """
    Represents a K8s Service, storing its parameters
    """

    class ServiceType(Enum):
        ClusterIP = 0  # default
        NodePort = 1
        LoadBalancer = 2
        ExternalName = 3

    class ServicePort:
        """
        Represents a K8s Service port
        """
        def __init__(self, port, target_port, protocol, name=''):
            self.port = port
            self.target_port = target_port  # a target port may be a number or a string (named port)
            self.protocol = protocol
            self.name = name

    def __init__(self, name, namespace_name):
        """
        :param str name: a service name
        :param str namespace_name: a namespce name
        """
        super().__init__(name, namespace_name)
        self.type = self.ServiceType.ClusterIP
        self.selector = {}
        self.ports = {}  # a map from service port name to ServicePort object

    def __eq__(self, other):
        if isinstance(other, K8sService):
            return self.name == other.name and self.namespace == other.namespace
        return False

    def set_type(self, service_type):
        """
        Set a service label
        :param ServiceType service_type: The service type
        :return: None
        """
        self.type = service_type

    def add_selector(self, key, value):
        """
        Add/update a service selector
        :param str key: The selector key
        :param str value: The selector value
        :return: None
        """
        self.selector[key] = value

    def get_single_port(self):
        return list(self.ports.values())[0] if len(self.ports) == 1 else None

    def get_port_by_name(self, name):
        return self.ports.get(name)

    def get_port_by_number(self, number):
        for port in self.ports.values():
            if port.port == number:
                return port
        return None

    def add_port(self, service_port):
        """
        Add a service port
        :param ServicePort service_port: The port to add by the key servicePort.port
        :return: True iff successfully added the port, i.e. the port with this name did not exist
        """
        if self.ports.get(service_port.name):
            return False
        self.ports[service_port.name] = service_port
        return True

    def is_service_exported_to_namespace(self, namespace):
        return self.namespace == namespace


class IstioServiceEntry(ServiceResource):
    """
    Represents an Istio ServiceEntry object
    """
    def __init__(self, name, namespace_name):
        super().__init__(name, namespace_name)
        self.exported_to_all_namespaces = True
        self.exported_to_namespaces = []  # list of namespaces names that the service entry is exported to, to be filled
        # only if exported_to_all_namespaces is False

    def update_namespaces_fields(self, ns_list=None, all_flag=False):
        self.exported_to_all_namespaces = all_flag
        self.exported_to_namespaces = ns_list if not all_flag else []

    def add_host(self, dns_entry):
        if dns_entry:
            self.target_pods.add(dns_entry)

    def is_service_exported_to_namespace(self, namespace):
        return self.exported_to_all_namespaces or namespace in self.exported_to_namespaces

    def update_hosts_namespaces(self):
        namespaces = '*' if self.exported_to_all_namespaces else self.exported_to_namespaces
        for host in self.target_pods:
            host.update_namespaces(namespaces)
