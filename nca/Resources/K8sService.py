#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
from dataclasses import dataclass
from enum import Enum
from typing import Union

from nca.CoreDS.Peer import PeerSet


class K8sService:
    """
    Represents a K8s Service, storing its parameters
    """

    class ServiceType(Enum):
        ClusterIP = 0  # default
        NodePort = 1
        LoadBalancer = 2
        ExternalName = 3

    @dataclass
    class ServicePort:
        """
        Represents a K8s Service port
        """
        port_num: int
        name: str
        protocol: str
        target_port: Union[str, int]

    def __init__(self, name, namespace_name):
        """
        :param str name: a service name
        :param str namespace_name: a namespce name
        """
        self.name = name
        self.namespace_name = namespace_name
        # The following self.namespace is a K8sNamespace
        # (to be retrieved from namespace_name by PeerContainer._set_services_and_populate_target_pods)
        self.namespace = None
        self.type = self.ServiceType.ClusterIP
        self.selector = {}
        self.ports = {}  # a map from service port name to ServicePort object
        self.target_pods = PeerSet()

    def __eq__(self, other):
        if isinstance(other, K8sService):
            return self.name == other.name and self.namespace == other.namespace
        return False

    def __hash__(self):
        return hash(self.name)

    def __str__(self):
        return self.name

    @staticmethod
    def service_full_name(name, ns):
        return ns.name + '/' + name

    def full_name(self):
        return self.service_full_name(self.name, self.namespace)

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
            if port.port_num == number:
                return port
        return None

    def add_port(self, service_port):
        """
        Add a service port
        :param ServicePort service_port: The port to add by the key servicePort.port_num
        :return: True iff successfully added the port, i.e. the port with this name did not exist
        """
        if self.ports.get(service_port.name):
            return False
        self.ports[service_port.name] = service_port
        return True
