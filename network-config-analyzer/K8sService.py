#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from enum import Enum
import Peer
from K8sNamespace import K8sNamespace


class K8sService:
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
        self.name = name
        self.namespace = K8sNamespace(namespace_name)
        self.type = self.ServiceType.ClusterIP
        self.selector = {}
        self.ports = {}  # a map from service port name to ServicePort object
        self.target_pods = Peer.PeerSet()

    def __eq__(self, other):
        if isinstance(other, K8sService):
            return self.name == other.name and self.namespace == other.namespace
        return NotImplemented

    def __hash__(self):
        return hash(self.name)

    def __str__(self):
        return self.name

    def full_name(self):
        return self.namespace.name + '/' + self.name

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
