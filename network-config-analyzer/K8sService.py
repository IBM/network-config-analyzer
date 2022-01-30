#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from enum import Enum
import Peer

class K8sService:
    """
    Represents a K8s Service, storing its parameters
    """

    class ServiceType(Enum):
        ClusterIP = 0 # default
        NodePort = 1
        LoadBalancer = 2
        ExternalName = 3

    class ServicePort:
        """
        Represents a K8s Service port
        """
        def __init__(self, port, target_port, protocol, name=''):
            self.port = port
            # a target port may be given either as a number or as a string (named port)
            if isinstance(target_port, int):
                self.target_port_number = target_port
            else:
                self.target_port_name = target_port
            self.protocol = protocol
            self.name = name

    def __init__(self, name):
        self.name = name
        self.labels = {}  # Storing the namespace labels in a dict as key-value pairs
        self.type = self.ServiceType.ClusterIP
        self.selector = {}
        self.ports = {}  # a map from service port name to ServicePort object
        self.target_pods = Peer.PeerSet()

    def __eq__(self, other):
        if isinstance(other, K8sService):
            return self.name == other.name
        return NotImplemented

    def __hash__(self):
        return hash(self.name)

    def __str__(self):
        return self.name

    def set_type(self, type):
        """
        Set a service label
        :param ServiceType type: The service type
        :return: None
        """
        self.type = type

    def add_selector(self, key, value):
        """
        Add/update a service selector
        :param str key: The selector key
        :param str value: The selector value
        :return: None
        """
        self.selector[key] = value

    def add_port(self, servicePort):
        """
        Add a service port
        :param ServicePort servicePort: The port to add by the key servicePort.port
        :return: True iff successfully added the port, i.e. the port with this name did not exist
        """
        if self.ports.get(servicePort.name) is not None:
            return False
        self.ports[servicePort.name] = servicePort
        return True