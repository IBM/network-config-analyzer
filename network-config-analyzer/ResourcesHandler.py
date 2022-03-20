from NetworkConfig import NetworkConfig
from ResourcesParser import ResourcesParser


class ResourcesHandler:
    """
    This class gets all resources (network policies, pods, namespaces...) from cmdline arguments or scheme files entries
    and using the Resources Parser, parses the input entries to finally build the Network Configs
    """
    def __init__(self, base_np_list, base_resource_list, base_ns_list, base_pod_list, np_list, resource_list, ns_list, pod_list, config_name='global'):
        self.base_ns_list = base_ns_list or ns_list
        self.base_pod_list = base_pod_list or pod_list
        self.base_np_list = base_np_list or np_list
        self.base_resource_list = base_resource_list or resource_list
        self.ns_list = ns_list
        self.pod_list = pod_list
        self.np_list = np_list
        self.resource_list = resource_list
        self.config_name = config_name

    def get_base_network_config(self):
        base_resources_parser = ResourcesParser(self.base_ns_list, self.base_pod_list, self.base_resource_list,
                                                self.config_name)
        base_peer_container = base_resources_parser.build_peer_container()
        # TODO: parsing the network policies will be done by the ResourcesParser too
        if self.base_np_list and self.base_resource_list:
            print(f'the network-policies will be taken only from {self.base_np_list}')
        base_np_list = self.base_np_list or self.base_resource_list or 'k8s'
        base_network_config = NetworkConfig(base_np_list, base_peer_container, [base_np_list])
        return base_network_config

    def get_network_config(self):
        resources_parser = ResourcesParser(self.ns_list, self.pod_list,
                                           self.resource_list, self.config_name)
        peer_container = resources_parser.build_peer_container()
        # TODO: parsing the network policies will be done by the ResourcesParser too
        if self.np_list and self.resource_list:
            print(f'the network policies will be taken only from {self.np_list}')
        np_list = self.np_list or self.resource_list or 'k8s'
        network_config = NetworkConfig(np_list, peer_container, [np_list])
        return network_config
