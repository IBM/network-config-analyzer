#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from sys import stderr
import yaml
from Peer import PeerSet, Pod, IpBlock, HostEP
from K8sNamespace import K8sNamespace
from K8sServiceYamlParser import K8sServiceYamlParser
from CmdlineRunner import CmdlineRunner


class PodsFinder:
    """
    This class is responsible for populating the pods from the relevant input resources
    it builds a PeerSet and map of representative_peers to be used in the PeerContainer later.
    Resources that contain eps, may be:
    - git path of yaml file or a directory with yamls
    - local file (yaml or json) or a local directory containing yamls
    """
    pod_creation_resources = ['Deployment', 'ReplicaSet', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob',
                              'ReplicationController']

    def __init__(self):
        self.namespaces_finder = None
        self.peer_set = PeerSet()
        self.representative_peers = {}

    def load_peer_from_calico_resource(self):
        for peer_type in ['wep', 'hep', 'networkset', 'globalnetworkset']:
            peer_code = yaml.load(CmdlineRunner.get_calico_resources(peer_type),
                                  Loader=yaml.SafeLoader)
            self.add_eps_from_list(peer_code)

    def load_peer_from_k8s_live_cluster(self):
        peer_code = yaml.load(CmdlineRunner.get_k8s_resources('pod'), Loader=yaml.SafeLoader)
        self.add_eps_from_list(peer_code)

    def add_eps_from_list(self, ep_list):
        """
        Takes a resource-list object and adds all endpoints in the list to the container
        :param ep_list: A resource list object
        :return: None
        """
        if not ep_list:
            return

        if not isinstance(ep_list, dict):
            for ep_sub_list in ep_list:  # we must have a list of lists here - call recursively for each list
                self.add_eps_from_list(ep_sub_list)
            return

        kind = ep_list.get('kind')
        if kind in ['PodList', 'List']:  # 'List' for the case of live cluster
            for endpoint in ep_list.get('items', []):
                if kind == 'PodList' or (isinstance(endpoint, dict) and endpoint.get('kind') in {'Pod', 'Deployment'}):
                    self._add_pod_from_yaml(endpoint)
        elif kind in PodsFinder.pod_creation_resources:
            self._add_pod_from_workload_yaml(ep_list)
        elif kind in ['WorkloadEndpointList', 'HostEndpointList']:
            is_calico_wep = kind == 'WorkloadEndpointList'
            is_calico_hep = kind == 'HostEndpointList'
            for endpoint in ep_list.get('items', []):
                if is_calico_wep:
                    self._add_wep_from_yaml(endpoint)
                elif is_calico_hep:
                    self._add_hep_from_yaml(endpoint)
        elif kind in ['NetworkSetList', 'GlobalNetworkSetList']:
            for networkset in ep_list.get('items', []):
                self._add_networkset_from_yaml(networkset)
        elif kind in ['NetworkSet', 'GlobalNetworkSet']:
            self._add_networkset_from_yaml(ep_list)

    def _add_pod_from_yaml(self, pod_object):
        """
        Add a K8s Pod to the container based on the given resource instance
        :param dict pod_object: The pod object to add
        :return: None
        """
        metadata = pod_object.get('metadata', {})
        pod_name = metadata.get('name', '')
        pod_namespace = self.namespaces_finder.get_or_update_namespace(metadata.get('namespace', 'default'))
        kind = pod_object.get('kind')

        owner_name = ''
        owner_kind = ''
        owner_references = metadata.get('ownerReferences', [])
        if owner_references:
            owner_name = owner_references[0].get('name', '')  # take the first owner
            owner_kind = owner_references[0].get('kind', '')

        service_account_name = ''
        if kind == 'Pod':
            # serviceAccountName for a Pod:
            service_account_name = pod_object['spec'].get('serviceAccountName', 'default')
        elif kind in PodsFinder.pod_creation_resources:
            # serviceAccountName for a Deployment:
            template_spec = pod_object['spec'].get('template', {}).get('spec', {})
            service_account_name = template_spec.get('serviceAccountName', 'default')

        pod = Pod(pod_name, pod_namespace, owner_name, owner_kind, service_account_name)
        labels = metadata.get('labels', {})
        for key, val in labels.items():
            pod.set_label(key, val)

        containers = pod_object['spec'].get('containers', {})
        for container in containers:
            for port in container.get('ports', {}):
                pod.add_named_port(port.get('name'), port.get('containerPort'), port.get('protocol', 'TCP'))
        self._add_peer(pod)

    def _add_peer(self, peer):
        """
        Adds a specific peer to the container. Makes sure that no more than two isomorphic peers are added
        (we leave two isomorphic peers to model the connections between them)
        :param Endpoint peer: The peer to add
        :return: None
        """
        canonical_form = peer.canonical_form()
        peers_with_same_canonical_form = self.representative_peers.get(canonical_form, 0)
        if peers_with_same_canonical_form >= 2:  # We allow at most 2 peers from each equivalence group
            return
        self.representative_peers[canonical_form] = peers_with_same_canonical_form + 1
        self.peer_set.add(peer)

    def _add_pod_from_workload_yaml(self, workload_resource):
        """
        Add K8s Pods to the container based on the given workload resource
        Reference: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.20/#podtemplatespec-v1-core
        :param workload_resource: A workload resource object
        :return: None
        """
        metadata = workload_resource.get('metadata', {})
        workload_name = metadata.get('name', '')
        pod_namespace = self.namespaces_finder.get_or_update_namespace(metadata.get('namespace', 'default'))

        workload_spec = workload_resource.get('spec', {})
        replicas = workload_spec.get('replicas', 1)

        if workload_resource.get('kind') == 'Job':
            # Reference: https://kubernetes.io/docs/concepts/workloads/controllers/job/
            parallelism = workload_spec.get('parallelism', 1)
            if parallelism == 0:
                return  # paused job, no pods are generated
            replicas = parallelism
        if workload_resource.get('kind') == 'CronJob':
            workload_spec = workload_spec.get('jobTemplate', {}).get('spec', {})

        template_spec = workload_spec.get('template', {}).get('spec', {})
        service_account_name = template_spec.get('serviceAccountName', 'default')

        replicas = min(replicas, 2)  # We allow at most 2 peers from each equivalence group
        for pod_index in range(1, replicas + 1):
            pod = Pod(f'{workload_name}-{pod_index}', pod_namespace, workload_name, workload_resource.get('kind'),
                      service_account_name)
            pod_template = workload_spec.get('template', {})
            labels = pod_template.get('metadata', {}).get('labels', {})
            for key, val in labels.items():
                pod.set_label(key, val)
            pod_containers = pod_template.get('spec', {}).get('containers', [])
            for container in pod_containers:
                for port in container.get('ports', []):
                    pod.add_named_port(port.get('name'), port.get('containerPort'), port.get('protocol', 'TCP'))
            self._add_peer(pod)

    def _add_networkset_from_yaml(self, networkset_object):
        """
        Add a Calico NetworkSet to the container based on the given resource instance
        :param dict networkset_object: The networkSet object to add
        :return: None
        """
        kind = networkset_object.get('kind')
        is_global = kind == 'GlobalNetworkSet'
        metadata = networkset_object.get('metadata', {})
        spec = networkset_object.get('spec', {})
        name = metadata.get('name', '')
        if name == '':
            print('NetworkSet must have a name', file=stderr)
            return
        if is_global:
            namespace = None
        else:
            namespace_name = metadata.get('namespace', 'default')
            namespace = self.namespaces_finder.get_or_update_namespace(namespace_name)
        ipb = IpBlock(name=name, namespace=namespace, is_global=is_global)
        labels = metadata.get('labels', {})
        if not labels:
            print(f'NetworkSet {name} should have labels', file=stderr)
        for key, val in labels.items():
            ipb.set_label(key, val)
        cidrs = spec.get('nets', {})
        for cidr in cidrs:
            ipb.add_cidr(cidr)
        self._add_peer(ipb)

    def _add_hep_from_yaml(self, hep_object):
        """
        Add a Calico HostEndpoint to the container based on the given resource instance
        :param dict hep_object: The hep object to add
        :return: None
        """
        metadata = hep_object.get('metadata', {})
        spec = hep_object.get('spec', {})
        hep_name = metadata.get('name', '')
        hep = HostEP(hep_name)

        labels = metadata.get('labels', {})
        for key, val in labels.items():
            hep.set_label(key, val)

        for port in spec.get('ports', []):
            hep.add_named_port(port.get('name'), port.get('port'), port.get('protocol', 'TCP'))

        for profile in spec.get('profiles', []):
            hep.add_profile(profile)

        self._add_peer(hep)

    def _add_wep_from_yaml(self, wep_object):
        """
        Add a Calico WorkloadEndpoint to the container based on the given resource instance
        :param dict wep_object: The wep object to add
        :return: None
        """
        metadata = wep_object.get('metadata', {})
        spec = wep_object.get('spec', {})
        wep_namespace = self.namespaces_finder.get_or_update_namespace(metadata.get('namespace', 'default'))
        wep_name = spec.get('pod', '')
        wep = Pod(wep_name, wep_namespace)
        # TODO: handle Pod's serviceAccountName: A wep definition includes a pod field which points to the
        #  corresponding k8s Pod resource.

        labels = metadata.get('labels', {})
        for key, val in labels.items():
            wep.set_label(key, val)

        for port in spec.get('ports', []):
            wep.add_named_port(port.get('name'), port.get('port'), port.get('protocol', 'TCP'))

        for profile in spec.get('profiles', []):
            wep.add_profile(profile)

        self._add_peer(wep)


class NameSpacesFinder:
    """
    This class is responsible for populating the namespaces from relevant input resources.
    Resources that contain namespaces, may be:
    - git path of yaml file or a directory with yamls
    - local file (yaml or json) or a local directory containing yamls
    """
    def __init__(self):
        self.namespaces = {}

    def parse_yaml_code_for_ns(self, res_code):
        if isinstance(res_code, dict) and res_code.get('kind') in {'NamespaceList', 'List'}:
            self.set_namespaces(res_code)

    def load_ns_from_live_cluster(self):
        yaml_file = CmdlineRunner.get_k8s_resources('namespace')
        ns_code = yaml.load(yaml_file, Loader=yaml.SafeLoader)
        self.set_namespaces(ns_code)

    def set_namespaces(self, ns_list):
        """
        Given a NamespaceList resource, adds all namespaces in the list to the container
        :param dict ns_list: The NamespaceList resource
        :return: None
        """
        if not isinstance(ns_list, dict):
            return

        for namespace in ns_list.get('items', []):
            self._add_namespace(namespace, ns_list.get('kind') == 'List')

    def _add_namespace(self, ns_object, generic_list):
        """
        Adds a single namespace to the container
        :param dict ns_object: The Namespace resource to add
        :param bool generic_list: When list has the generic kind 'List', we have to check the resource kind
        :return: None
        """
        if generic_list and ns_object.get('kind') != 'Namespace':
            return
        metadata = ns_object.get('metadata', {})
        ns_name = metadata.get('name', '')
        namespace = K8sNamespace(ns_name)
        labels = metadata.get('labels', {})
        for key, val in labels.items():
            namespace.set_label(key, val)
        self.namespaces[ns_name] = namespace

    def get_or_update_namespace(self, ns_name):
        """
        Get a K8sNamespace object for a given namespace name. If namespace is missing, then add it
        :param str ns_name: The name of the required namespace
        :return: A relevant K8sNamespace
        :rtype: K8sNamespace
        """
        if ns_name not in self.namespaces:
            namespace = K8sNamespace(ns_name)
            self.namespaces[ns_name] = namespace
        return self.namespaces[ns_name]


class ServicesFinder:
    """
    This class is responsible for populating the services in the relevant input resources
    Resources that contain services, may be:
    - git path of yaml file or a directory with yamls
    - local file (yaml or json) or a local directory containing yamls
    """

    def __init__(self):
        self.namespaces_finder = None
        self.services_list = []

    def load_services_from_live_cluster(self):
        """
        Loads and parses service resources from live cluster
        :return: The list of parsed services in K8sService format
        """
        yaml_file = CmdlineRunner.get_k8s_resources('service')
        srv_resources = yaml.load(yaml_file, Loader=yaml.SafeLoader)
        if not isinstance(srv_resources, dict):
            return
        parser = K8sServiceYamlParser('k8s')
        for srv_code in srv_resources.get('items', []):
            service = parser.parse_service(srv_code)
            if service:
                service.namespace = self.namespaces_finder.get_or_update_namespace(service.namespace.name)
                self.services_list.append(service)

    def parse_yaml_code_for_service(self, res_code, yaml_file):
        parser = K8sServiceYamlParser(yaml_file)
        if not isinstance(res_code, dict):
            return
        kind = res_code.get('kind')
        if kind in {'List'}:
            for srv_item in res_code.get('items', []):
                if isinstance(srv_item, dict) and srv_item.get('kind') in {'Service'}:
                    service = parser.parse_service(srv_item)
                    if service:
                        service.namespace = self.namespaces_finder.get_or_update_namespace(service.namespace.name)
                        self.services_list.append(service)
        elif kind in {'Service'}:
            service = parser.parse_service(res_code)
            if service:
                service.namespace = self.namespaces_finder.get_or_update_namespace(service.namespace.name)
                self.services_list.append(service)
