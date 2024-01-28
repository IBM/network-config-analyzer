#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from sys import stderr
import yaml
from nca.Utils.CmdlineRunner import CmdlineRunner
from nca.CoreDS.Peer import PeerSet, Pod, IpBlock, HostEP, BasePeerSet
from nca.Resources.OtherResources.K8sNamespace import K8sNamespace
from nca.Parsers.IstioServiceEntryYamlParser import IstioServiceEntryYamlParser
from nca.Parsers.K8sServiceYamlParser import K8sServiceYamlParser
from nca.Utils.NcaLogger import NcaLogger
from nca.Utils.ExplTracker import ExplTracker


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
                                  Loader=yaml.CSafeLoader)
            self.add_eps_from_yaml(peer_code)

    def load_peer_from_istio_resource(self):
        peer_code = yaml.load(CmdlineRunner.get_k8s_resources(['serviceentry']), Loader=yaml.CSafeLoader)
        self.add_eps_from_yaml(peer_code)

    def load_peer_from_k8s_live_cluster(self):
        peer_code = yaml.load(CmdlineRunner.get_k8s_resources(['pod']), Loader=yaml.CSafeLoader)
        self.add_eps_from_yaml(peer_code)

    def add_eps_from_yaml(self, yaml_obj, kind_override=None):
        """
        Takes a yaml object (typically a dict or a list) and creates appropriate endpoints from it
        :param yaml_obj: A code of python object generated by yaml.load()
        :param kind_override: if set, ignoring the object kind and using this param instead
        :return: None
        """
        if isinstance(yaml_obj, list):
            for ep_sub_list in yaml_obj:  # e.g. when we have a list of lists - call recursively for each list
                self.add_eps_from_yaml(ep_sub_list)
            return
        if not isinstance(yaml_obj, dict):
            return
        kind = yaml_obj.get('kind') if not kind_override else kind_override
        if kind in ['List', 'PodList', 'WorkloadEndpointList', 'HostEndpointList', 'NetworkSetList',
                    'GlobalNetworkSetList']:
            for endpoint in yaml_obj.get('items', []):
                self.add_eps_from_yaml(endpoint, kind[:-4])
        elif kind == 'Pod':
            self._add_pod_from_yaml(yaml_obj)
        elif kind in PodsFinder.pod_creation_resources:
            self._add_pod_from_workload_yaml(yaml_obj)
        elif kind == 'WorkloadEndpoint':
            self._add_wep_from_yaml(yaml_obj)
        elif kind == 'HostEndpoint':
            self._add_hep_from_yaml(yaml_obj)
        elif kind in ['NetworkSet', 'GlobalNetworkSet']:
            self._add_networkset_from_yaml(yaml_obj)
        elif kind == 'ServiceEntry':
            self._add_dns_entries_from_yaml(yaml_obj)

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
            for port in container.get('ports') or []:
                pod.add_named_port(port.get('name'), port.get('containerPort'), port.get('protocol', 'TCP'))
        self._add_peer(pod)
        if ExplTracker().is_active():
            ExplTracker().add_item(pod_object.path, pod_object.line_number, pod.full_name(), pod.workload_name)

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
        BasePeerSet().add_peer(peer)

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
                for port in container.get('ports') or []:
                    pod.add_named_port(port.get('name'), port.get('containerPort'), port.get('protocol', 'TCP'))
            self._add_peer(pod)
            if ExplTracker().is_active():
                ExplTracker().add_item(workload_resource.path,
                                       workload_resource.line_number,
                                       pod.full_name(),
                                       pod.workload_name
                                       )

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
        if ExplTracker().is_active():
            ExplTracker().add_item(networkset_object.path, networkset_object.line_number, ipb.full_name())

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

        for port in spec.get('ports') or []:
            hep.add_named_port(port.get('name'), port.get('port'), port.get('protocol', 'TCP'))

        for profile in spec.get('profiles') or []:
            hep.add_profile(profile)

        self._add_peer(hep)
        if ExplTracker().is_active():
            ExplTracker().add_item(hep_object.path, hep_object.line_number, hep.full_name())

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

        for port in spec.get('ports') or []:
            wep.add_named_port(port.get('name'), port.get('port'), port.get('protocol', 'TCP'))

        for profile in spec.get('profiles') or []:
            wep.add_profile(profile)

        self._add_peer(wep)
        if ExplTracker().is_active():
            ExplTracker().add_item(wep_object.path, wep_object.line_number, wep.full_name(), wep.workload_name)

    def _add_dns_entries_from_yaml(self, srv_entry_object):
        """
        Add DNSEntry peers to the container based on the given istio ServiceEntry resource instance
        :param dict srv_entry_object: The service-entry object to parse for dns-entry peers
        :return: None
        """
        parser = IstioServiceEntryYamlParser()
        dns_entries = parser.parse_serviceentry(srv_entry_object, self.peer_set)
        for dns_entry in dns_entries:
            self._add_peer(dns_entry)
            if ExplTracker().is_active():
                ExplTracker().add_item(srv_entry_object.path, srv_entry_object.line_number, dns_entry.full_name())


class NamespacesFinder:
    """
    This class is responsible for populating the namespaces from relevant input resources.
    Resources that contain namespaces, may be:
    - git path of yaml file or a directory with yamls
    - local file (yaml or json) or a local directory containing yamls
    """
    def __init__(self):
        self.namespaces = {}

    def parse_yaml_code_for_ns(self, res_code):
        if not isinstance(res_code, dict):
            return
        res_kind = res_code.get('kind')
        if res_kind in {'NamespaceList', 'List'}:
            self.set_namespaces(res_code)
        elif res_kind == 'Namespace':
            self._add_namespace(res_code, False)

    def load_ns_from_live_cluster(self):
        yaml_file = CmdlineRunner.get_k8s_resources(['namespace'])
        ns_code = yaml.load(yaml_file, Loader=yaml.CSafeLoader)
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
            NcaLogger().log_message(msg=f'Namespace {ns_name} is missing from the peer container', file=stderr)
            namespace = K8sNamespace(ns_name)
            self.namespaces[ns_name] = namespace
        return self.namespaces[ns_name]


class ServicesFinder:
    """
    This class is responsible for populating the services in the relevant input resources.
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
        yaml_file = CmdlineRunner.get_k8s_resources(['service'])
        srv_resources = yaml.load(yaml_file, Loader=yaml.CSafeLoader)
        if not isinstance(srv_resources, dict):
            return
        parser = K8sServiceYamlParser('k8s')
        for srv_code in srv_resources.get('items', []):
            self._parse_and_update_services_list(srv_code, parser)

    def parse_yaml_code_for_service(self, res_code, yaml_file):
        parser = K8sServiceYamlParser(yaml_file)
        if not isinstance(res_code, dict):
            return
        kind = res_code.get('kind')
        if kind in {'List'}:
            for srv_item in res_code.get('items', []):
                if isinstance(srv_item, dict) and srv_item.get('kind') in ['Service']:
                    self._parse_and_update_services_list(srv_item, parser)
        elif kind in ['Service']:
            self._parse_and_update_services_list(res_code, parser)

    def _parse_and_update_services_list(self, srv_object, parser):
        """
        parses the service object using the given parser and updates the services_list accordingly
        :param dict srv_object: the service object code from the yaml content
        :param K8sServiceYamlParser parser: the service object parser
        """
        service = parser.parse_service(srv_object)
        if service:
            service.namespace = self.namespaces_finder.get_or_update_namespace(service.namespace_name)
            self.services_list.append(service)
