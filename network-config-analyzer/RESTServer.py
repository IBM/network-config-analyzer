#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from flask import Flask, request, escape
from flask.views import MethodView
from NetworkConfig import NetworkConfig
from NetworkConfigQuery import SanityQuery
from ResourcesHandler import ResourcesParser


class NCAResource(MethodView):
    def __init__(self, policy_sets_map, resources_parser):
        # type: (dict, ResourcesParser) -> None
        self.policy_sets_map = policy_sets_map
        self.resources_parser = resources_parser


class AllResource(NCAResource):
    def delete(self):
        self.policy_sets_map.clear()
        peer_container = self.resources_parser.build_peer_container()
        peer_container.delete_all_peers()
        peer_container.delete_all_namespaces()
        return 'Successfully deleted all resources', 200


class NamespaceListResource(NCAResource):
    def post(self):
        if not request.is_json:
            return 'Badly formed json in POST request', 400
        json_data = request.get_json()
        self.resources_parser.ns_finder.set_namespaces(json_data)
        return f'{len(self.resources_parser.ns_finder.namespaces)} namespaces loaded.', 201


class NamespacesResource(NCAResource):
    def get(self):
        namespaces = self.resources_parser.build_peer_container().get_namespaces()
        return {'namespaces': [key for key in namespaces.keys()]}

    def delete(self):
        peer_container = self.resources_parser.build_peer_container()
        if peer_container.get_num_peers() > 0:
            return 'Delete all pods first', 405
        peer_container.delete_all_namespaces()
        return 'Successfully deleted all namespaces', 200


class NamespaceResource(NCAResource):
    def get(self, ns_name):
        peer_container = self.resources_parser.build_peer_container()
        if ns_name not in peer_container.get_namespaces().keys():
            return f'Namespace {escape(ns_name)} does not exist', 404
        # ns = self.peer_container.get_namespace(ns_name)
        return {ns_name: 'OK'}


class PodListResource(NCAResource):
    def post(self):
        if not request.is_json:
            return 'Badly formed json in POST request', 400
        json_data = request.get_json()
        self.resources_parser.pods_finder.namespaces_finder = self.resources_parser.ns_finder
        self.resources_parser.pods_finder.add_eps_from_yaml(json_data)
        peer_container = self.resources_parser.build_peer_container()
        return f'{len(peer_container.get_all_peers_group())} pods loaded.', 201


class PodsResource(NCAResource):
    def get(self):
        pods = self.resources_parser.build_peer_container().get_all_peers_group()
        return {'pods': [pod.name for pod in pods]}

    def delete(self):
        if self.policy_sets_map:
            return 'Delete all policy_sets first', 405
        self.resources_parser.build_peer_container().delete_all_peers()
        return 'Successfully deleted all pods', 200


class PolicySetsResource(NCAResource):
    def get(self):
        return {'policy_sets': [policy_set for policy_set in self.policy_sets_map.keys()]}

    def post(self):
        if not request.is_json:
            return 'Badly formed json in POST request', 400

        set_num = 0
        while True:
            new_policy_set = 'set_' + str(set_num)
            if new_policy_set not in self.policy_sets_map:
                break
            set_num += 1

        # noinspection PyBroadException
        try:
            entry = request.get_data().decode("utf-8")
            peer_container = self.resources_parser.build_peer_container()
            self.resources_parser.policies_finder.set_peer_container(peer_container)
            self.resources_parser.policies_finder.load_policies_from_buffer(entry)
            self.resources_parser.policies_finder.parse_policies_in_parse_queue()
            network_config = NetworkConfig(new_policy_set, peer_container,
                                           self.resources_parser.policies_finder.policies_container)

        except Exception:
            return 'Badly formed policy list', 400

        SanityQuery(network_config).exec()
        self.policy_sets_map[new_policy_set] = network_config
        return f'{new_policy_set} ({len(network_config.policies)} policies)', 201

    def delete(self):
        self.policy_sets_map.clear()
        return 'Successfully deleted all policy_sets', 200


class PolicySetResource(NCAResource):
    def get(self, config_name):
        if config_name not in self.policy_sets_map:
            return f'policy_set {escape(config_name)} does not exist', 404

        config = self.policy_sets_map[config_name]
        policies_array = [policy[0] for policy in config.policies.keys()]
        profiles_array = [profile for profile in config.profiles.keys()]
        return {'name': escape(config_name), 'policies': policies_array, 'profiles': profiles_array}

    def delete(self, config_name):
        if config_name not in self.policy_sets_map:
            return f'policy_set {escape(config_name)} does not exist', 404
        del self.policy_sets_map[config_name]
        return f'Successfully deleted policy_set {escape(config_name)}', 200


class PolicySetFindings(NCAResource):
    def get(self, config_name):
        if config_name not in self.policy_sets_map:
            return f'policy_set {escape(config_name)} does not exist', 404

        config = self.policy_sets_map[config_name]
        policies_array = {}
        for policy in config.policies.values():
            policies_array[policy.full_name()] = policy.findings
        profiles_array = {}
        for profile in config.profiles.values():
            profiles_array[profile.full_name()] = profile.findings
        return {'name': escape(config_name), 'policies': policies_array, 'profiles': profiles_array}


class RestServer:
    def __init__(self, ns_list, pod_list, resource_list):
        self.app = Flask(__name__)
        self.policy_sets_map = {}
        self.resources_parser = ResourcesParser()
        self.resources_parser.parse_lists_for_topology(ns_list, pod_list, resource_list)
        self.add_url_rule('/all', AllResource, 'all')
        self.add_url_rule('/namespaces', NamespacesResource, 'namespaces')
        self.add_url_rule('/namespaces/<ns_name>', NamespaceResource, 'namespace')
        self.add_url_rule('/namespace_list', NamespaceListResource, 'namespace_list')
        self.add_url_rule('/pods', PodsResource, 'pods')
        self.add_url_rule('/pod_list', PodListResource, 'pod_list')
        self.add_url_rule('/policy_sets', PolicySetsResource, 'policy_sets')
        self.add_url_rule('/policy_sets/<config_name>', PolicySetResource, 'policy_set')
        self.add_url_rule('/policy_sets/<config_name>/findings', PolicySetFindings, 'findings')

    def add_url_rule(self, path, class_type, name):
        self.app.add_url_rule(path, view_func=class_type.as_view(name, policy_sets_map=self.policy_sets_map,
                                                                 resources_parser=self.resources_parser))

    def run(self):
        return self.app.run(host='0.0.0.0')
