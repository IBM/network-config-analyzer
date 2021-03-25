#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

from flask import Flask, request
from flask_restful import Resource, Api, abort
from PeerContainer import PeerContainer
from NetworkConfig import NetworkConfig
from NetworkConfigQuery import SanityQuery


class NCAResource(Resource):
    def __init__(self, policy_sets_map, peer_container):
        # type: (dict, PeerContainer) -> None
        self.policy_sets_map = policy_sets_map
        self.peer_container = peer_container


class AllResource(NCAResource):
    def delete(self):
        self.policy_sets_map.clear()
        self.peer_container.delete_all_peers()
        self.peer_container.delete_all_namespaces()
        return 'Successfully deleted all resources', 200


class NamespaceListResource(NCAResource):
    def post(self):
        if not request.is_json:
            abort(400, message='Badly formed json in POST request')
        json_data = request.get_json()
        self.peer_container.set_namespaces(json_data)
        return '{} namespaces loaded.'.format(len(self.peer_container.get_namespaces())), 201


class NamespacesResource(NCAResource):
    def get(self):
        namespaces = self.peer_container.get_namespaces()
        return {'namespaces': [namespaces.keys()]}

    def delete(self):
        if self.peer_container.get_num_peers() > 0:
            abort(405, message='Delete all pods first')
        self.peer_container.delete_all_namespaces()
        return 'Successfully deleted all namespaces', 200


class NamespaceResource(NCAResource):
    def get(self, ns_name):
        if ns_name not in self.peer_container.get_namespaces().keys():
            abort(404, message='Namespace {} does not exist'.format(ns_name))
        # ns = self.peer_container.get_namespace(ns_name)
        return {ns_name:  'OK'}


class PodListResource(NCAResource):
    def post(self):
        if not request.is_json:
            abort(400, message='Badly formed json in POST request')
        json_data = request.get_json()
        self.peer_container.add_eps_from_list(json_data)
        return '{} pods loaded.'.format(len(self.peer_container.get_all_peers_group())), 201


class PodsResource(NCAResource):
    def get(self):
        pods = self.peer_container.get_all_peers_group()
        return {'pods': [pod.name for pod in pods]}

    def delete(self):
        if self.policy_sets_map:
            abort(405, message='Delete all policy_sets first')
        self.peer_container.delete_all_peers()
        return 'Successfully deleted all pods', 200


class PolicySetsResource(NCAResource):
    def get(self):
        return {'policy_sets': [self.policy_sets_map.keys()]}

    def post(self):
        if not request.is_json:
            abort(400, message='Badly formed json in POST request')

        set_num = 0
        while True:
            new_policy_set = 'set_' + str(set_num)
            if new_policy_set not in self.policy_sets_map:
                break
            set_num += 1

        # noinspection PyBroadException
        try:
            entry = 'buffer: ' + request.get_data().decode("utf-8")
            network_config = NetworkConfig(new_policy_set, self.peer_container, [entry])
        except Exception:
            abort(400, message='Badly formed policy list')
            return

        SanityQuery(network_config).exec()
        self.policy_sets_map[new_policy_set] = network_config
        return new_policy_set + ' (' + str(len(network_config.policies)) + ' policies)', 201

    def delete(self):
        self.policy_sets_map.clear()
        return 'Successfully deleted all policy_sets', 200


class PolicySetResource(NCAResource):
    def get(self, config_name):
        if config_name not in self.policy_sets_map:
            abort(404, message='policy_set {} does not exist'.format(config_name))

        config = self.policy_sets_map[config_name]
        policies_array = [config.policies.keys()]
        profiles_array = [config.profiles.keys()]
        return {'name': config_name, 'policies': policies_array, 'profiles': profiles_array}

    def delete(self, config_name):
        if config_name not in self.policy_sets_map:
            abort(404, message='policy_set {} does not exist'.format(config_name))
        del self.policy_sets_map[config_name]
        return 'Successfully deleted policy_set ' + config_name, 200


class PolicySetFindings(NCAResource):
    def get(self, config_name):
        if config_name not in self.policy_sets_map:
            abort(404, message='policy_set {} does not exist'.format(config_name))

        config = self.policy_sets_map[config_name]
        policies_array = {}
        for policy in config.policies.values():
            policies_array[policy.full_name()] = policy.findings
        profiles_array = {}
        for profile in config.profiles.values():
            profiles_array[profile.full_name()] = profile.findings
        return {'name': config_name, 'policies': policies_array, 'profiles': profiles_array,
                'global_findings': config.findings}


class RestServer:
    def __init__(self, ns_list, pod_list):
        self.app = Flask(__name__)
        self.api = Api(self.app)
        self.policy_sets_map = {}
        self.peer_container = PeerContainer(ns_list, pod_list)
        args_map = {'peer_container': self.peer_container, 'policy_sets_map': self.policy_sets_map}
        self.api.add_resource(AllResource, '/all', resource_class_kwargs=args_map)
        self.api.add_resource(NamespacesResource, '/namespaces', resource_class_kwargs=args_map)
        self.api.add_resource(NamespaceResource, '/namespaces/<ns_name>', resource_class_kwargs=args_map)
        self.api.add_resource(NamespaceListResource, '/namespace_list', resource_class_kwargs=args_map)
        self.api.add_resource(PodsResource, '/pods', resource_class_kwargs=args_map)
        self.api.add_resource(PodListResource, '/pod_list', resource_class_kwargs=args_map)
        self.api.add_resource(PolicySetsResource, '/policy_sets', resource_class_kwargs=args_map)
        self.api.add_resource(PolicySetResource, '/policy_sets/<config_name>', resource_class_kwargs=args_map)
        self.api.add_resource(PolicySetFindings, '/policy_sets/<config_name>/findings', resource_class_kwargs=args_map)

    def run(self):
        return self.app.run(host='0.0.0.0')
