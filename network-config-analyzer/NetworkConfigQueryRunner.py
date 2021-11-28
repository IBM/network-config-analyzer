import NetworkConfigQuery
from NetworkConfig import NetworkConfig


class NetworkConfigQueryRunner:
    OneConfigQueryMap = {
        'sanity': 'SanityQuery', 'vacuity': 'VacuityQuery', 'disjointness': 'DisjointnessQuery',
        'emptiness': 'EmptinessQuery', 'redundancy': 'RedundancyQuery', 'allCaptured': 'AllCapturedQuery',
        'connectivityMap': 'ConnectivityMapQuery'}

    TwoConfigsQueryMap = {
        'equivalence': 'SemanticEquivalenceQuery', 'strongEquivalence': 'StrongEquivalenceQuery',
        'semanticDiff': 'SemanticDiffQuery', 'containment': 'ContainmentQuery', 'interferes': 'InterferesQuery',
        'pairwiseInterferes': 'InterferesQuery', 'twoWayContainment': 'TwoWayContainmentQuery',
        'forbids': 'IntersectsQuery', 'permits': 'PermitsQuery'}

    def __init__(self, key_name, configs_array, output_configuration, network_configs=None):
        self.query_name = key_name
        self.configs_array = configs_array
        self.output_configuration = output_configuration
        self.network_configs = network_configs

    def _get_config(self, config_name):
        """
        :param str config_name: The name of a previously defined config or a policy within a previously defined config
        :return: A NetworkConfig object for the requested config
        :rtype: NetworkConfig
        """
        if isinstance(config_name, NetworkConfig):
            return config_name
        if '/' not in config_name:  # plain config name
            if config_name not in self.network_configs:
                raise Exception(f'NetworkPolicyList {config_name} is undefined')
            return self.network_configs[config_name]

        # User wants a specific policy from the given config. config_name has the form <config>/<namespace>/<policy>
        split_config = config_name.split('/', 1)
        config_name = split_config[0]
        policy_name = split_config[1]
        if config_name not in self.network_configs:
            raise Exception(f'NetworkPolicyList {config_name} is undefined')
        return self.network_configs[config_name].clone_with_just_one_policy(policy_name)

    def run_query(self):
        res = 0
        q_output = ''
        formats = None
        if self.query_name in self.OneConfigQueryMap:
            if self.query_name == 'connectivityMap':
                formats = NetworkConfigQuery.ConnectivityMapQuery.supported_output_formats
            for config in self.configs_array:
                query_res, query_output = self.execute_one_config_query(self.OneConfigQueryMap[self.query_name],
                                                                        self._get_config(config))
                res += query_res
                q_output += query_output + '\n'

        elif self.query_name in self.TwoConfigsQueryMap:
            if len(self.configs_array) <= 1:
                return 0
            if self.query_name in {'permits', 'forbids', 'interferes', 'containment'}:
                base_config = self._get_config(self.configs_array[0])
                for config in self.configs_array[1:]:
                    query_res, query_output = self.execute_pair_configs_query(
                        self.TwoConfigsQueryMap[self.query_name], self._get_config(config), base_config)
                    res += query_res
                    q_output += query_output + '\n'
            elif self.query_name in {'equivalence', 'strongEquivalence', 'semanticDiff', 'twoWayContainment'}:
                if self.query_name == 'semanticDiff':
                    formats = NetworkConfigQuery.SemanticDiffQuery.supported_output_formats
                for ind1 in range(len(self.configs_array) - 1):
                    config1 = self.configs_array[ind1]
                    for ind2 in range(ind1 + 1, len(self.configs_array)):
                        query_res, query_output = self.execute_pair_configs_query(
                            self.TwoConfigsQueryMap[self.query_name],
                            self._get_config(config1), self._get_config(self.configs_array[ind2]))
                        res += query_res
                        q_output += query_output + '\n'
            else:  # pairWiseInterferes
                for config1 in self.configs_array:
                    for config2 in self.configs_array:
                        if config1 != config2:
                            query_res, query_output = self.execute_pair_configs_query(
                                self.TwoConfigsQueryMap[self.query_name],
                                self._get_config(config1), self._get_config(config2))
                            res += query_res
                            q_output += query_output + '\n'

        q_output += '\n'
        self.output_configuration.print_query_output(q_output, formats)
        return res

    def execute_one_config_query(self, query_type, config):
        if query_type == "ConnectivityMapQuery":
            self.output_configuration.configName = config.name
        full_result = getattr(NetworkConfigQuery, query_type)(config, self.output_configuration).exec()
        res = full_result.numerical_result
        query_output = full_result.output_result
        if query_type in {'SanityQuery', 'DisjointnessQuery', 'AllCapturedQuery'} and not full_result.bool_result:
            query_output += full_result.output_explanation
        elif query_type in {'RedundancyQuery', 'EmptinessQuery', 'ConnectivityMapQuery'} and full_result.bool_result:
            query_output = full_result.output_explanation
        return res, query_output

    def execute_pair_configs_query(self, query_type, config1, config2):
        full_result = getattr(NetworkConfigQuery, query_type)(config1, config2, self.output_configuration).exec()
        res = 0
        query_output = full_result.output_result
        if query_type in {'SemanticEquivalenceQuery', 'StrongEquivalenceQuery'}:
            res = not full_result.bool_result
            if not full_result.bool_result:
                query_output += full_result.output_explanation
        elif query_type in {'ContainmentQuery', 'TwoWayContainmentQuery'}:
            res = full_result.numerical_result
            query_output += full_result.output_explanation
        elif query_type == 'InterferesQuery':
            res = full_result.bool_result
            if full_result.bool_result:
                query_output += full_result.output_explanation
        elif query_type == 'SemanticDiffQuery':
            res = full_result.numerical_result
            query_output = ''
            if self.output_configuration.outputFormat == 'txt':
                query_output = full_result.output_result
            if not full_result.bool_result:
                query_output += full_result.output_explanation
        elif query_type == 'PermitsQuery':
            res = 0
            if full_result.bool_result:
                query_output = config2.name + ' permits all connections specified in ' + config1.name
            if not full_result.bool_result and full_result.output_explanation:
                res = 1
                query_output = (config2.name + ' does not permit connections specified in ' + config1.name + ':')
                query_output += full_result.output_explanation
        else:  # forbids
            res = full_result.bool_result
            if full_result.bool_result:
                query_output = config2.name + ' does not forbid connections specified in ' + config1.name + ':'
                query_output += full_result.output_explanation
            else:
                query_output = config2.name + ' forbids connections specified in ' + config1.name
        return res, query_output

