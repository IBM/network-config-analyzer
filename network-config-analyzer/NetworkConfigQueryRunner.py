import NetworkConfigQuery
from NetworkConfig import NetworkConfig


class NetworkConfigQueryRunner:
    """
    A Class for Running Queries
    """

    def __init__(self, key_name, configs_array, output_configuration, network_configs=None):
        self.query_name = f'{key_name[0].upper()+key_name[1:]}Query'
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

    def run_query(self, cmd_line_flag=False):
        """
        runs the query based on the self.query_name
        :param bool cmd_line_flag: indicates if the query arg is given in the cmd-line
        rtype: int
        """
        res = 0
        q_output = ''
        query_to_exec = getattr(NetworkConfigQuery, self.query_name)  # for calling static methods
        formats = query_to_exec.get_supported_output_formats()
        if query_to_exec.get_query_type() == NetworkConfigQuery.QueryType.SingleConfigQuery:
            for config in self.configs_array:
                query_res, query_output = self._execute_one_config_query(self.query_name, self._get_config(config))
                res += query_res
                q_output += query_output + '\n'

        else:
            if len(self.configs_array) <= 1:
                return 0
            if query_to_exec.get_query_type() == NetworkConfigQuery.QueryType.ComparisonToBaseConfigQuery:
                base_config = self._get_config(self.configs_array[0])
                for config in self.configs_array[1:]:
                    query_res, query_output = self._execute_pair_configs_query(
                        self.query_name, self._get_config(config), base_config, cmd_line_flag)
                    res += query_res
                    q_output += query_output + '\n'
            elif query_to_exec.get_query_type() == NetworkConfigQuery.QueryType.PairComparisonQuery:
                for ind1 in range(len(self.configs_array) - 1):
                    config1 = self.configs_array[ind1]
                    for ind2 in range(ind1 + 1, len(self.configs_array)):
                        query_res, query_output = self._execute_pair_configs_query(
                            self.query_name, self._get_config(config1), self._get_config(self.configs_array[ind2]),
                            cmd_line_flag)
                        res += query_res
                        q_output += query_output + '\n'
            else:  # pairWiseInterferes
                for config1 in self.configs_array:
                    for config2 in self.configs_array:
                        if config1 != config2:
                            query_res, query_output = self._execute_pair_configs_query(
                                self.query_name, self._get_config(config1), self._get_config(config2))
                            res += query_res
                            q_output += query_output + '\n'

        self.output_configuration.print_query_output(q_output, formats)
        return res

    def _execute_one_config_query(self, query_type, config):
        query_to_exec = getattr(NetworkConfigQuery, query_type)(config, self.output_configuration)
        return query_to_exec.compute_query_output(query_to_exec.exec())

    def _execute_pair_configs_query(self, query_type, config1, config2, cmd_line_flag=False):
        query_to_exec = getattr(NetworkConfigQuery, query_type)(config1, config2, self.output_configuration)
        return query_to_exec.compute_query_output(query_to_exec.exec(), cmd_line_flag)
