## Queries Patterns
### CmdLine Queries:
#### Queries with one config (sanity, connectivity)
Patterns describing how to use specific switches (`--<query_name> , ns_list and pod_list`) and general switch (`resource_list`)
1. `--<query_name> <NetworkPolicy set> --ns_list <namespaces path> --pod_list <pods path>` [see example here](../tests/k8s_cmdline_tests.yaml#L1-L8)
2. `--<query_name> <NetworkPolicy set> --resource_list <namespaces and pods path>` [see example here](../tests/k8s_cmdline_tests.yaml#L232-L237) 
3. `--<query_name> --resource_list <networkPolicies, namespaces and pods paths>` [see example here](../tests/k8s_cmdline_tests.yaml#L239-L245) 
#### Queries with two configs (equiv, interferes, permits, forbids, semantic_diff)
Patterns describing how to combine specific switches (global: `--<query_name> , ns_list and pod_list`, base:`base_np_list, base_ns_list and base_pod_list`), and general switches (global: `resource_list`, base: `base_resource_list`)
1. `--<query_name> <NetworkPolicy set> --base_np_list <NetworkPolicy set> --ns_list <namespaces path> --base_ns_list <namespaces path> --pod_list <pods path> --base_pod_list <pods path>` [see example here](../tests/k8s_cmdline_tests.yaml#L88-L97) 
2. Using general base switch to specify base topology paths, may be used with any combination of the global switches [above](#queries-with-one-config)\
`--<query_name> --resource_list <networkPolicies, namespaces and pods paths> --base_np_list <NetworkPolicy set> --base_resource_list <namespaces and pods path>` [see example here](../tests/k8s_cmdline_tests.yaml#L274-L282)
3. Using general base switch to specify all base resources, may be used with any combination of the global switches [above](#queries-with-one-config)\
`--<query_name> --resource_list <networkPolicies, namespaces and pods paths> --base_resource_list <networkpolicies, namespaces and pods path>` [see example here](../tests/k8s_cmdline_tests.yaml#L293-L302)

Handling missing resources and loading resources from live cluster:
- for global and base configs, if networkPolicies paths are missing (i.e. the specific switch is not used and global switch does not refer to any policy), policies will be loaded from k8s live cluster
- If global pods paths are missing (i.e. the specific switch is not used and global switch does not refer to any pod), pods will be loaded from k8s live cluster
- If base pods are missing, global pods will be used 
- If namespaces paths are missing:
    - if there are pods, the namespaces set will contain the pods' namespaces
    - else global namespaces will be used if existed, otherwise, namespaces will be loaded from k8s live cluster
- If any of the specific switches is specified, it overrides the relevant paths in the argument of the general switch.
    
### Scheme File Patterns:
#### The patterns of the globally-scoped topology paths
1. `namespaceList: [list of namespaces paths]`\
`podList: [list of pods paths]` [see example here](../tests/k8s_testcases/example_policies/demo_short/demo2-scheme.yaml#L1-L2)
2. `resourceList: [list of namespaces and pods paths]` [see example here ](../tests/k8s_testcases/example_policies/demo_short/demo1-topology-resourcelist-scheme.yaml#L1-L3)
#### The patterns of the NetworkConfig objects
1. `networkConfigList:`\
  `- name: <config_name>`\
    `networkPolicyList: [list of networkPolicies paths]`\
    `namespaceList: [list of namespaces paths]`\
    `podList: [list of pods paths]` [see example here](../tests/k8s_testcases/example_policies/tests-different-topologies/semanticDiff-different-topologies-scheme.yaml#L17-L22)
2. `networkConfigList:`\
  `- name: <config_name>`\
    `networkPolicyList: [list of networkPolicies paths]`\
    `resourceList: [list of namespaces and pods paths]`[see example here](../tests/k8s_testcases/example_policies/testcase10-nameSpace-podSelector/testcase10-all-resources-in-one-key-scheme.yaml#L5-L11)
3. `networkConfigList:`\
  `- name: <config_name>`\
    `resourceList: [list of networkPolicies, namespaces and pods paths]` [see example here ](../tests/k8s_testcases/example_policies/resourcelist-one-path-example/resource-path-scheme.yaml#L3-L7)

Handling missing resources and loading resources from live cluster:
- If `networkPolicyList` is not used and `resourceList` does not refer to any policy, policies will be loaded from k8s live cluster
- If global pods are missing (i.e. `podList` is not used and `resourceList` does not refer to any pod), pods will be loaded from k8s live cluster
- If config's pods are missing, global pods will be used
- If namespaces are missing,
  - if there are pods, namespaces set will contain the pods' namespaces
  - otherwise, global namespaces will be used if existed or will be loaded from k8s live cluster if not
- If any specific key is specified it will override the relevant contents in resourceList


