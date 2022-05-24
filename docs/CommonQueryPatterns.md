## Queries Patterns
Following are desired patterns involving all resources paths switches
### CmdLine Queries:
#### Queries with one config
1. Old version, not using `resource_list` switch\
`--<query_name> <NetworkPolicy set>`\
`--ns_list <namespaces path> ` - this field may be specified multiple times (appends values)\
`--pod_list <pods path>` - this field may be specified multiple times (appends values)
2. Using resource_list switch to specify topology paths (namespaces and pods)\
`--<query_name> <NetworkPolicy set>`\
`--resource_list <namespaces and pods path> ` - this field may be specified multiple times (appends values)
3. Using resource_list switch to specify all resources paths (NetworkPolicy, namespaces and pods)\
`--<query_name>`\
`--resource_list <networkPolicies, namespaces and pods paths> ` - this field may be specified multiple times (appends values)

Notes regarding [cmdline one config queries](#queries-with-one-config):
- If any of the specific switches of `--<query_name>, --ns_list and --pod_list` is specified, it overrides the relevant paths in the argument of `--resource_list` (if it exists too)
- If networkPolicy paths are missing (neither provided by the `<query_name>` switch nor `resource_list` refers to any policy), policies will be loaded from k8s live cluster
- If pods paths are missing (`--pod_list` is not used and no pods are found in `resource_list` paths), pods will be loaded from k8s live cluster
- If namespaces paths are missing:
    - if there are pods, the namespaces set will contain the pods' namespaces
    - otherwise, namespaces will be loaded from k8s live cluster 

#### Queries with two configs
1. Old version, not using `resource_list` and `base_resource_list` switches\
`--<query_name> <NetworkPolicy set>`\
`--base_np_list <NetworkPolicy set>`\
`--ns_list <namespaces path> ` - this field may be specified multiple times (appends values)\
`--base_ns_list <namespaces path>` - this field may be specified multiple times (appends values)\
`--pod_list <pods path>` - this field may be specified multiple times (appends values)\
`--base_pod_list <pods path>` - this field may be specified multiple times (appends values)
2. Using `base_resource_list` switch to specify base topology paths, may be used with any combination of the other config's switches\
a.\
`--<query_name> <NetworkPolicy set>`\
`--base_np_list <NetworkPolicy set>`\
`--ns_list <namespaces path> ` - this field may be specified multiple times (appends values)\
`--pod_list <pods path>` - this field may be specified multiple times (appends values)\
`--base_resource_list <namespaces and pods path>` - this field may be specified multiple times (appends values)\
b.\
`--<query_name> <NetworkPolicy set>`\
`--base_np_list <NetworkPolicy set>` - this field may be specified multiple times (appends values)\
`--resource_list <namespaces and pods path> ` - this field may be specified multiple times (appends values)\
`--base_resource_list <namespaces and pods path> ` - this field may be specified multiple times (appends values)\
c.\
`--<query_name>`\
`--resource_list <networkPolicies, namespaces and pods paths> ` - this field may be specified multiple times (appends values)\
`--base_np_list <NetworkPolicy set>` - this field may be specified multiple times (appends values)\
`--base_resource_list <namespaces and pods path> ` - this field may be specified multiple times (appends values)
3. Using `base_resource_list` switch to specify all base resources paths, may be used with any combination of the other config's switches\
a.\
`--<query_name> <NetworkPolicy set>`\
`--ns_list <namespaces path> ` - this field may be specified multiple times (appends values)\
`--pod_list <pods path>` - this field may be specified multiple times (appends values)\
`--base_resource_list <networkpolicies, namespaces and pods path> ` - this field may be specified multiple times (appends values)\
b.\
`--<query_name> <NetworkPolicy set>`\
`--resource_list <namespaces and pods path> ` - this field may be specified multiple times (appends values)\
`--base_resource_list <networkpolicies, namespaces and pods path> ` - this field may be specified multiple times (appends values)\
c.\
`--<query_name>`\
`--resource_list <networkPolicies, namespaces and pods paths> ` - this field may be specified multiple times (appends values)\
`--base_resource_list <networkpolicies, namespaces and pods path> ` - this field may be specified multiple times (appends values)

Notes regarding [cmdline two configs queries](#queries-with-two-configs):
- If any of the specific switches of `--base_np_list, --base_ns_list and --base_pod_list` is specified, it overrides the relevant paths in the arguments of `--base_resource_list` (if it exists too)
- If base networkPolicy paths are missing (neither provided by the `base_np_list` switch nor `base_resource_list` refers to any policy), base policies will be loaded from k8s live cluster
- If base pods paths are missing (`--base_pod_list` is not used and no pods are found in `base_resource_list` paths), pods will be used from `pod_list` or `resource_list` or will be loaded from k8s live cluster
- If base namespaces paths are missing:
    - if there are base pods, the namespaces set will contain these pods' namespaces
    - otherwise, namespaces will be taken from `ns_list` or `resource_list` or will be loaded from k8s live cluster 
- Notes under [cmdline one config queries notes](#queries-with-one-config) are relevant to the other config's switches 

Examples of all patterns are found [here](../tests/k8s_cmdline_tests.yaml)

### Scheme File Patterns:
#### The patterns of the globally-scoped topology paths
1. Old version, not using `resourceList` key\
`namespaceList: [list of namespaces paths]`\
`podList: [list of pods paths]`
2. ResourceList is used to refer to all topology paths (namespaces and pods)\
`resourceList: [list of namespaces and pods paths]`\
[click here for an example of this pattern](../tests/k8s_testcases/example_policies/demo_short/demo1-topology-resourcelist-scheme.yaml)

Notes regarding [globally-scoped patterns](#the-patterns-of-the-globally-scoped-topology-paths): 
- If `podList` is not used and no pod paths in `resourceList`, pods will be loaded from k8s live cluster
- If `namespaceList` is not used and `resourceList` contains no namespaces, then:
  - if there are global pods, namespaces set will contain the pods' namespaces
  - otherwise, namespaces will be loaded from k8s live cluster
- If `podList` and `namespaceList` are not used, and `resourceList` does not refer to topology paths or is not used either, pods and namespaces will be loaded from k8s live cluster 
#### The patterns of the NetworkConfig objects
1. Old version, not using `resourceList` key \
`networkConfigList:`\
  `- name: <config_name>`
    `networkPolicyList: [list of networkPolicies paths]`\
    `namespaceList: [list of namespaces paths]`\
    `podList: [list of pods paths]`
2. `resourceList` refers to topology paths\
`networkConfigList:`\
  `- name: <config_name>`
    `networkPolicyList: [list of networkPolicies paths]`\
    `resourceList: [list of namespaces and pods paths]`\
[click here for an example of this pattern](../tests/k8s_testcases/example_policies/testcase10-nameSpace-podSelector/testcase10-all-resources-in-one-key-scheme.yaml)
3. `resourceList` refers to all input resources\
`networkConfigList:`\
  `- name: <config_name>`\
    `resourceList: [list of networkPolicies, namespaces and pods paths]`\
[click here for an example of this pattern](../tests/k8s_testcases/example_policies/resourcelist-one-path-example)

Notes regarding [NetworkConfig objects patterns](#the-patterns-of-the-networkconfig-objects):
- If topology paths are missing (no use of topology switches and resourceList does not refer to topology objects), then the global peers will be used or k8s live cluster peers
- If `networkPolicyList` is not used and `resourceList` does not refer to any policy, policies will be loaded from k8s live cluster
