## Scheme file format
A scheme file is a yaml file, specifying what should be checked.
It should contain at least the `networkConfigList` and the `queries` fields.

| Field | Description | Value | Default |
|-------|-------------|-------|---------|
|namespaceList|A globally-scoped list of namespaces in the cluster|directory, git-repo or yaml/json file|Cluster namespaces|
|podList|A globally-scoped list of pods in the cluster|directory, git-repo or yaml/json file|Cluster pods|
|resourceList|A globally-scoped list of namespaces and pods |directory, git-repo or yaml/json file|Specific field (namespaceList/podList) overrides relevant resource, missing resources with the absence of specific field defaults to cluster items|
|networkConfigList|A list of network configurations and policies to reason about|list of [NetworkConfig](#NetworkConfigobject) objects|
|queries|Queries for the tool to run|list of [Query](#queryobject) objects|

### <a name="NetworkConfigobject"></a>NetworkConfig object
Each NetworkConfig object represents a specific network configuration.
It should contain the `name` and at least one of the fields `networkPolicyList`, `resourceList`.\
`resourceList` field may contain entries that refer to namespaces, pods and NetworkPolicies.\
If `networkPolicyList` is not provided and `resourceList` contains no policies, then cluster policies will be loaded


| Field | Description | Value | Default |
|-------|-------------|-------|---------|
|name   |The name of this NetworkConfig|string|
|namespaceList|A specific list of namespaces|directory, git-repo or yaml/json file|global namespaceList|
|podList|A specific list of pods|directory, git-repo or yaml/json file|global podList|
|networkPolicyList|A list of sources for NetworkPolicies|list of sources |
|resourceList|A list of sources for pods, namespaces and NetworkPolicies|list of sources|Specific field (namespaceList/podList/NetworkPolicyList) overrides relevant resource|
|expectedWarnings|The expected sum of returned warnings for all resources of this configuration (an error is issued on mismatch)|integer |
|expectedError|indicates if there is an expected error from a networkPolicy|0/1|

For more information on fields patterns, see [Common Query Patterns](CommonQueryPatterns.md#scheme-file-patterns)

Possible entries (sources) in the list under `networkPolicyList` or `resourceList` are:
* The string `k8s` - Adds all K8s NetworkPolicies in the cluster to the set
* The string `calico` - Adds all Calico NetworkPolicies and Profiles in the cluster to the set
* The string `istio` - Adds all Istio AuthorizationPolicies in the cluster to the set
* A full path to a yaml file containing NetworkPolicies - Adds all policies in the file
* A full path to a directory - Adds all policies in all files in this directory
* A full path to a directory + `/**` - Adds all policies in all files under this directory recursively
* A URL of a file in a GHE repository - Adds all policies in the file
* A URL of a directory in a GHE repository - Adds all policies in all files in this directory
* A URL of a GHE directory + `/**` - Adds all policies in all files under this directory recursively
* A URL of a GHE repository + `/**` - Adds all policies in all files in this repository

###  <a name="queryobject"></a>Query object
Each query object instructs the tool to run a specific check on one or more sets of policies.

| Field | Description | Value |
|-------|-------------|-------|
|name   |Query name|string|
|emptiness|Checks all NetworkConfigs for empty selectors/rules|list of [config set](#configsets) names|
|redundancy|Checks each set of NetworkConfigs for redundant policies and for redundant rules within each policy|list of [config set](#configsets) names|
|equivalence|Checks semantic equivalence between each pair of NetworkConfigs sets|list of [config set](#configsets) names|
|strongEquivalence|Like equivalence, but comparisons are policy-wise|list of [config set](#configsets) names|
|semanticDiff|Checks semantic diff between each pair of NetworkConfigs sets|list of [config set](#configsets) names|
|forbids|Checks whether the first set denies all connections **explicitly** allowed by the other sets|list of [config set](#configsets) names|
|permits|Checks whether the first set allows all connections **explicitly** allowed by the other sets|list of [config set](#configsets) names|
|interferes|Checks whether any set interferes with the first set|list of [config set](#configsets) names|
|pairwiseInterferes|Checks whether any two sets in the list interfere each other|list of [config set](#configsets) names|
|containment|Checks whether any set is semantically contained in the first set (does not allow additional connections)|list of [config set](#configsets) names|
|twoWayContainment|Checks what are the relations - equivalence, contains, contained, disjoint, neither - between the first set and each of the other sets|list of [config set](#configsets) names|
|disjointness|Reports pairs of policies with overlapping sets of captured pods|list of [config set](#configsets) names|
|vacuity|Checks whether the set of policies changes cluster default behavior|list of [config set](#configsets) names|
|sanity|Checks all NetworkConfigs for sanity check - includes emptiness, vacuity and redundancies|list of [config set](#configsets) names|
|allCaptured|Checks that all pods are captured by at least one NetworkPolicy|list of [config set](#configsets) names|
|connectivityMap|Reports a summary of the allowed connections in the cluster|list of [config set](#configsets) names| 
|expected|The expected sum of returned results by all sub-queries in this query (a warning is issued on mismatch)|integer|
|expectedOutput|The file path of the expected output of this query (for connectivityMap or semanticDiff queries) |string|
|expectedNotExecuted|The number of input configs/config pairs that the query is not expected to be run on. Reasons for not executing the configs are listed [here](CmdLineQueriesResults.md#a-query-will-not-be-executed-when) |integer|
|outputConfiguration| A dict object with the required output configuration|[outputConfig](#outputconfig) object|

#### <a name="configsets"></a>Config sets
Each entry in the list of config sets should be either
* __Full set__ - The name of a [NetworkConfig object](#NetworkConfigobject) _OR_
* __Single policy__ - Use one of the forms: `<set name>/<namespace>/<policy>` or `<set name>/<kind>/<namespace>/<policy>`, where `kind` is one of: `K8sNetworkPolicy`, `CalicoNetworkPolicy`, `CalicoGlobalNetworkPolicy`, `IstioAuthorizationPolicy` or `K8sIngress`.
For example: `my_set/prod_ns/deny_all_policy`. If there are multiple policies named `deny_all_policy` in the namespace `prod_ns` on different layers, then specifying a single policy should include its layer, such as `my_set/K8sNetworkPolicy/prod_ns/deny_all_policy`. 


#### <a name="outputconfig"></a>Output Configuration object
The supported entries in the outputConfiguration object are as follows:

| Field           | Description                                                             | Value                                  |
|-----------------|-------------------------------------------------------------------------|----------------------------------------|
| outputFormat    | Output format specification.                                            | string [ txt / yaml / csv / md / dot ] |
| outputPath      | A file path to redirect output into.                                    | string                                 |
| outputEndpoints | Choose endpoints type in output.                                        | string [ pods / deployments ]          |
| subset          | A dict object with the defined subset elements to display in the output | [subset](#subset) object               |
| printAllPairs   | Choose if to print all counter peer pairs examples in the output        | bool                                   |

#### <a name="subset"></a>Subset object
The supported entries in the subset object are as follows:

| Field | Description                                                                                                                                                                                                      | Value                                                                                      |
|-------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
|namespace_subset| A comma separated list of namespaces (no spaces allowed)                                                                                                                                                         | string                                                                                     |
|deployment_subset| A comma separated list of deployments (no spaces allowed). Deployment can be specific for a namespace and have the namespace prefix following by the '/' character.                                              | string                                                                                     |
|label_subset| Blocks of pairs key:value, each pair per line. Each block of labels (pairs) starts with the '-' character. Labels within a block implement a logical AND between them, while between blocks there is a logical OR| - key:value pair, starting each block. key:value pair, per line, at the rest of each block |


#### Returned value for each sub-query:
* _emptiness_ -  Count of empty selectors/rules found in all sets of policies
* _redundancy_ - Count of redundant policies/rules found in all sets of policies
* _equivalence_ - Count of non-equivalent comparisons
* _strongEquivalence_ - Count of non-equivalent comparisons
* _semanticDiff_ - Count of categories with changed connections
* _forbids_ - Count of sets explicitly specifying connections which the first set allows
* _permits_ - Count of sets explicitly specifying connections which the first set denies
* _interferes_ - Count of sets interfering with the first set
* _pairwiseInterference_ - Count of pairs of interfering sets
* _containment_ - Count of sets contained in the first set
* _disjointness_ - Count of policy pairs in each set with overlapping captured pods
* _vacuity_ - Count of vacuous sets
* _sanity_ - Count of sanity issues
* _allCaptured_ - Count of non-captured pods
* _connectivityMap_ - 0

#### Exit code meaning :
The exit code of running a scheme-file queries is the count of:
* NetworkConfigs with mismatching number of expectedWarnings (only networkConfigs that run in queries are counted)
* NetworkConfigs with mismatching number of expectedError (only networkConfigs that run in queries are counted)
* Queries that their result did not match the given expected result 
* Queries that their output did not match the given expected output file contents.
* Queries that were not executed differently than as much expected.