# Network Config Analyzer (NCA)
[![.github/workflows/test-push.yml](https://github.com/IBM/network-config-analyzer/actions/workflows/test-push.yml/badge.svg)](https://github.com/IBM/network-config-analyzer/actions/workflows/test-push.yml)
[![.github/workflows/codeql-analysis.yml](https://github.com/IBM/network-config-analyzer/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/IBM/network-config-analyzer/actions/workflows/codeql-analysis.yml)
---
## What is NCA?
NCA is a tool for analyzing Network Policies and other connectivity-configuration resources.
It takes such resources as input, in addition to a list of relevant endpoints, and provides answers to queries such as:
- What is my current connectivity posture?
- How is my connectivity posture changing?
- Is specific traffic allowed/denied?
- What are the endpoints that are not covered by any policy?
- Are my policies implemented efficiently?

## Installation (requires Python 3.8 or above)
For command-line use, NCA is installed with:
```shell
pip install network-config-analyzer
```
NCA can also be consumed as a [Docker container][Docker package],
[GitHub Action][NCA GitHub Action]
or [Tekton Tasks][NCA Tekton Tasks].

## Usage 
Basic NCA command-line usage:
```shell
nca <query> [--resource_list <resource_list>] [--base_resource_list <base_resource_list>]
```
For example:
```shell
nca --connectivity --resource_list k8s  # Read policies and endpoints from a live Kubernetes cluster and report connectivity
# OR
nca --semantic_diff -r istio --base_resource_list ./old_config  # Compare two istio connectivity configs  
```

The full list of queries is:
- `--sanity` - Running several sanity checks on the given set of NetworkPolicies
- `--connectivity` - Get the list of allowed connections (as firewall rules or as a graph) as implied by the given set of NetworkPolicies
- `--semantic_diff` - Get the semantic connectivity difference (as firewall rules) between two sets of NetworkPolicy sets
- `--equiv` - Semantically comparing two sets of NetworkPolicy sets to decide whether they allow exactly the same traffic
- `--interferes` - Checking whether the given set of NetworkPolicies interferes with the base set of NetworkPolicies 
(allows more traffic between relevant endpoints)
- `--permits` - Checking whether the **base** set of NetworkPolicies permits the traffic explicitly specified in the given set of NetworkPolicies
- `--forbids` - Checking whether the **base** set of NetworkPolicies forbids the traffic explicitly specified in the given set of NetworkPolicies

The arguments to `--resource_list` and to `--base_resource_list` should be one of:
- a path to a yaml/json file defining NetworkPolicies and/or endpoints
- a path to a directory with files containing NetworkPolicies and/or endpoints
- a URL of a GitHub repository/dir/file with NetworkPolicies and/or endpoints
- The string `k8s`, instructing the tool to take all NetworkPolicies and endpoints from a Kubernetes cluster (using `kubectl`)
- The string `calico`, instructing the tool to take all NetworkPolicies and endpoints from a Kubernetes cluster with Calico (using `calicoctl`)
- The string `istio`, instructing the tool to take all AuthorizationPolicies and endpoints from a Kubernetes cluster with Istio (using `kubectl`)

#### Additional command-line switches:
- `--resource_list <an argument from the list above>`\
  Specifies where to take namespaces, endpoints and NetworkPolicies from. This switch may be specified multiple times\
  *shorthand:* `-r`
- `--ns_list <an argument from the list above>`\
  Specifies where to take the list of namespaces from (and ignoring namespaces found by `--resource_list`). This switch may be specified multiple times\
  *default:* the result of `kubectl get ns`\
  *shorthand:* `-n`
- `--pod_list <an argument from the list above>`\
  Specifies where to take the list of pods/endpoints from (and ignoring those found by `--resource_list`). This switch may be specified multiple times\
  *default:* the result of `kubectl get pods -A`\
  *shorthand*: `-p`
- `--base_resource_list <an argument from the list above>`\
  Specifies where to take namespaces, endpoints and NetworkPolicies to compare against. This switch may be specified multiple times
- `--base_np_list <an argument from the list above>`\
  The set of NetworkPolicies to compare against. Using this switch will ignore NetworkPolicies found by `--base_resource_list` \
  *default:* The result of `kubectl get netpol -A`\
  *shorthand:* `-b`
- `--base_ns_list <an argument from the list above>`\
  Specifies files with list of namespaces to compare against (and ignoring those found by `--base_resource_list`). This switch may be specified multiple times
- `--base_pod_list  <an argument from the list above>`\
  Specifies files with list of pods/endpoints to compare against (and ignoring those found by `--base_resource_list`). This switch may be specified multiple times
- `--namespace_subset  <A comma separated list of namespaces (no spaces allowed)>`\
  Specifies the namespaces to be included in the 'connectivity' query results
- `--deployment_subset  <A comma separated list of deployments (no spaces allowed)>`\
  Specifies the deployments to be included in the 'connectivity' query results. Deployments' names can include the namespace prefix followed by the '/' character.
- `--label_subset  <A comma separated list of pairs (key:value) of labels (no spaces allowed)>`\
  Specifies the labels to include in the 'connectivity' query results. An element should include all the labels in this list to be included in the subset and in the results (AND operation). This switch may be specified multiple times and an element will be included if it matches one of the label-sets given in one of the switches (OR operation).
- `--ghe_token <token>`\
  A valid token to access a GHE repository
- `--period <minutes>`\
  Run NCA with given arguments every specified number of minutes
- `--output_format <format>`\
  Output format specification (txt/yaml/csv/md/dot).\
  *default:* txt\
  *shorthand:* `-o`
- `--file_out <file name>`\
  A file path to redirect output into.\
  *shorthand* `-f`
- `--expected_output <file name>`\
  A file path to the expected query output (for connectivity or semantic_diff queries).\
- `--pr_url <URL>`\
   Write output as GitHub PR comment. URL points to the relevant `comments` resource in the GitHub API.\
   e.g., https://api.github.com/repos/shift-left-netconfig/online-boutique/issues/1/comments
- `--output_endpoints`\
  Choose endpoints type in output (pods/deployments).\
  *default:* deployments

For more information on command-line switches combinations, see [Common Query Patterns](docs/CommonQueryPatterns.md#cmdline-queries)

#### Exit Code Meaning:
The exit value of running a command-line without a scheme is the combination of three factors:
1. The result of running the query (0/1) as specified [here](docs/CmdLineQueriesResults.md)
2. The result of comparing the query output with the expected output file contents (if given)
3. The query was not executed because of one of the reasons listed [here](docs/CmdLineQueriesResults.md#a-query-will-not-be-executed-when). If this is true, then other factors are ignored.

And it can be in the range 0 to 7 as followed:
  - 0 : query result is 0, output comparison passed.
  - 1 : query result is 1, output comparison passed.
  - 2 : query result is 0, output comparison failed.
  - 3 : query result is 1, output comparison failed.
  - [4-7] : query was not executed.

### Running with a scheme file
Scheme files allow running NCA on multiple queries in a single command-line, and also for fine-tuning the output.
To run NCAs with a scheme file, use the `--scheme` switch.
```shell
nca --scheme <scheme_file>
```
where `scheme_file` is a yaml file describing what to verify.

Scheme files should follow [this specification](docs/SchemeFileFormat.md).
See an [example scheme file](tests/k8s_testcases/example_policies/testcase1/testcase1-scheme.yaml).

## Supported platforms
* Kubernetes
* Calico
* Istio (see what is supported [here](docs/IstioSupport.md).)

## Contributing

If you have any questions or issues you can create a new [issue here][issues].

Pull requests are very welcome! Make sure your patches are well tested.
Ideally create a topic branch for every separate change you make. For
example:

1. Fork the repo
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Added some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

## License

All source files must include a Copyright and License header. The SPDX license header is 
preferred because it can be easily scanned.

If you would like to see the detailed LICENSE click [here](LICENSE).

```text
#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#
```

[issues]: https://github.com/IBM/network-config-analyzer/issues/new/choose
[Docker package]: https://github.com/IBM/network-config-analyzer/pkgs/container/nca
[NCA GitHub Action]: https://github.com/np-guard/netpol-reports-gh-action
[NCA Tekton Tasks]: https://github.com/IBM/network-config-analyzer/tree/master/tekton