[![.github/workflows/test-push.yml](https://github.com/IBM/network-config-analyzer/actions/workflows/test-push.yml/badge.svg)](https://github.com/IBM/network-config-analyzer/actions/workflows/test-push.yml)
[![.github/workflows/codeql-analysis.yml](https://github.com/IBM/network-config-analyzer/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/IBM/network-config-analyzer/actions/workflows/codeql-analysis.yml)
# Network Config Analyzer
An analyzer for Network Policies and other connectivity-configuration resources

---

## Usage (requires Python 3.8 or above)
`python nca.py [--scheme <scheme_file>]`

where *scheme_file* is a yaml file describing what to verify.

Scheme file structure is specified [here](docs/SchemeFileFormat.md).
See an example scheme file [here](tests/k8s_testcases/example_policies/testcase1/testcase1-scheme.yaml).

#### Running without a scheme file
Various predefined queries can be performed without providing a scheme file, using the following command line configurations.
Note: The <Networkpolicy set> in the following lines, can be provided instead within the --resource_list switch.
- `--sanity [<NetworkPolicy set>]` \
Running several sanity checks on the given set of NetworkPolicies
- `--equiv [<NetworkPolicy set> --base_np_list <NetworkPolicy set>]`\
Semantically comparing two sets of NetworkPolicy sets to decide whether they allow exactly the same traffic
- `--interferes [<NetworkPolicy set> --base_np_list <NetworkPolicy set>]`\
Checking whether the given set of NetworkPolicies interferes with the base set of NetworkPolicies 
(allows more traffic between relevant endpoints)
- `--permits [<NetworkPolicy set> --base_np_list <NetworkPolicy set>]`\
Checking whether the base set of NetworkPolicies permits the traffic explicitly specified in the given set of NetworkPolicies
- `--forbids [<NetworkPolicy set> --base_np_list <NetworkPolicy set>]`\
Checking whether the base set of NetworkPolicies forbids the traffic explicitly specified in the given set of NetworkPolicies
- `--connectivity [<NetworkPolicy set>]` \
Get the list of allowed connections as firewall rules on the given set of NetworkPolicies
- `--semantic_diff [<NetworkPolicy set> --base_np_list <NetworkPolicy set>]`\
Get the connectivity semantic difference as firewall rules between two sets of NetworkPolicy sets

`<NetworkPolicy set>` should be one of:
- a path to a yaml/json file defining NetworkPolicies
- a path to a directory with files containing NetworkPolicies
- a url of a GHE repository/dir/file with NetworkPolicies
- The string `k8s`, instructing the tool to take all NetworkPolicies from a Kubernetes cluster (using `kubectl`)
- The string `calico`, instructing the tool to take all NetworkPolicies from a Calico cluster (using `calicoctl`)
- The string `istio`, instructing the tool to take all AuthorizationPolicies from a Kubernetes cluster (using `kubectl`)

Running with no command-line options at all is like running `nca.py --sanity k8s`.

#### Additional command-line switches:
- `--base_np_list <path to file or 'k8s'>`\
  The set of NetworkPolicies to compare against in `--equiv`, `--interferes`,`--permits`, `--forbids` and `--semantic_diff`  \
  *default:* The result of `kubectl get netpol -A`\
  *shorthand:* `-b`
- `--ns_list <path to file or 'k8s'>`\
  Allows specifying files to take the list of namespaces from\
  *default:* the result of `kubectl get ns`\
  *shorthand:* `-n`
- `--pod_list <path to a file, 'calico' or 'k8s'>`\
  Specifies where to take the list of pods/endpoints from\
  *default:* the result of `kubectl get pods -A`\
  *shorthand*: `-p`
- `--resource_list <a networkpolicy path from the list above or path to file or 'k8s'>`\
  Allows specifying paths to take lists of namespaces, pods and NetworkPolicies from\
  *shorthand:* `-r`

- `--base_ns_list <path to file or 'k8s'>`\
  Specifies files with list of namespaces to compare against in `--semantic_diff`
- `--base_pod_list  <path to a file, 'calico' or 'k8s'>`\
  Specifies files with list of pods/endpoints to compare against in `--semantic_diff`
- `--base_resource_list <a networkpolicy path from the list above or path to file or 'k8s'>`\
  Specifies paths with list of lists of namespaces, pods and NetworkPolicies to compare against in `--semantic_diff`
- `--ghe_token <token>`\
  A valid token to access a GHE repository
- `--period <minutes>`\
  Run NCA with given arguments every specified number of minutes
- `--daemon`\
  Run NCA as a daemon. Send and receive data using a REST API.
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
   Write output as GitHub PR comment. URL points to the relevant comments resource in the GitHub API.\
   e.g., https://api.github.com/repos/shift-left-netconfig/online-boutique/issues/1/comments
- `--output_endpoints`\
  Choose endpoints type in output (pods/deployments).\
  *default:* deployments

#### Exit Code Meaning:
The exit value of running a command-line without a scheme is combined from two factors:
1. The result of running the query (0/1) as specified [here](docs/CmdLineQueriesResults.md)
2. The result of comparing the query output with the expected output file contents (if given)

And it can be in the range 0 to 3 as followed:
  - 0 : query result is 0, output comparison passed.
  - 1 : query result is 1, output comparison passed.
  - 2 : query result is 0, output comparison failed.
  - 3 : query result is 1, output comparison failed.
## Installation
```commandline
git clone https://github.com/IBM/network-config-analyzer.git
cd network-config-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

python network-config-analyzer/nca.py -h
```

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
