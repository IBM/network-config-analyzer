# Network Config Analyzer
An analyzer for Network Policies and other connectivity-configuration resources

---

## Usage (requires Python 3.7 or above)
`python nca.py [--scheme <scheme_file>]`

where *scheme_file* is a yaml file describing what to verify.

Scheme file structure is specified [here](docs/SchemeFileFormat.md).
See an example scheme file [here](tests/example_policies/testcase1/testcase1-scheme.yaml).

#### Running without a scheme file
Various predefined queries can be performed without providing a scheme file, using the following command line configurations.
- `--sanity <NetworkPolicy set>` \
Running several sanity checks on the given set of NetworkPolicies
- `--equiv <NetworkPolicy set> [--base_np_list <NetworkPolicy set>]`\
Semantically comparing two sets of NetworkPolicy sets to decide whether they allow exactly the same traffic
- `--interferes <NetworkPolicy set> [--base_np_list <NetworkPolicy set>]`\
Checking whether the base set of NetworkPolicies interferes with the given set of NetworkPolicies
(allows more traffic between relevant endpoints)
- `--permits <NetworkPolicy set> [--base_np_list <NetworkPolicy set>]`\
Checking whether the base set of NetworkPolicies permits the traffic explicitly specified in the given set of NetworkPolicies
- `--forbids <NetworkPolicy set> [--base_np_list <NetworkPolicy set>]`\
Checking whether the base set of NetworkPolicies forbids the traffic explicitly specified in the given set of NetworkPolicies

`<NetworkPolicy set>` should be one of:
- a path to a yaml/json file defining NetworkPolicies
- a path to a directory with files containing NetworkPolicies
- a url of a GHE repository/dir/file with NetworkPolicies
- The string `k8s`, instructing the tool to take all NetworkPolicies from a Kubernetes cluster (using `kubectl`)
- The string `calico`, instructing the tool to take all NetworkPolicies from a Calico cluster (using `calicoctl`)

Running with no command-line options at all is like running `nca.py --sanity k8s`.

#### Additional command-line switches:
- `--base_np_list <path to file or 'k8s'>`\
  The set of NetworkPolicies to compare against in `--equiv` and `--interferes`\
  *default:* The result of `kubectl get netpol -A`\
  *shorthand:* `-b`
- `--ns_list <path to file or 'k8s'>`\
  Allows specifying a file to take the list of namespaces from\
  *default:* the result of `kubectl get ns`\
  *shorthand:* `-n`
- `--pod_list <path to a file, 'calico' or 'k8s'>`\
  Specifies where to take the list of pods/endpoints from\
  *default:* the result of `kubectl get pods -A`\
  *shorthand*: `-p`
- `--ghe_token <token>`\
  A valid token to access a GHE repository
- `--period <minutes>`\
  Run NCA with given arguments every specified number of minutes
- `--daemon`\
  Run NCA as a daemon. Send and receive data using a REST API.
- `--output_format <format>`\
  Output format specification (txt/yaml/csv).\
  *default:* txt\
  *shorthand:* `-o`
- `--file_out <file name>`\
  A file path to redirect output into.\
  *shorthand* `-f`

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
