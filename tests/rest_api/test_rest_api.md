```
python network-config-analyzer/nca.py --daemon &
curl -X POST -H "Content-Type: application/json" -d @tests/k8s_testcases/example_podlist/ns_list.json localhost:5000/namespace_list
curl -X POST -H "Content-Type: application/json" -d @tests/k8s_testcases/example_podlist/pods_list.json localhost:5000/pod_list
curl -X POST -H "Content-Type: application/json" -d @tests/k8s_testcases/example_policies/testcase1/testcase1-networkpolicy1.json localhost:5000/policy_sets
curl localhost:5000/policy_sets/set_0/findings
```

The result should look like:
```json
{"name":"set_0","policies":{"default/allow-agent-to-analyzer-via-ingress":["NetworkPolicy set_0/default/allow-agent-to-analyzer-via-ingress is redundant: it is contained in NetworkPolicy set_0/default/allow-egress-deny-ingress-within-namespace\n"],"default/allow-egress-deny-ingress-within-namespace":[]},"profiles":{}}
```
