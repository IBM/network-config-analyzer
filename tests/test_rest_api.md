```commandline
python nca.py --daemon &
cd tests/example_podlist
curl -X POST -H "Content-Type: application/json" -d @ns_list.json localhost:5000/namespace_list
curl -X POST -H "Content-Type: application/json" -d @pods_list.json localhost:5000/pod_list
cd ../example_policies/testcase1
curl -X POST -H "Content-Type: application/json" -d @testcase1-networkpolicy1.json localhost:5000/policy_sets
curl localhost:5000/policy_sets/set_0/findings
```

The result should look like:
```json
{"name":"set_0","policies":{"default/allow-agent-to-analyzer-via-ingress":["NetworkPolicy default/allow-agent-to-analyzer-via-ingress is redundant: it is contained in NetworkPolicy default/allow-egress-deny-ingress-within-namespace\n"],"default/allow-egress-deny-ingress-within-namespace":[]},"profiles":{}}
```
