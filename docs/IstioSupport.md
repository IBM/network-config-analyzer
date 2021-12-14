## Istio Authorization Policy analysis

For Istio Authorization Policy (see [Istio Authorization Policy spec](https://istio.io/latest/docs/reference/config/security/authorization-policy/)), 
the following is supported:

| Field | Supported Fields |
|-------|-------------|
|selector| WorkloadSelector |
|action| ALLOW, DENY|
|source| principals, notPrincipals, namespaces, notNamespaces, ipBlocks, notIpBlocks|
|operation| hosts, notHosts, ports, notPorts, methods, notMethods, paths, notPaths|
|condition| source.ip, source.namespace, source.principal, destination.port|