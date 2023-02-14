## Istio Authorization Policy analysis

For Istio Authorization Policy (see [Istio Authorization Policy spec](https://istio.io/latest/docs/reference/config/security/authorization-policy/)), 
the following is supported:

| Field     | Supported Fields                                                            |
|-----------|-----------------------------------------------------------------------------|
| selector  | WorkloadSelector                                                            |
| action    | ALLOW, DENY                                                                 |
| source    | principals, notPrincipals, namespaces, notNamespaces, ipBlocks, notIpBlocks |
| operation | hosts, notHosts, ports, notPorts, methods, notMethods, paths, notPaths      |
| condition | source.ip, source.namespace, source.principal, destination.port             |

For Istio Ingress Traffic Management (see [Istio Traffic Management spec](https://istio.io/latest/docs/concepts/traffic-management/)), 
VirtualServices, Gateways and Sidecars are supported. 

In the VirtualService, the following is supported:

| Field    | Supported (Sub)-Fields     | Supported (Sub)-Fields |
|----------|----------------------------|------------------------|
| hosts    | string                     |                        |
| gateways | string                     |                        |
| http     | match                      | route                  |
|          | uri, ignoreUriCase, method | destination            |
|          |                            | host, port             |

In the Gateway, the following is supported:

| Field    | Supported (Sub)-Fields  | Supported (Sub)-Fields |      |
|----------|-------------------------|------------------------|------|
| selector | string:string           |                        |      |
| servers  | port                    | hosts                  | name |
|          | number, protocol, name  |                        |

In the Sidecar, the following is supported:

| Field                 | Supported (Sub)-Fields | 
|-----------------------|------------------------|
| workloadSelector      | labels                 |
| egress                | hosts                  |
| outboundTrafficPolicy | mode                   |

In the ServiceEntry, the following is suported:

| Field      | Supported (Sub)-Fields | 
|------------|------------------------|
| hosts      |                        |
| location   |                        |
| resolution |                        |
| exportTo   |                        | 