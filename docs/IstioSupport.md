## Istio Authorization Policy and Other Traffic Resource analysis

For Istio Authorization Policy (see [Istio Authorization Policy spec](https://istio.io/latest/docs/reference/config/security/authorization-policy/)), 
the following is supported:

| Field     | Supported Fields                                                            |
|-----------|-----------------------------------------------------------------------------|
| selector  | WorkloadSelector                                                            |
| action    | ALLOW, DENY                                                                 |
| source    | principals, notPrincipals, namespaces, notNamespaces, ipBlocks, notIpBlocks |
| operation | hosts, notHosts, ports, notPorts, methods, notMethods, paths, notPaths      |
| condition | source.ip, source.namespace, source.principal, destination.port             |

For [Istio Traffic Management](https://istio.io/latest/docs/concepts/traffic-management/), 
VirtualServices, Gateways and Sidecars are supported. 

In the [VirtualService](https://istio.io/latest/docs/reference/config/networking/virtual-service/#VirtualService), the following is supported:

| Field    | Supported (Sub)-Fields               | Supported (Sub)-Fields |
|----------|--------------------------------------|------------------------|
| hosts    | string                               |                        |
| gateways | string                               |                        |
| http     | match                                | route                  |
|          | uri, ignoreUriCase, method, gateways | destination            |
|          |                                      | host, port             |
| tls      | match                                | route                  |
|          | sniHosts, gateways                   | destination            |
|          |                                      | host, port             |
| tcp      | match                                | route                  |
|          | gateways                             | destination            |
|          |                                      | host, port             |

In the [Gateway](https://istio.io/latest/docs/reference/config/networking/gateway/#Gateway), the following is supported:

| Field    | Supported (Sub)-Fields  | Supported (Sub)-Fields |      |
|----------|-------------------------|------------------------|------|
| selector | string:string           |                        |      |
| servers  | port                    | hosts                  | name |
|          | number, protocol, name  |                        |      |

Internal policies, having a style of network policies, are generated from the parsed Gateways and VirtualServices.
These policies model the connectivity logic as defined by the combination of the gateways and the virtual services.

In the [Sidecar](https://istio.io/latest/docs/reference/config/networking/sidecar/#Sidecar), the following is supported:

| Field                 | Supported (Sub)-Fields | 
|-----------------------|------------------------|
| workloadSelector      | labels                 |
| egress                | hosts                  |
| outboundTrafficPolicy | mode                   |

In the [ServiceEntry](https://istio.io/latest/docs/reference/config/networking/service-entry/#ServiceEntry), the following is supported:

| Field      | Supported (Sub)-Fields | Supported Values           |
|------------|------------------------|----------------------------|
| hosts      |                        |                            |
| location   |                        | MESH_EXTERNAL              |