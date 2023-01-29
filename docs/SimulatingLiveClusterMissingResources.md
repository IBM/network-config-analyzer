## Simulating live cluster missing resources:
- There are several key elements that may be assumed to exist in the live cluster and be missing form the topology configurations in the repo.
At those case, nca will add complementary configurations to make the topology and the connectivity whole. 
- Fine-tune of the configurations can be made in dedicated yaml files.

| Missing Element        | Element name when added to the topology                                       |
|------------------------|-------------------------------------------------------------------------------|
| kube-dns               | [kube-dns-livesim](../nca/NetworkConfig/LiveSim/dns)                          |
| ingress controller     | [ingress-controller-livesim](../nca/NetworkConfig/LiveSim/ingress_controller) |
| Istio ingress gateway  | [istio-ingressgateway-livesim](../nca/NetworkConfig/LiveSim/istio_gateway)    |
