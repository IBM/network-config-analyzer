|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|semantic_diff, config1: allow_all, config2: poc3, key: Removed connections between persistent peers||||||
||[default]|[*]|[kube-system]|[*]|All but UDP 53|
||[default]|[*]|[default]|[productcatalogservice]|All but TCP 3550|
||[default]|[recommendationservice]|[default]|[*]|All but TCP 3550|
||[default]|[*]|[default]|[app in (paymentservice,shippingservice)]|All but TCP 50051|
||[default]|[*]|[default]|[checkoutservice]|All but TCP 5050|
||[default]|[cartservice]|[default]|[*]|All but TCP 6379|
||[default]|[*]|[default]|[currencyservice]|All but TCP 7000|
||[default]|[*]|[default]|[cartservice]|All but TCP 7070|
||[default]|[*]|[default]|[app in (emailservice,recommendationservice)]|All but TCP 8080|
||[default]|[loadgenerator]|[default]|[*]|All but TCP 8080|
||[kube-system]|[*]|[default]|[*]|All but TCP 8080|
||[default]|[*]|[default]|[adservice]|All but TCP 9555|
||[default]|[*]|[default]|[loadgenerator]|All connections|
||[default]|[*]|[kube-system]|[etcd-operator]|All connections|
||[default]|[app not in (cartservice,checkoutservice,frontend,loadgenerator,recommendationservice)]|[default,kube-system]|[*]|All connections|
||[default]|[cartservice]|[default]|[app not in (cartservice,loadgenerator,redis-cart)]|All connections|
||[default]|[checkoutservice]|[default]|[app in (adservice,frontend,recommendationservice,redis-cart)]|All connections|
||[default]|[frontend]|[default]|[app in (emailservice,paymentservice,redis-cart)]|All connections|
||[default]|[loadgenerator]|[default]|[app not in (frontend,loadgenerator)]|All connections|
||[default]|[recommendationservice]|[default]|[app not in (loadgenerator,productcatalogservice,recommendationservice)]|All connections|
||[kube-system]|[*]|[default]|[app!=frontend]|All connections|
|semantic_diff, config1: allow_all, config2: poc3, key: Removed connections between persistent peers and ipBlocks||||||
|||0.0.0.0/0|[default]|[*]|All but TCP 8080|
|||0.0.0.0/0|[default]|[app!=frontend]|All connections|
||[default]|[*]||0.0.0.0/0|All connections|
