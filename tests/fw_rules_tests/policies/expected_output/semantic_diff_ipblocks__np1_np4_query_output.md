|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|semantic_diff, config1: np1, config2: np4, key: Added connections between persistent peers||||||
||[default,kube-system-dummy-to-ignore,vendor-system]|[*]|[kube-system]|[tier=frontend]|All connections|
||[kube-system]|[!has(tier) or tier=not_frontend_for_demo]|[kube-system]|[tier=frontend]|All connections|
|semantic_diff, config1: np1, config2: np4, key: Removed connections between persistent peers||||||
||[kube-system]|[tier=frontend]|[default,kube-system-dummy-to-ignore,vendor-system]|[*]|All connections|
||[kube-system]|[tier=frontend]|[kube-system]|[!has(tier) or tier=not_frontend_for_demo]|All connections|
|semantic_diff, config1: np1, config2: np4, key: Added connections between persistent peers and ipBlocks||||||
|||0.0.0.0-9.255.255.255|[kube-system]|[tier=frontend]|All but UDP 53|
|||11.0.0.0-172.20.255.255|[kube-system]|[tier=frontend]|All but UDP 53|
|||172.22.0.0-172.29.255.255|[kube-system]|[tier=frontend]|All but UDP 53|
|||172.31.0.0-255.255.255.255|[kube-system]|[tier=frontend]|All but UDP 53|
|||10.0.0.0/8|[kube-system]|[tier=frontend]|All connections|
|||172.21.0.0/16|[kube-system]|[tier=frontend]|All connections|
|||172.30.0.0/16|[kube-system]|[tier=frontend]|All connections|
|semantic_diff, config1: np1, config2: np4, key: Removed connections between persistent peers and ipBlocks||||||
||[kube-system]|[tier=frontend]||0.0.0.0-49.49.255.255|All connections|
||[kube-system]|[tier=frontend]||49.50.0.1/32|All connections|
||[kube-system]|[tier=frontend]||49.50.0.11/32|All connections|
||[kube-system]|[tier=frontend]||49.50.0.13/32|All connections|
||[kube-system]|[tier=frontend]||49.50.0.15/32|All connections|
||[kube-system]|[tier=frontend]||49.50.0.17-255.255.255.255|All connections|
||[kube-system]|[tier=frontend]||49.50.0.3/32|All connections|
||[kube-system]|[tier=frontend]||49.50.0.5/32|All connections|
||[kube-system]|[tier=frontend]||49.50.0.7/32|All connections|
||[kube-system]|[tier=frontend]||49.50.0.9/32|All connections|
