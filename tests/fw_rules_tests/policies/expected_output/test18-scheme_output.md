|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|connectivity_map, config: np18||||||
|||ip block: 0.0.0.0/0|[kube-system-new]|[*]|All connections|
||[kube-system-new]|[!has(tier) or tier in (not_frontend_for_demo)]||ip block: 0.0.0.0/0|All connections|
||[kube-system-new]|[!has(tier) or tier in (not_frontend_for_demo)]|[kube-system-new]|[*]|All connections|
||[kube-system-new]|[tier in (frontend)]||ip block: 49.50.0.0/32|All connections|
||[kube-system-new]|[tier in (frontend)]||ip block: 49.50.0.2/32|All connections|


