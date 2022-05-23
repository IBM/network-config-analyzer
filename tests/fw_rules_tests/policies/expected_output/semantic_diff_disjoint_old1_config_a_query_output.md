|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|semantic_diff, config1: old1, config2: config_a, key: Lost connections between removed peers||||||
||[default,kube-system,vendor-system]|[*]|[default,kube-system,vendor-system]|[*]|All connections|
|semantic_diff, config1: old1, config2: config_a, key: Lost connections between removed peers and ipBlocks||||||
|||0.0.0.0/0|[default,kube-system,vendor-system]|[*]|All connections|
|||::/0|[default,kube-system,vendor-system]|[*]|All connections|
||[default,kube-system,vendor-system]|[*]||0.0.0.0/0|All connections|
||[default,kube-system,vendor-system]|[*]||::/0|All connections|
|semantic_diff, config1: old1, config2: config_a, key: New connections between added peers||||||
||[default]|[*]|[default]|[app=app-1]|All connections|
||[default]|[app in (app-1,app-2)]|[default]|[*]|All connections|
|semantic_diff, config1: old1, config2: config_a, key: New connections between added peers and ipBlocks||||||
|||0.0.0.0/0|[default]|[app=app-1]|All connections|
|||::/0|[default]|[app=app-1]|All connections|
||[default]|[*]||0.0.0.0/0|All connections|
||[default]|[*]||::/0|All connections|

