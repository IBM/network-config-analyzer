|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|semantic_diff, config1: np1, config2: np2, key: Added connections between persistent peers and ipBlocks||||||
|||ip block: 0.0.0.0/5|[kube-system]|[tier in (frontend)]|TCP 53|
|||ip block: 11.0.0.0/8|[kube-system]|[tier in (frontend)]|TCP 53|
|||ip block: 172.22.0.0/15|[kube-system]|[tier in (frontend)]|TCP 53|
|||ip block: 172.31.0.0/16|[kube-system]|[tier in (frontend)]|TCP 53|
|semantic_diff, config1: np1, config2: np2, key: Removed connections between persistent peers and ipBlocks||||||
|||ip block: 0.0.0.0/5|[kube-system]|[tier in (frontend)]|UDP 53|
|||ip block: 11.0.0.0/8|[kube-system]|[tier in (frontend)]|UDP 53|
|||ip block: 172.22.0.0/15|[kube-system]|[tier in (frontend)]|UDP 53|
|||ip block: 172.31.0.0/16|[kube-system]|[tier in (frontend)]|UDP 53|