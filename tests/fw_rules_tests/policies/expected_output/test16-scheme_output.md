|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|connectivity_map, config: np16||||||
|||ip block: 0.0.0.0/5|[kube-system-new]|[tier in (frontend)]|UDP 53,|
|||ip block: 11.0.0.0/8|[kube-system-new]|[tier in (frontend)]|UDP 53,|
|||ip block: 172.22.0.0/15|[kube-system-new]|[tier in (frontend)]|UDP 53,|
|||ip block: 172.31.0.0/16|[kube-system-new]|[tier in (frontend)]|UDP 53,|
|||ip block: 0.0.0.0/0|[default,ibm-system-new,kube-system-new-dummy-to-ignore]|[*]|All connections|
|||ip block: 0.0.0.0/0|[kube-system-new]|[!has(tier) or tier in (not_frontend_for_demo)]|All connections|
||[default,ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]||ip block: 0.0.0.0/0|All connections|
||[default,ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|[default,ibm-system-new,kube-system-new-dummy-to-ignore]|[*]|All connections|
||[default,ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|[kube-system-new]|[!has(tier) or tier in (not_frontend_for_demo)]|All connections|


