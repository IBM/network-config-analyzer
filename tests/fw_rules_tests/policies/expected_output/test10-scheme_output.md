|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|connectivity_map, config: np10||||||
|||ip block: 0.0.0.0/0|[default]|[has(app) and tier in (agent)]|All connections|
|||ip block: 0.0.0.0/0|[ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|All connections|
||[default,ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|[default]|[has(app) and tier in (agent)]|All connections|
||[default]|[has(app) and tier in (agent)]||ip block: 0.0.0.0/0|All connections|
||[default]|[has(app) and tier in (agent)]|[ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|All connections|
||[ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]||ip block: 0.0.0.0/0|All connections|
||[ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|[ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|All connections|


