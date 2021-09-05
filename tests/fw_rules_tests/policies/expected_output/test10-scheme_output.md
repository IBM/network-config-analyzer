|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|connectivity_map, config: np10||||||
|||ip block: 0.0.0.0/0|[default]|[{(tier in (agent))} and {has(app)}]|All connections|
|||ip block: 0.0.0.0/0|[ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|All connections|
||[default,ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|[default]|[{(tier in (agent))} and {has(app)}]|All connections|
||[default]|[{(tier in (agent))} and {has(app)}]||ip block: 0.0.0.0/0|All connections|
||[default]|[{(tier in (agent))} and {has(app)}]|[ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|All connections|
||[ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]||ip block: 0.0.0.0/0|All connections|
||[ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|[ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|All connections|


