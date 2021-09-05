|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|connectivity_map, config: np15||||||
|||ip block: 0.0.0.0/0|[ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|All connections|
||[default,ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]||ip block: 0.0.0.0/0|All connections|
||[default,ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|[ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|All connections|
||[ibm-system-new]|[(ibm-cloud-provider-lb-app in (keepalived))]|[default]|[*]|All connections|


