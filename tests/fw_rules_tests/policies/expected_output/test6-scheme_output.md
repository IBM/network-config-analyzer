|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|connectivity_map, config: np6|
|||ip block: 0.0.0.0/0|[default,ibm-system-new,kube-system-new-dummy-to-ignore]|[*]|All connections|
||[default,ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]||ip block: 0.0.0.0/0|All connections|
||[default,ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|[default,ibm-system-new,kube-system-new-dummy-to-ignore]|[*]|All connections|
||[kube-system-new]|[app in (helm,ibm-kube-fluentd,ibm-storage-watcher,vpn)]|[kube-system-new]|[*]|All connections|


