|query|src_ns|src_pods|dst_ns|dst_pods|connection|
|---|---|---|---|---|---|
|connectivity_map, config: np2||||||
|||ip block: 0.0.0.0/0|[kube-system-new]|[*]|TCP 53,UDP 53,|
||[default,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|[kube-system-new]|[*]|TCP 53,UDP 53,|
|||ip block: 0.0.0.0/0|[default,ibm-system-new,kube-system-new-dummy-to-ignore]|[*]|All connections|
||[default,ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]||ip block: 0.0.0.0/0|All connections|
||[default,ibm-system-new,kube-system-new,kube-system-new-dummy-to-ignore]|[*]|[default,ibm-system-new,kube-system-new-dummy-to-ignore]|[*]|All connections|
||[ibm-system-new]|[*]|[kube-system-new]|[*]|All connections|


